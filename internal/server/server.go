package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/hectorm/cardea/internal/config"
	"github.com/hectorm/cardea/internal/credential"
	"github.com/hectorm/cardea/internal/metrics"
	"github.com/hectorm/cardea/internal/ratelimit"
	"github.com/hectorm/cardea/internal/recorder"
	"github.com/hectorm/cardea/internal/tpm"
	"github.com/hectorm/cardea/internal/utils/ansi"
	"github.com/hectorm/cardea/internal/utils/bytesize"
	"github.com/hectorm/cardea/internal/utils/disk"
)

const (
	sshPublicKeyExt = "public-key"
	sshKeyOptsExt   = "key-options"
	sshConnTimeout  = 10 * time.Second
)

type Server struct {
	config               *config.Config
	sshServerConfig      *ssh.ServerConfig
	sshClientConfig      *ssh.ClientConfig
	credentialProvider   credential.Provider
	signer               ssh.Signer
	authKeysDB           map[string][]*AuthorizedKeyOptions
	authKeysMu           sync.RWMutex
	hostKeysCB           ssh.HostKeyCallback
	hostKeysMu           sync.RWMutex
	banner               string
	bannerMu             sync.RWMutex
	listener             net.Listener
	connMap              sync.Map
	connNum              atomic.Int64
	rateLimit            *ratelimit.RateLimit
	recordingsMaxPercent float64
	recordingsMaxBytes   int64
	metrics              *metrics.Metrics
	ctx                  context.Context
	cancel               context.CancelFunc
	done                 chan struct{}
	wg                   sync.WaitGroup
}

var bufferPool = sync.Pool{
	New: func() any {
		return make([]byte, 32*1024)
	},
}

type Option func(*Server) error

func NewServer(cfg *config.Config, opts ...Option) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	cfgCopy := *cfg
	srv := &Server{
		config:  &cfgCopy,
		metrics: metrics.NewMetrics(),
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}

	for _, opt := range opts {
		if err := opt(srv); err != nil {
			return nil, err
		}
	}

	if srv.credentialProvider == nil {
		switch srv.config.KeyStrategy {
		case "file":
			passphrase, err := config.ResolveSecret(srv.config.PrivateKeyPassphrase, srv.config.PrivateKeyPassphraseFile, "passphrase")
			if err != nil {
				return nil, err
			}
			provider, err := credential.NewFileKeyProvider(srv.config.PrivateKeyFile, passphrase)
			if err != nil {
				return nil, fmt.Errorf("file key: %w", err)
			}
			srv.credentialProvider = provider
		case "tpm":
			parentHandle, err := tpm.ParseParentHandle(srv.config.TPMParentHandle)
			if err != nil {
				return nil, err
			}

			parentAuth, err := config.ResolveSecret(srv.config.TPMParentAuth, srv.config.TPMParentAuthFile, "parent auth")
			if err != nil {
				return nil, err
			}

			keyAuth, err := config.ResolveSecret(srv.config.TPMKeyAuth, srv.config.TPMKeyAuthFile, "key auth")
			if err != nil {
				return nil, err
			}

			provider, err := credential.NewTPMKeyProvider(
				srv.config.TPMDevice,
				srv.config.TPMKeyFile,
				&tpm.KeyOptions{
					ParentHandle: parentHandle,
					ParentAuth:   []byte(parentAuth),
					KeyAuth:      []byte(keyAuth),
				},
			)
			if err != nil {
				return nil, fmt.Errorf("tpm key: %w", err)
			}
			srv.credentialProvider = provider
		default:
			return nil, fmt.Errorf("invalid key-strategy %q", srv.config.KeyStrategy)
		}
		srv.signer = srv.credentialProvider.Signer()
	}

	if srv.authKeysDB == nil {
		authKeysDB, err := srv.newAuthorizedKeysDB(srv.config.AuthorizedKeysFile)
		if err != nil {
			return nil, err
		}
		srv.authKeysDB = authKeysDB
	}

	if srv.hostKeysCB == nil {
		hostKeysCB, err := srv.newHostKeysCB(srv.config.KnownHostsFile)
		if err != nil {
			return nil, err
		}
		srv.hostKeysCB = hostKeysCB
	}

	if srv.config.BannerFile != "" {
		banner, err := srv.loadBanner(srv.config.BannerFile)
		if err != nil {
			return nil, err
		}
		srv.banner = banner
	}

	if srv.rateLimit == nil && srv.config.RateLimitMax > 0 {
		srv.rateLimit = ratelimit.NewRateLimit(10000, srv.config.RateLimitMax, srv.config.RateLimitTime)
	}

	maxPercent, maxBytes, err := bytesize.Parse(srv.config.RecordingsMaxDiskUsage)
	if err != nil {
		return nil, err
	}
	srv.recordingsMaxPercent = maxPercent
	srv.recordingsMaxBytes = maxBytes

	srv.sshServerConfig = &ssh.ServerConfig{
		ServerVersion:     "SSH-2.0-Cardea",
		PublicKeyCallback: srv.publicKeyCallback,
		BannerCallback:    srv.bannerCallback,
		MaxAuthTries:      6,
	}
	srv.sshServerConfig.AddHostKey(srv.signer)

	srv.sshClientConfig = &ssh.ClientConfig{
		HostKeyCallback: srv.hostKeyCallback,
		Timeout:         sshConnTimeout,
	}

	return srv, nil
}

func WithCredentialProvider(provider credential.Provider) Option {
	return func(srv *Server) error {
		srv.credentialProvider = provider
		srv.signer = provider.Signer()
		return nil
	}
}

func WithAuthorizedKeysDB(authKeysDB map[string][]*AuthorizedKeyOptions) Option {
	return func(srv *Server) error {
		srv.authKeysDB = authKeysDB
		return nil
	}
}

func WithHostKeysCB(hostKeysCB ssh.HostKeyCallback) Option {
	return func(srv *Server) error {
		srv.hostKeysCB = hostKeysCB
		return nil
	}
}

func WithRateLimit(rateLimit *ratelimit.RateLimit) Option {
	return func(srv *Server) error {
		srv.rateLimit = rateLimit
		return nil
	}
}

func (srv *Server) Start() error {
	slog.Info("starting SSH server")

	go srv.fileWatcher()

	if srv.config.RecordingsDir != "" {
		go srv.diskCleanupWorker()
	}

	var err error
	if srv.listener, err = net.Listen("tcp", srv.config.Listen); err != nil {
		return err
	}

	slog.Info("SSH server listening",
		"address", srv.Address(),
		"fingerprint", ssh.FingerprintSHA256(srv.signer.PublicKey()),
		"public_key", srv.marshalAuthorizedKey(srv.signer.PublicKey()),
	)

	go func() {
		for {
			select {
			case <-srv.ctx.Done():
				return
			default:
			}

			conn, err := srv.listener.Accept()
			if err != nil {
				select {
				case <-srv.ctx.Done():
					return
				default:
					slog.Error("failed to accept incoming connection", "error", err)
					continue
				}
			}

			srv.wg.Go(func() {
				if err := srv.handleConnection(conn); err != nil {
					slog.Error("connection error", "remote_addr", conn.RemoteAddr(), "error", err)
				}
			})
		}
	}()

	return nil
}

func (srv *Server) Stop() error {
	slog.Info("stopping SSH server")

	srv.cancel()

	if srv.listener != nil {
		if err := srv.listener.Close(); err != nil {
			return err
		}
	}

	if srv.credentialProvider != nil {
		if err := srv.credentialProvider.Close(); err != nil {
			slog.Warn("failed to close credential provider", "error", err)
		}
	}

	srv.connMap.Range(func(key, value any) bool {
		if conn, ok := key.(net.Conn); ok {
			_ = conn.Close()
			srv.connMap.Delete(conn)
		}
		return true
	})

	done := make(chan struct{}, 1)
	go func() {
		srv.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("all SSH connections closed gracefully")
	case <-time.After(10 * time.Second):
		slog.Warn("shutdown timeout, some connections may have been forcefully closed")
	}

	close(srv.done)
	return nil
}

func (srv *Server) Address() *net.TCPAddr {
	if srv.listener != nil {
		addr := srv.listener.Addr()
		if addr, ok := addr.(*net.TCPAddr); ok {
			return addr
		}
	}
	return &net.TCPAddr{}
}

func (srv *Server) Signer() ssh.Signer {
	return srv.signer
}

func (srv *Server) Config() config.Config {
	return *srv.config
}

func (srv *Server) Metrics() *metrics.Metrics {
	return srv.metrics
}

func (srv *Server) Done() <-chan struct{} {
	return srv.done
}

func (srv *Server) handleConnection(tcpConn net.Conn) error {
	srv.connMap.Store(tcpConn, struct{}{})
	defer func() {
		if _, loaded := srv.connMap.LoadAndDelete(tcpConn); loaded {
			_ = tcpConn.Close()
		}
	}()

	connNum := srv.connNum.Add(1)
	srv.metrics.ConnectionsActive.Add(1)
	srv.metrics.ConnectionsTotal.Add(1)
	defer func() {
		srv.connNum.Add(-1)
		srv.metrics.ConnectionsActive.Add(-1)
	}()
	if connNum > int64(srv.config.ConnectionsMax) && srv.config.ConnectionsMax > 0 {
		return fmt.Errorf("max connections reached")
	}

	ip, _, err := net.SplitHostPort(tcpConn.RemoteAddr().String())
	if err != nil {
		return err
	}

	if srv.rateLimit != nil && !srv.rateLimit.Allow(ip) {
		srv.metrics.RateLimitRejectionsTotal.Add(1)
		return fmt.Errorf("rate limit exceeded for %s", ip)
	}

	frontendConn, channels, requests, err := srv.newFrontendConnection(tcpConn)
	if err != nil {
		if srv.rateLimit != nil {
			srv.rateLimit.Failure(ip)
		}
		if _, ok := err.(*ssh.ServerAuthError); ok {
			return nil
		}
		return err
	} else if srv.rateLimit != nil {
		srv.rateLimit.Reset(ip)
	}
	defer func() { _ = frontendConn.Close() }()

	permitconnect, err := parsePermitConnect(frontendConn.User())
	if err != nil {
		return err
	}

	backendConn, err := srv.newBackendConnection(permitconnect)
	if err != nil {
		return err
	}
	defer func() { _ = backendConn.Close() }()

	// Handle global requests
	go func() {
		for req := range requests {
			switch req.Type {
			case "tcpip-forward", "cancel-tcpip-forward":
				go func() {
					if err := srv.handleTCPIPForward(req, frontendConn, backendConn); err != nil {
						slog.Error("tcpip-forward error", "error", err)
					}
				}()
			case "keepalive@openssh.com":
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			default:
				slog.Debug("unsupported global request type", "type", req.Type)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	// Handle frontend channels
	go func() {
		for newChannel := range channels {
			switch newChannel.ChannelType() {
			case "session":
				go func() {
					if err := srv.handleSession(frontendConn, backendConn, newChannel); err != nil {
						slog.Error("session error", "error", err)
					}
				}()
			case "direct-tcpip":
				go func() {
					if err := srv.handleDirectTCPIP(frontendConn, backendConn, newChannel); err != nil {
						slog.Error("direct-tcpip error", "error", err)
					}
				}()
			default:
				slog.Warn("unsupported channel type", "type", newChannel.ChannelType())
				_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			}
		}
	}()

	// Handle backend channels
	go func() {
		for newChannel := range backendConn.HandleChannelOpen("forwarded-tcpip") {
			go func() {
				if err := srv.handleForwardedTCPIP(frontendConn, newChannel); err != nil {
					slog.Error("forwarded-tcpip error", "error", err)
				}
			}()
		}
	}()

	_ = frontendConn.Wait()

	return nil
}

func (srv *Server) handleSession(frontendConn *ssh.ServerConn, backendConn *ssh.Client, newChannel ssh.NewChannel) error {
	backendSession, err := backendConn.NewSession()
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "internal error")
		return err
	}
	defer func() { _ = backendSession.Close() }()

	frontendChannel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = frontendChannel.Close() }()

	srv.metrics.SessionsTotal.Add(1)
	srv.metrics.SessionsActive.Add(1)
	defer srv.metrics.SessionsActive.Add(-1)

	var asciicastRec *recorder.AsciicastV3Recorder
	var asciicastHeader *recorder.AsciicastV3Header
	if srv.config.RecordingsDir != "" {
		if ok, err := srv.diskCleanup(); ok {
			title := fmt.Sprintf(
				"Connection to %q from %q (%s)",
				backendConn.RemoteAddr(),
				frontendConn.RemoteAddr(),
				frontendConn.Permissions.Extensions[sshPublicKeyExt],
			)
			path := filepath.Join(srv.config.RecordingsDir, fmt.Sprintf("%s-%s.cast.gz",
				time.Now().Format("20060102-150405"),
				hex.EncodeToString(frontendConn.SessionID()[:10]),
			))
			asciicastRec = recorder.NewAsciicastV3Recorder(path)
			asciicastHeader = recorder.NewAsciicastV3Header(title)
			defer func() { _ = asciicastRec.Close() }()
		} else if err != nil {
			return err
		} else {
			slog.Warn("insufficient space for recording")
			return nil
		}
	}

	backendStdin, err := backendSession.StdinPipe()
	if err != nil {
		return err
	}
	backendStdout, err := backendSession.StdoutPipe()
	if err != nil {
		return err
	}
	backendStderr, err := backendSession.StderrPipe()
	if err != nil {
		return err
	}

	go func() {
		defer func() { _ = backendStdin.Close() }()
		buf := bufferPool.Get()
		defer bufferPool.Put(buf)
		_, _ = io.CopyBuffer(backendStdin, frontendChannel, buf.([]byte))
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := bufferPool.Get()
		defer bufferPool.Put(buf)
		var writers io.Writer = frontendChannel
		if asciicastRec != nil {
			writers = io.MultiWriter(writers, asciicastRec)
		}
		_, _ = io.CopyBuffer(writers, backendStdout, buf.([]byte))
	}()
	go func() {
		defer wg.Done()
		buf := bufferPool.Get()
		defer bufferPool.Put(buf)
		var writers io.Writer = frontendChannel.Stderr()
		if asciicastRec != nil {
			writers = io.MultiWriter(writers, asciicastRec)
		}
		_, _ = io.CopyBuffer(writers, backendStderr, buf.([]byte))
	}()

	go func() {
		if started, err := srv.handleRequests(requests, frontendConn, backendSession, asciicastRec, asciicastHeader); err != nil {
			slog.Error("failed to handle request", "error", err)
			_ = backendSession.Close()
		} else if !started {
			_ = backendSession.Close()
		}
	}()

	wg.Wait()

	exitStatus := uint32(0)
	if err = backendSession.Wait(); err != nil && err != io.EOF {
		exitStatus = uint32(255)
		if exitErr, ok := err.(*ssh.ExitError); ok {
			if n := exitErr.ExitStatus(); n >= 0 && n <= 255 {
				exitStatus = uint32(n)
			}
		}
	}

	_, _ = frontendChannel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{exitStatus}))

	if asciicastRec != nil {
		if _, err := asciicastRec.Write([]byte("\x1bc")); err != nil {
			slog.Error("failed to write reset event", "error", err)
		}
		if err := asciicastRec.WriteExit(exitStatus); err != nil {
			slog.Error("failed to write exit event", "error", err)
		}
	}

	return nil
}

func (srv *Server) handleRequests(
	requests <-chan *ssh.Request,
	frontendConn *ssh.ServerConn, backendSession *ssh.Session,
	asciicastRec *recorder.AsciicastV3Recorder, asciicastHeader *recorder.AsciicastV3Header,
) (bool, error) {
	authKeyOptsStr := frontendConn.Permissions.Extensions[sshKeyOptsExt]
	if authKeyOptsStr == "" {
		_ = frontendConn.Close()
		return false, fmt.Errorf("authorized key options not provided")
	}

	var authKeyOpts AuthorizedKeyOptions
	if err := json.Unmarshal([]byte(authKeyOptsStr), &authKeyOpts); err != nil {
		_ = frontendConn.Close()
		return false, err
	}

	started := false
	for req := range requests {
		ok := false
		switch req.Type {
		case "pty-req":
			if authKeyOpts.NoPty {
				break
			}
			var payload struct {
				Term     string
				Columns  uint32
				Rows     uint32
				Width    uint32
				Height   uint32
				Modelist string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				slog.Error("failed to parse pty-req payload", "error", err)
				break
			}
			var err error
			modes := ssh.TerminalModes{}
			modesBuf := []byte(payload.Modelist)
			for len(modesBuf) > 0 {
				opcode := modesBuf[0]
				if opcode == 0 {
					break
				}
				if len(modesBuf) < 5 {
					err = fmt.Errorf("malformed modes string in pty-req")
					break
				}
				val := binary.BigEndian.Uint32(modesBuf[1:5])
				modes[opcode] = val
				modesBuf = modesBuf[5:]
			}
			if err != nil {
				slog.Error("failed to parse pty-req modes", "error", err)
				break
			}
			if asciicastHeader != nil {
				asciicastHeader.Term.Cols = payload.Columns
				asciicastHeader.Term.Rows = payload.Rows
				asciicastHeader.Term.Type = payload.Term
				asciicastHeader.Env["TERM"] = payload.Term
			}
			if err = backendSession.RequestPty(payload.Term, int(payload.Rows), int(payload.Columns), modes); err != nil {
				slog.Error("failed to request pty", "error", err)
				break
			}
			ok = true
		case "window-change":
			var payload struct {
				Columns uint32
				Rows    uint32
				Width   uint32
				Height  uint32
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				slog.Error("failed to parse window-change payload", "error", err)
				break
			}
			if asciicastRec != nil && asciicastHeader != nil {
				asciicastHeader.Term.Cols = payload.Columns
				asciicastHeader.Term.Rows = payload.Rows
				if err := asciicastRec.WriteResize(payload.Columns, payload.Rows); err != nil {
					slog.Error("failed to write resize event", "error", err)
					break
				}
			}
			if err := backendSession.WindowChange(int(payload.Rows), int(payload.Columns)); err != nil {
				slog.Error("failed to send window-change", "error", err)
				break
			}
			ok = true
		case "env":
			var payload struct {
				Name  string
				Value string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				slog.Error("failed to parse env payload", "error", err)
				break
			}
			if asciicastHeader != nil {
				asciicastHeader.Env[payload.Name] = payload.Value
			}
			if err := backendSession.Setenv(payload.Name, payload.Value); err != nil {
				slog.Error("failed to set env", "error", err)
				break
			}
			ok = true
		case "exec":
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				slog.Error("failed to parse exec payload", "error", err)
				break
			}
			command := authKeyOpts.Command
			if command == "" {
				command = payload.Command
			} else if err := backendSession.Setenv("SSH_ORIGINAL_COMMAND", payload.Command); err != nil {
				slog.Warn("failed to set SSH_ORIGINAL_COMMAND", "error", err)
			}
			if asciicastRec != nil {
				asciicastHeader.Command = command
				if err := asciicastRec.WriteHeader(asciicastHeader); err != nil {
					slog.Error("failed to write header", "error", err)
					break
				}
				if srv.isNonInteractiveCommand(command) {
					if err := asciicastRec.WriteExit(0); err != nil {
						slog.Error("failed to write exit event", "error", err)
						break
					}
				}
			}
			if err := backendSession.Start(command); err != nil {
				slog.Error("session run error", "error", err)
				break
			}
			ok, started = true, true
		case "shell":
			command := authKeyOpts.Command
			if asciicastRec != nil && asciicastHeader != nil {
				asciicastHeader.Command = command
				if err := asciicastRec.WriteHeader(asciicastHeader); err != nil {
					slog.Error("failed to write header", "error", err)
					break
				}
				if srv.isNonInteractiveCommand(command) {
					if err := asciicastRec.WriteExit(0); err != nil {
						slog.Error("failed to write exit event", "error", err)
						break
					}
				}
			}
			if command == "" {
				if err := backendSession.Shell(); err != nil {
					slog.Error("session shell error", "error", err)
					break
				}
			} else {
				if err := backendSession.Start(command); err != nil {
					slog.Error("session run error", "error", err)
					break
				}
			}
			ok, started = true, true
		case "subsystem":
			var payload struct {
				Subsystem string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				slog.Error("failed to parse subsystem payload", "error", err)
				break
			}
			switch payload.Subsystem {
			case "sftp":
				if authKeyOpts.Command != "" && authKeyOpts.Command != "internal-sftp" {
					slog.Warn("subsystem request ignored, command option is set", "command", authKeyOpts.Command)
					break
				}
				if asciicastRec != nil && asciicastHeader != nil {
					asciicastHeader.Command = "internal-sftp"
					if err := asciicastRec.WriteHeader(asciicastHeader); err != nil {
						slog.Error("failed to write header", "error", err)
						break
					}
					if err := asciicastRec.WriteExit(0); err != nil {
						slog.Error("failed to write exit event", "error", err)
						break
					}
				}
				if err := backendSession.RequestSubsystem(payload.Subsystem); err != nil {
					slog.Error("failed to request sftp subsystem", "error", err)
					break
				}
				ok, started = true, true
			default:
				slog.Warn("unsupported subsystem", "subsystem", payload.Subsystem)
			}
		case "simple@putty.projects.tartarus.org", "winadj@putty.projects.tartarus.org":
			ok = true
		default:
			slog.Warn("unsupported request type", "type", req.Type)
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}

	return started, nil
}

func (srv *Server) isNonInteractiveCommand(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	cmd := filepath.Base(fields[0])
	return cmd == "rsync" || cmd == "git" || strings.HasPrefix(cmd, "git-")
}

func (srv *Server) handleDirectTCPIP(frontendConn *ssh.ServerConn, backendConn *ssh.Client, newChannel ssh.NewChannel) error {
	authKeyOptsStr := frontendConn.Permissions.Extensions[sshKeyOptsExt]
	if authKeyOptsStr == "" {
		_ = newChannel.Reject(ssh.ConnectionFailed, "internal error")
		return fmt.Errorf("authorized key options not provided")
	}

	var authKeyOpts AuthorizedKeyOptions
	if err := json.Unmarshal([]byte(authKeyOptsStr), &authKeyOpts); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "internal error")
		return err
	}

	if authKeyOpts.NoPortForwarding {
		_ = newChannel.Reject(ssh.Prohibited, "port forwarding disabled")
		return nil
	}

	var payload struct {
		HostToConnect  string
		PortToConnect  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "failed to parse payload")
		return err
	}

	allowed := false
	for _, po := range authKeyOpts.PermitOpens {
		matchHost := srv.matchHostPattern(po.Host, payload.HostToConnect)
		matchPort := srv.matchPortPattern(po.Port, payload.PortToConnect)
		if matchHost && matchPort {
			allowed = true
			break
		}
	}
	if !allowed {
		_ = newChannel.Reject(ssh.Prohibited, "port forwarding not permitted")
		return nil
	}

	backendChannel, requests, err := backendConn.OpenChannel("direct-tcpip", newChannel.ExtraData())
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "internal error")
		return err
	}
	defer func() { _ = backendChannel.Close() }()

	go ssh.DiscardRequests(requests)

	clientChannel, _, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = clientChannel.Close() }()

	srv.metrics.PortForwardsLocalTotal.Add(1)
	srv.metrics.PortForwardsLocalActive.Add(1)
	defer srv.metrics.PortForwardsLocalActive.Add(-1)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer func() { _ = backendChannel.Close() }()
		buf := bufferPool.Get()
		defer bufferPool.Put(buf)
		_, _ = io.CopyBuffer(backendChannel, clientChannel, buf.([]byte))
	}()
	go func() {
		defer wg.Done()
		defer func() { _ = clientChannel.Close() }()
		buf := bufferPool.Get()
		defer bufferPool.Put(buf)
		_, _ = io.CopyBuffer(clientChannel, backendChannel, buf.([]byte))
	}()

	wg.Wait()
	return nil
}

func (srv *Server) handleTCPIPForward(
	req *ssh.Request,
	frontendConn *ssh.ServerConn,
	backendConn *ssh.Client,
) error {
	authKeyOptsStr := frontendConn.Permissions.Extensions[sshKeyOptsExt]
	if authKeyOptsStr == "" {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return fmt.Errorf("authorized key options not provided")
	}

	var authKeyOpts AuthorizedKeyOptions
	if err := json.Unmarshal([]byte(authKeyOptsStr), &authKeyOpts); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return err
	}

	if authKeyOpts.NoPortForwarding {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return nil
	}

	var payload struct {
		BindAddr string
		BindPort uint32
	}
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return err
	}

	allowed := false
	for _, pl := range authKeyOpts.PermitListens {
		matchHost := srv.matchHostPattern(pl.Host, payload.BindAddr)
		matchPort := srv.matchPortPattern(pl.Port, payload.BindPort)
		if matchHost && matchPort {
			allowed = true
			break
		}
	}
	if !allowed {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return nil
	}

	ok, response, err := backendConn.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return err
	}

	if req.WantReply {
		_ = req.Reply(ok, response)
	}

	return nil
}

func (srv *Server) handleForwardedTCPIP(frontendConn *ssh.ServerConn, newChannel ssh.NewChannel) error {
	authKeyOptsStr := frontendConn.Permissions.Extensions[sshKeyOptsExt]
	if authKeyOptsStr == "" {
		_ = newChannel.Reject(ssh.ConnectionFailed, "internal error")
		return fmt.Errorf("authorized key options not provided")
	}

	var authKeyOpts AuthorizedKeyOptions
	if err := json.Unmarshal([]byte(authKeyOptsStr), &authKeyOpts); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "internal error")
		return err
	}

	if authKeyOpts.NoPortForwarding {
		_ = newChannel.Reject(ssh.Prohibited, "port forwarding disabled")
		return nil
	}

	var payload struct {
		ConnectedHost  string
		ConnectedPort  uint32
		OriginatorIP   string
		OriginatorPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "failed to parse payload")
		return err
	}

	allowed := false
	for _, pl := range authKeyOpts.PermitListens {
		matchHost := srv.matchHostPattern(pl.Host, payload.ConnectedHost)
		matchPort := srv.matchPortPattern(pl.Port, payload.ConnectedPort)
		if matchHost && matchPort {
			allowed = true
			break
		}
	}
	if !allowed {
		_ = newChannel.Reject(ssh.Prohibited, "port forwarding not permitted")
		return nil
	}

	clientChannel, clientRequests, err := frontendConn.OpenChannel("forwarded-tcpip", newChannel.ExtraData())
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "failed to open channel to client")
		return err
	}
	defer func() { _ = clientChannel.Close() }()

	go ssh.DiscardRequests(clientRequests)

	backendChannel, backendRequests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = backendChannel.Close() }()

	go ssh.DiscardRequests(backendRequests)

	srv.metrics.PortForwardsRemoteTotal.Add(1)
	srv.metrics.PortForwardsRemoteActive.Add(1)
	defer srv.metrics.PortForwardsRemoteActive.Add(-1)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer func() { _ = backendChannel.Close() }()
		buf := bufferPool.Get()
		defer bufferPool.Put(buf)
		_, _ = io.CopyBuffer(backendChannel, clientChannel, buf.([]byte))
	}()
	go func() {
		defer wg.Done()
		defer func() { _ = clientChannel.Close() }()
		buf := bufferPool.Get()
		defer bufferPool.Put(buf)
		_, _ = io.CopyBuffer(clientChannel, backendChannel, buf.([]byte))
	}()

	wg.Wait()
	return nil
}

func (srv *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	srv.authKeysMu.RLock()
	defer srv.authKeysMu.RUnlock()

	user := conn.User()
	remoteAddr := conn.RemoteAddr()
	remoteHost, _, _ := net.SplitHostPort(remoteAddr.String())
	sessionID := hex.EncodeToString(conn.SessionID()[:10])
	publicKey := srv.marshalAuthorizedKey(key)

	authKeyEntries, ok := srv.authKeysDB[string(key.Marshal())]
	if !ok {
		srv.metrics.AuthFailuresUnknownKeyTotal.Add(1)
		slog.Info("access denied, not in authorized keys list",
			"backend", user,
			"remote_addr", remoteAddr,
			"session_id", sessionID,
			"public_key", publicKey,
		)
		return nil, fmt.Errorf("public key not authorized")
	}

	backend, err := parsePermitConnect(user)
	if err != nil {
		srv.metrics.AuthFailuresInvalidBackendTotal.Add(1)
		slog.Info("access denied, invalid backend format",
			"backend", user,
			"remote_addr", remoteAddr,
			"session_id", sessionID,
			"public_key", publicKey,
		)
		return nil, fmt.Errorf("public key not authorized")
	}

	var authKeyOpts *AuthorizedKeyOptions
	var denyReason string

	now := time.Now()
	for _, entry := range authKeyEntries {
		if entry.StartTime != nil && now.Before(*entry.StartTime) {
			denyReason = "not_yet_valid"
			continue
		}

		if entry.ExpiryTime != nil && !now.Before(*entry.ExpiryTime) {
			denyReason = "no_longer_valid"
			continue
		}

		if len(entry.Froms) > 0 {
			fromAllowed := false
			for _, pattern := range entry.Froms {
				negated := strings.HasPrefix(pattern, "!")
				if negated {
					pattern = pattern[1:]
				}
				if srv.matchHostPattern(pattern, remoteHost) {
					if negated {
						fromAllowed = false
						break
					}
					fromAllowed = true
				}
			}
			if !fromAllowed {
				denyReason = "denied_source"
				continue
			}
		}

		backendAllowed := false
		for _, pattern := range entry.PermitConnects {
			matchUser := srv.matchUserPattern(pattern.User, backend.User)
			matchHost := srv.matchHostPattern(pattern.Host, backend.Host)
			matchPort := srv.matchPortPattern(pattern.Port, backend.Port)
			if matchUser && matchHost && matchPort {
				backendAllowed = true
				break
			}
		}
		if !backendAllowed {
			denyReason = "denied_backend"
			continue
		}

		authKeyOpts = entry
		break
	}

	if authKeyOpts == nil {
		switch denyReason {
		case "not_yet_valid":
			srv.metrics.AuthFailuresNotYetValidKeyTotal.Add(1)
		case "no_longer_valid":
			srv.metrics.AuthFailuresNoLongerValidKeyTotal.Add(1)
		case "denied_source":
			srv.metrics.AuthFailuresDeniedSourceTotal.Add(1)
		default:
			srv.metrics.AuthFailuresDeniedBackendTotal.Add(1)
		}

		slog.Info("access denied",
			"reason", denyReason,
			"backend", user,
			"remote_addr", remoteAddr,
			"session_id", sessionID,
			"public_key", publicKey,
		)
		return nil, fmt.Errorf("public key not authorized")
	}

	authKeyOptsStr, err := json.Marshal(authKeyOpts)
	if err != nil {
		slog.Error("failed to encode authorized key", "error", err)
		return nil, fmt.Errorf("internal error")
	}

	srv.metrics.AuthSuccessesTotal.Add(1)
	slog.Info("access allowed",
		"backend", user,
		"remote_addr", remoteAddr,
		"session_id", sessionID,
		"public_key", publicKey,
	)
	return &ssh.Permissions{
		Extensions: map[string]string{
			sshPublicKeyExt: publicKey,
			sshKeyOptsExt:   string(authKeyOptsStr),
		},
	}, nil
}

func (srv *Server) hostKeyCallback(host string, remote net.Addr, key ssh.PublicKey) error {
	srv.hostKeysMu.RLock()
	hkCb := srv.hostKeysCB
	srv.hostKeysMu.RUnlock()

	if cbErr := hkCb(host, remote, key); cbErr != nil {
		var khErr *knownhosts.KeyError
		if !errors.As(cbErr, &khErr) {
			return cbErr
		}

		// Host key mismatch
		if len(khErr.Want) > 0 {
			srv.metrics.BackendErrorsMismatchedHostkeyTotal.Add(1)
			return khErr
		}

		// Host is unknown
		switch srv.config.UnknownHostsPolicy {
		case "tofu":
			f, err := os.OpenFile(srv.config.KnownHostsFile, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()

			if _, err = f.Write([]byte(knownhosts.Line([]string{host}, key) + "\n")); err != nil {
				return err
			}

			slog.Warn("added new host key to known hosts",
				"host", host,
				"remote_addr", remote,
				"fingerprint", ssh.FingerprintSHA256(key),
				"public_key", srv.marshalAuthorizedKey(key),
			)
		case "strict":
			fallthrough
		default:
			srv.metrics.BackendErrorsUnknownHostTotal.Add(1)
			return khErr
		}
	}

	return nil
}

func (srv *Server) hostKeyAlgorithms(host string) ([]string, error) {
	srv.hostKeysMu.RLock()
	hkCb := srv.hostKeysCB
	srv.hostKeysMu.RUnlock()

	remote := &net.TCPAddr{IP: net.IPv4zero, Port: 22}
	key := srv.signer.PublicKey()

	if cbErr := hkCb(host, remote, key); cbErr != nil {
		var khErr *knownhosts.KeyError
		if errors.As(cbErr, &khErr) && len(khErr.Want) > 0 {
			// Collect cert algorithms first, then base algorithms.
			// This matches OpenSSH's order_hostkeyalgs behavior which prefers certificate algorithms.
			certAlgos := make([]string, 0, len(khErr.Want))
			baseAlgos := make([]string, 0, len(khErr.Want))
			seen := make(map[string]struct{}, len(khErr.Want)*2)
			for _, want := range khErr.Want {
				base := want.Key.Type()
				if _, ok := seen[base]; !ok {
					seen[base] = struct{}{}
					baseAlgos = append(baseAlgos, base)
				}
				switch base {
				case ssh.KeyAlgoED25519:
					if _, ok := seen[ssh.CertAlgoED25519v01]; !ok {
						seen[ssh.CertAlgoED25519v01] = struct{}{}
						certAlgos = append(certAlgos, ssh.CertAlgoED25519v01)
					}
				case ssh.KeyAlgoECDSA256:
					if _, ok := seen[ssh.CertAlgoECDSA256v01]; !ok {
						seen[ssh.CertAlgoECDSA256v01] = struct{}{}
						certAlgos = append(certAlgos, ssh.CertAlgoECDSA256v01)
					}
				case ssh.KeyAlgoECDSA384:
					if _, ok := seen[ssh.CertAlgoECDSA384v01]; !ok {
						seen[ssh.CertAlgoECDSA384v01] = struct{}{}
						certAlgos = append(certAlgos, ssh.CertAlgoECDSA384v01)
					}
				case ssh.KeyAlgoECDSA521:
					if _, ok := seen[ssh.CertAlgoECDSA521v01]; !ok {
						seen[ssh.CertAlgoECDSA521v01] = struct{}{}
						certAlgos = append(certAlgos, ssh.CertAlgoECDSA521v01)
					}
				case ssh.KeyAlgoRSA:
					for _, algo := range []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512} {
						if _, ok := seen[algo]; !ok {
							seen[algo] = struct{}{}
							baseAlgos = append(baseAlgos, algo)
						}
					}
					for _, algo := range []string{ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01} {
						if _, ok := seen[algo]; !ok {
							seen[algo] = struct{}{}
							certAlgos = append(certAlgos, algo)
						}
					}
				}
			}
			return append(certAlgos, baseAlgos...), nil
		}
	}

	return nil, fmt.Errorf("no host key algorithms available for %s", host)
}

func (srv *Server) loadBanner(path string) (string, error) {
	path = filepath.Clean(path)

	banner, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read banner file: %w", err)
	}

	return string(ansi.StripEscapes(banner)), nil
}

func (srv *Server) bannerCallback(conn ssh.ConnMetadata) string {
	srv.bannerMu.RLock()
	defer srv.bannerMu.RUnlock()

	return srv.banner
}

func (srv *Server) newFrontendConnection(tcpConn net.Conn) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	// Set a read deadline for the initial handshake to mitigate slowloris attacks
	_ = tcpConn.SetReadDeadline(time.Now().Add(sshConnTimeout))
	defer func() { _ = tcpConn.SetReadDeadline(time.Time{}) }()

	// Set TCP_NODELAY to disable Nagle's algorithm for low-latency connections
	if tcpConn, ok := tcpConn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil {
			slog.Warn("failed to set TCP_NODELAY on client connection", "error", err)
		}
	}

	countedConn := &countingConn{
		Conn:         tcpConn,
		bytesRead:    &srv.metrics.ReceivedBytesTotal,
		bytesWritten: &srv.metrics.SentBytesTotal,
	}

	sshConn, channels, requests, err := ssh.NewServerConn(countedConn, srv.sshServerConfig)
	if err != nil {
		return nil, nil, nil, err
	}

	return sshConn, channels, requests, nil
}

func (srv *Server) newBackendConnection(permitconnect *PermitConnect) (*ssh.Client, error) {
	user, host, port := permitconnect.User, permitconnect.Host, permitconnect.Port
	addr := net.JoinHostPort(host, port)

	authMethod, err := srv.credentialProvider.GetAuthMethod(srv.ctx, user, host, port)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth method: %w", err)
	}

	dialer := &net.Dialer{Timeout: sshConnTimeout}
	tcpConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		switch {
		case os.IsTimeout(err):
			srv.metrics.BackendErrorsTimeoutTotal.Add(1)
		case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused"):
			srv.metrics.BackendErrorsRefusedTotal.Add(1)
		default:
			srv.metrics.BackendErrorsOtherTotal.Add(1)
		}
		return nil, err
	}

	// Set a read deadline for the initial handshake to mitigate slowloris attacks
	_ = tcpConn.SetReadDeadline(time.Now().Add(sshConnTimeout))
	defer func() { _ = tcpConn.SetReadDeadline(time.Time{}) }()

	// Set TCP_NODELAY to disable Nagle's algorithm for low-latency connections
	if tcpConn, ok := tcpConn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil {
			slog.Warn("failed to set TCP_NODELAY on backend connection", "error", err)
		}
	}

	sshClientConfig := *srv.sshClientConfig
	sshClientConfig.User = user
	sshClientConfig.Auth = []ssh.AuthMethod{authMethod}

	// Populate the client's host key algorithms from known_hosts if available
	if algos, err := srv.hostKeyAlgorithms(addr); err == nil {
		sshClientConfig.HostKeyAlgorithms = algos
		slog.Debug("using host key algorithms from known_hosts", "host", addr, "algorithms", algos)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, addr, &sshClientConfig)
	if err != nil {
		_ = tcpConn.Close()
		switch {
		case os.IsTimeout(err):
			srv.metrics.BackendErrorsTimeoutTotal.Add(1)
		case strings.Contains(err.Error(), "unable to authenticate"):
			srv.metrics.BackendErrorsFailedAuthTotal.Add(1)
		case !errors.As(err, new(*knownhosts.KeyError)):
			srv.metrics.BackendErrorsOtherTotal.Add(1)
		}
		return nil, err
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

func (srv *Server) matchUserPattern(pattern, user string) bool {
	if user == "" || len(user) > 255 {
		return false
	}

	return srv.matchShellPattern(pattern, user)
}

func (srv *Server) matchHostPattern(pattern, host string) bool {
	if len(host) > 255 {
		return false
	}

	if srv.matchShellPattern(strings.ToLower(pattern), strings.ToLower(host)) {
		return true
	}

	_, cidr, err := net.ParseCIDR(pattern)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return cidr.Contains(ip)
}

func (srv *Server) matchPortPattern(pattern string, port any) bool {
	targetPort, err := strconv.ParseUint(fmt.Sprintf("%v", port), 10, 16)
	if err != nil || targetPort > math.MaxUint16 {
		return false
	}

	if pattern == "*" {
		return true
	}

	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		if len(parts) == 2 {
			startPort, startErr := strconv.ParseUint(parts[0], 10, 16)
			endPort, endErr := strconv.ParseUint(parts[1], 10, 16)
			if startErr == nil && endErr == nil && startPort <= endPort {
				if targetPort >= startPort && targetPort <= endPort {
					return true
				}
			}
		}
	} else {
		patternPort, err := strconv.ParseUint(pattern, 10, 16)
		if err == nil && targetPort == patternPort {
			return true
		}
	}

	return false
}

func (srv *Server) matchShellPattern(pattern, value string) bool {
	if !strings.Contains(value, "/") && value != "." && value != ".." {
		if match, err := filepath.Match(pattern, value); match && err == nil {
			return true
		}
	}

	return false
}

func (srv *Server) marshalAuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func (srv *Server) fileWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("failed to create file watcher", "error", err)
		return
	}
	defer func() { _ = watcher.Close() }()

	authorizedKeysFile := filepath.Clean(srv.config.AuthorizedKeysFile)
	knownHostsFile := filepath.Clean(srv.config.KnownHostsFile)

	var bannerFile string
	if srv.config.BannerFile != "" {
		bannerFile = filepath.Clean(srv.config.BannerFile)
	}

	dirs := map[string]struct{}{}
	dirs[filepath.Dir(authorizedKeysFile)] = struct{}{}
	dirs[filepath.Dir(knownHostsFile)] = struct{}{}
	if bannerFile != "" {
		dirs[filepath.Dir(bannerFile)] = struct{}{}
	}
	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			slog.Error("failed to watch directory", "dir", dir, "error", err)
		}
	}

	waitFor := 100 * time.Millisecond
	timers := make(map[string]*time.Timer)
	mu := sync.Mutex{}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) {
				continue
			}

			file := filepath.Clean(event.Name)
			if file != authorizedKeysFile && file != knownHostsFile && file != bannerFile {
				continue
			}

			mu.Lock()
			t, ok := timers[file]
			mu.Unlock()

			if !ok {
				file := file
				t = time.AfterFunc(math.MaxInt64, func() {
					switch file {
					case authorizedKeysFile:
						authKeysDB, err := srv.newAuthorizedKeysDB(file)
						if err != nil {
							slog.Error("error reloading authorized keys file", "error", err)
						} else {
							srv.authKeysMu.Lock()
							srv.authKeysDB = authKeysDB
							srv.authKeysMu.Unlock()
							slog.Debug("reloaded authorized keys file", "file", file)
						}
					case knownHostsFile:
						hostKeysCB, err := srv.newHostKeysCB(file)
						if err != nil {
							slog.Error("error reloading known hosts file", "error", err)
						} else {
							srv.hostKeysMu.Lock()
							srv.hostKeysCB = hostKeysCB
							srv.hostKeysMu.Unlock()
							slog.Debug("reloaded known hosts file", "file", file)
						}
					case bannerFile:
						banner, err := srv.loadBanner(file)
						if err != nil {
							slog.Error("error reloading banner file", "error", err)
						} else {
							srv.bannerMu.Lock()
							srv.banner = banner
							srv.bannerMu.Unlock()
							slog.Debug("reloaded banner file", "file", file)
						}
					}
				})
				t.Stop()

				mu.Lock()
				timers[file] = t
				mu.Unlock()
			}

			t.Reset(waitFor)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Error("file watcher error", "error", err)
		case <-srv.ctx.Done():
			return
		}
	}
}

func (srv *Server) diskCleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := srv.diskCleanup(); err != nil {
				slog.Error("disk cleanup failed", "error", err)
			}
		case <-srv.ctx.Done():
			return
		}
	}
}

func (srv *Server) diskCleanup() (bool, error) {
	if srv.config.RecordingsDir == "" {
		return true, nil
	}

	if err := os.MkdirAll(srv.config.RecordingsDir, 0700); err != nil {
		return false, err
	}

	if srv.config.RecordingsRetentionTime > 0 {
		files, err := disk.GetFilesBySuffix(srv.config.RecordingsDir, ".cast.gz")
		if err != nil {
			return false, err
		}

		cutoffTime := time.Now().Add(-srv.config.RecordingsRetentionTime)
		for _, file := range files {
			if file.ModTime.Before(cutoffTime) {
				if err := os.Remove(file.Path); err != nil {
					slog.Error("failed to remove recording", "file", file.Path, "error", err)
					continue
				}
				slog.Debug("removed recording", "file", filepath.Base(file.Path), "age", time.Since(file.ModTime))
			}
		}
	}

	if srv.recordingsMaxPercent > 0 {
		usage, err := disk.GetDiskUsage(srv.config.RecordingsDir)
		if err != nil {
			return false, err
		}

		if usage <= srv.recordingsMaxPercent {
			return true, nil
		}

		files, err := disk.GetFilesBySuffix(srv.config.RecordingsDir, ".cast.gz")
		if err != nil {
			return false, err
		}

		slog.Warn("disk usage above threshold, cleaning up oldest recordings",
			"usage", fmt.Sprintf("%.1f%%", usage),
			"threshold", fmt.Sprintf("%.1f%%", srv.recordingsMaxPercent))

		for _, file := range files {
			if err := os.Remove(file.Path); err != nil {
				slog.Error("failed to remove recording", "file", file.Path, "error", err)
				continue
			}
			slog.Debug("removed recording", "file", filepath.Base(file.Path))

			usage, err = disk.GetDiskUsage(srv.config.RecordingsDir)
			if err != nil {
				return false, err
			}

			if usage <= srv.recordingsMaxPercent {
				slog.Info("disk usage back below threshold",
					"usage", fmt.Sprintf("%.1f%%", usage),
					"threshold", fmt.Sprintf("%.1f%%", srv.recordingsMaxPercent))
				return true, nil
			}
		}

		return false, nil
	}

	if srv.recordingsMaxBytes > 0 {
		total, err := disk.GetTotalSizeBySuffix(srv.config.RecordingsDir, ".cast.gz")
		if err != nil {
			return false, err
		}

		if total <= srv.recordingsMaxBytes {
			return true, nil
		}

		files, err := disk.GetFilesBySuffix(srv.config.RecordingsDir, ".cast.gz")
		if err != nil {
			return false, err
		}

		slog.Warn("recordings size above threshold, cleaning up oldest recordings",
			"size", bytesize.Format(total),
			"threshold", bytesize.Format(srv.recordingsMaxBytes))

		for _, file := range files {
			if err := os.Remove(file.Path); err != nil {
				slog.Error("failed to remove recording", "file", file.Path, "error", err)
				continue
			}
			slog.Debug("removed recording", "file", filepath.Base(file.Path))

			if total -= file.Size; total <= srv.recordingsMaxBytes {
				slog.Info("recordings size back below threshold",
					"size", bytesize.Format(total),
					"threshold", bytesize.Format(srv.recordingsMaxBytes))
				return true, nil
			}
		}

		return false, nil
	}

	return true, nil
}
