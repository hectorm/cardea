package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/hectorm/cardea/internal/config"
	"github.com/hectorm/cardea/internal/ratelimit"
	"github.com/hectorm/cardea/internal/recorder"
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
	signer               ssh.Signer
	authKeysDB           map[string][]*AuthorizedKeyOptions
	authKeysMu           sync.RWMutex
	hostKeysCB           ssh.HostKeyCallback
	hostKeysMu           sync.RWMutex
	listener             net.Listener
	connMap              sync.Map
	connNum              int64
	rateLimit            *ratelimit.RateLimit
	recordingsMaxPercent float64
	recordingsMaxBytes   int64
	ctx                  context.Context
	cancel               context.CancelFunc
	done                 chan struct{}
	wg                   sync.WaitGroup
}

type AuthorizedKeyOptions struct {
	PermitConnects   []PermitConnect `json:"permit_connects"`
	PermitOpens      []PermitOpen    `json:"permit_opens"`
	Command          string          `json:"command"`
	NoPortForwarding bool            `json:"no_port_forwarding"`
	NoPty            bool            `json:"no_pty"`
}

type PermitConnect struct {
	User string `json:"user"`
	Host string `json:"host"`
	Port string `json:"port"`
}

type PermitOpen struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type HostCertAuthority struct {
	Patterns []string
	Key      ssh.PublicKey
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
		config: &cfgCopy,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	for _, opt := range opts {
		if err := opt(srv); err != nil {
			return nil, err
		}
	}

	if srv.signer == nil {
		signer, err := srv.newPrivateKeySigner(srv.config.PrivateKeyFile, srv.config.PrivateKeyPassphrase, srv.config.PrivateKeyPassphraseFile)
		if err != nil {
			return nil, err
		}
		srv.signer = signer
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
		PublicKeyCallback: srv.publicKeyCallback,
		MaxAuthTries:      6,
	}
	srv.sshServerConfig.AddHostKey(srv.signer)

	srv.sshClientConfig = &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(srv.signer)},
		HostKeyCallback: srv.hostKeyCallback,
		Timeout:         sshConnTimeout,
	}

	return srv, nil
}

func WithSigner(signer ssh.Signer) Option {
	return func(srv *Server) error {
		srv.signer = signer
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
	slog.Info("starting server")

	go srv.fileWatcher()

	if srv.config.RecordingsDir != "" {
		go srv.diskCleanupWorker()
	}

	var err error
	if srv.listener, err = net.Listen("tcp", srv.config.Listen); err != nil {
		return err
	}

	slog.Info("listening",
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

			srv.wg.Add(1)
			go func() {
				defer srv.wg.Done()
				if err := srv.handleConnection(conn); err != nil {
					slog.Error("connection error", "remote_addr", conn.RemoteAddr(), "error", err)
				}
			}()
		}
	}()

	return nil
}

func (srv *Server) Stop() error {
	slog.Info("stopping server")

	srv.cancel()

	if srv.listener != nil {
		if err := srv.listener.Close(); err != nil {
			return err
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
		slog.Info("all connections closed gracefully")
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

	connNum := atomic.AddInt64(&srv.connNum, 1)
	defer atomic.AddInt64(&srv.connNum, -1)
	if connNum > int64(srv.config.ConnectionsMax) && srv.config.ConnectionsMax > 0 {
		return fmt.Errorf("max connections reached")
	}

	ip, _, err := net.SplitHostPort(tcpConn.RemoteAddr().String())
	if err != nil {
		return err
	}

	if srv.rateLimit != nil && !srv.rateLimit.Allow(ip) {
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

	permitconnect, err := srv.parsePermitConnect(frontendConn.User())
	if err != nil {
		return err
	}

	backendConn, err := srv.newBackendConnection(permitconnect)
	if err != nil {
		return err
	}
	defer func() { _ = backendConn.Close() }()

	go ssh.DiscardRequests(requests)

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

	sessionId := hex.EncodeToString(conn.SessionID()[:10])
	publicKey := srv.marshalAuthorizedKey(key)

	authKeyEntries, ok := srv.authKeysDB[string(key.Marshal())]
	if !ok {
		slog.Info("access denied, not in authorized keys list",
			"backend", conn.User(),
			"remote_addr", conn.RemoteAddr(),
			"session_id", sessionId,
			"public_key", publicKey,
		)
		return nil, fmt.Errorf("public key not authorized")
	}

	backend, err := srv.parsePermitConnect(conn.User())
	if err != nil {
		slog.Info("access denied, invalid backend format",
			"backend", conn.User(),
			"remote_addr", conn.RemoteAddr(),
			"session_id", sessionId,
			"public_key", publicKey,
		)
		return nil, fmt.Errorf("public key not authorized")
	}

	var authKeyOpts *AuthorizedKeyOptions
	for _, entry := range authKeyEntries {
		allowed := false
		for _, pattern := range entry.PermitConnects {
			matchUser := srv.matchUserPattern(pattern.User, backend.User)
			matchHost := srv.matchHostPattern(pattern.Host, backend.Host)
			matchPort := srv.matchPortPattern(pattern.Port, backend.Port)
			if matchUser && matchHost && matchPort {
				allowed = true
				break
			}
		}
		if allowed {
			authKeyOpts = entry
			break
		}
	}

	if authKeyOpts == nil {
		slog.Info("access denied, not in allowed backend list",
			"backend", conn.User(),
			"remote_addr", conn.RemoteAddr(),
			"session_id", sessionId,
			"public_key", publicKey,
		)
		return nil, fmt.Errorf("public key not authorized")
	}

	authKeyOptsStr, err := json.Marshal(authKeyOpts)
	if err != nil {
		slog.Error("failed to encode authorized key", "error", err)
		return nil, fmt.Errorf("internal error")
	}

	slog.Info("access allowed",
		"backend", conn.User(),
		"remote_addr", conn.RemoteAddr(),
		"session_id", sessionId,
		"public_key", publicKey,
	)
	return &ssh.Permissions{
		Extensions: map[string]string{
			sshPublicKeyExt: publicKey,
			sshKeyOptsExt:   string(authKeyOptsStr),
		},
	}, nil
}

func (srv *Server) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	srv.hostKeysMu.RLock()
	hkCb := srv.hostKeysCB
	srv.hostKeysMu.RUnlock()

	if cbErr := hkCb(hostname, remote, key); cbErr != nil {
		var khErr *knownhosts.KeyError
		if !errors.As(cbErr, &khErr) {
			return cbErr
		}

		// Host key mismatch
		if len(khErr.Want) > 0 {
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

			if _, err = f.Write([]byte(knownhosts.Line([]string{hostname}, key) + "\n")); err != nil {
				return err
			}

			slog.Warn("added new host key to known hosts",
				"hostname", hostname,
				"remote_addr", remote,
				"fingerprint", ssh.FingerprintSHA256(key),
				"public_key", srv.marshalAuthorizedKey(key),
			)
		case "strict":
			fallthrough
		default:
			return khErr
		}
	}

	return nil
}

func (srv *Server) hostKeyAlgorithms(hostname string) ([]string, error) {
	srv.hostKeysMu.RLock()
	hkCb := srv.hostKeysCB
	srv.hostKeysMu.RUnlock()

	remote := &net.TCPAddr{IP: net.IPv4zero, Port: 22}
	key := srv.signer.PublicKey()

	if cbErr := hkCb(hostname, remote, key); cbErr != nil {
		var khErr *knownhosts.KeyError
		if errors.As(cbErr, &khErr) && len(khErr.Want) > 0 {
			algos := make([]string, 0, len(khErr.Want)*2)
			seen := make(map[string]struct{}, len(algos))
			for _, want := range khErr.Want {
				base := want.Key.Type()
				if _, ok := seen[base]; !ok {
					seen[base] = struct{}{}
					algos = append(algos, base)
				}
				switch base {
				case ssh.KeyAlgoED25519:
					if _, ok := seen[ssh.CertAlgoED25519v01]; !ok {
						seen[ssh.CertAlgoED25519v01] = struct{}{}
						algos = append(algos, ssh.CertAlgoED25519v01)
					}
				case ssh.KeyAlgoECDSA256:
					if _, ok := seen[ssh.CertAlgoECDSA256v01]; !ok {
						seen[ssh.CertAlgoECDSA256v01] = struct{}{}
						algos = append(algos, ssh.CertAlgoECDSA256v01)
					}
				case ssh.KeyAlgoECDSA384:
					if _, ok := seen[ssh.CertAlgoECDSA384v01]; !ok {
						seen[ssh.CertAlgoECDSA384v01] = struct{}{}
						algos = append(algos, ssh.CertAlgoECDSA384v01)
					}
				case ssh.KeyAlgoECDSA521:
					if _, ok := seen[ssh.CertAlgoECDSA521v01]; !ok {
						seen[ssh.CertAlgoECDSA521v01] = struct{}{}
						algos = append(algos, ssh.CertAlgoECDSA521v01)
					}
				case ssh.KeyAlgoRSA:
					for _, algo := range []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.CertAlgoRSAv01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSASHA512v01} {
						if _, ok := seen[algo]; !ok {
							seen[algo] = struct{}{}
							algos = append(algos, algo)
						}
					}
				}
			}
			return algos, nil
		}
	}

	return nil, fmt.Errorf("no host key algorithms available for %s", hostname)
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

	sshConn, channels, requests, err := ssh.NewServerConn(tcpConn, srv.sshServerConfig)
	if err != nil {
		return nil, nil, nil, err
	}

	return sshConn, channels, requests, nil
}

func (srv *Server) newBackendConnection(permitconnect *PermitConnect) (*ssh.Client, error) {
	user := permitconnect.User
	addr := net.JoinHostPort(permitconnect.Host, permitconnect.Port)

	dialer := &net.Dialer{Timeout: sshConnTimeout}
	tcpConn, err := dialer.Dial("tcp", addr)
	if err != nil {
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

	// Populate the client's host key algorithms from known_hosts if available
	if algos, err := srv.hostKeyAlgorithms(addr); err == nil {
		sshClientConfig.HostKeyAlgorithms = algos
		slog.Debug("using host key algorithms from known_hosts", "hostname", addr, "algorithms", algos)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, addr, &sshClientConfig)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

func (srv *Server) newPrivateKeySigner(privateKeyPath, passphrase, passphrasePath string) (ssh.Signer, error) {
	privateKeyPath = filepath.Clean(privateKeyPath)

	if passphrase == "" && passphrasePath != "" {
		passphrasePath = filepath.Clean(passphrasePath)
		if data, err := os.ReadFile(passphrasePath); err == nil {
			passphrase = strings.TrimSpace(string(data))
		} else {
			return nil, err
		}
	} else if passphrase != "" && passphrasePath != "" {
		return nil, fmt.Errorf("cannot specify both passphrase and passphrase file")
	}

	var signer ssh.Signer
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		var pemBlock *pem.Block
		if passphrase != "" {
			pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
		} else {
			pemBlock, err = ssh.MarshalPrivateKey(privateKey, "")
		}

		if err != nil {
			return nil, err
		}

		if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, err
		}

		if signer, err = ssh.NewSignerFromKey(privateKey); err != nil {
			return nil, err
		}
	} else if err == nil {
		pemBytes, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, err
		}

		if passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(pemBytes)
		}

		if err != nil {
			if _, ok := err.(*ssh.PassphraseMissingError); ok {
				return nil, err
			}
			return nil, err
		}
	} else {
		return nil, err
	}

	return signer, nil
}

func (srv *Server) newAuthorizedKeysDB(path string) (map[string][]*AuthorizedKeyOptions, error) {
	path = filepath.Clean(path)

	authKeysDB := make(map[string][]*AuthorizedKeyOptions)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, []byte{}, 0600); err != nil {
			return nil, err
		}
	} else if err == nil {
		authKeysBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		lines := strings.Split(string(authKeysBytes), "\n")
		keyLines := make([]string, 0)
		macros := make(map[string]string)

		for _, line := range lines {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "#define "):
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					macros[parts[1]] = strings.Join(parts[2:], " ")
				}
			case line != "" && !strings.HasPrefix(line, "#"):
				keyLines = append(keyLines, line)
			}
		}

		var replacer *strings.Replacer
		if len(macros) > 0 {
			pairs := make([]string, 0, len(macros)*2)
			for k, v := range macros {
				pairs = append(pairs, k, v)
			}
			replacer = strings.NewReplacer(pairs...)
		}

	line:
		for _, line := range keyLines {
			if replacer != nil {
				line = replacer.Replace(line)
			}

			publicKey, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				slog.Warn("skipping invalid authorized keys line", "line", line, "error", err)
				continue line
			}

			authKeyOpts := &AuthorizedKeyOptions{}
			for _, opt := range opts {
				if after, ok := strings.CutPrefix(opt, "permitconnect=\""); ok {
					for val := range strings.SplitSeq(strings.TrimSuffix(after, "\""), ",") {
						permitconnect, err := srv.parsePermitConnect(val)
						if err != nil {
							slog.Warn("skipping invalid authorized keys line", "line", line, "error", err)
							continue line
						}
						authKeyOpts.PermitConnects = append(authKeyOpts.PermitConnects, *permitconnect)
					}
				} else if after, ok := strings.CutPrefix(opt, "permitopen=\""); ok {
					for val := range strings.SplitSeq(strings.TrimSuffix(after, "\""), ",") {
						permitopen, err := srv.parsePermitOpen(val)
						if err != nil {
							slog.Warn("skipping invalid authorized keys line", "line", line, "error", err)
							continue line
						}
						authKeyOpts.PermitOpens = append(authKeyOpts.PermitOpens, *permitopen)
					}
				} else if after, ok := strings.CutPrefix(opt, "command=\""); ok {
					authKeyOpts.Command = strings.TrimSuffix(after, "\"")
				} else if opt == "no-port-forwarding" {
					authKeyOpts.NoPortForwarding = true
				} else if opt == "no-pty" {
					authKeyOpts.NoPty = true
				}
			}

			if len(authKeyOpts.PermitConnects) == 0 {
				slog.Warn("skipping authorized keys line without 'permitconnect' option", "line", line)
				continue line
			}

			if len(authKeyOpts.PermitOpens) == 0 {
				authKeyOpts.PermitOpens = []PermitOpen{
					{Host: "localhost", Port: "1-65535"},
					{Host: "127.0.0.1/8", Port: "1-65535"},
					{Host: "::1/128", Port: "1-65535"},
				}
			}

			k := string(publicKey.Marshal())
			authKeysDB[k] = append(authKeysDB[k], authKeyOpts)
		}
	} else {
		return nil, err
	}

	return authKeysDB, nil
}

func (srv *Server) newHostKeysCB(path string) (ssh.HostKeyCallback, error) {
	path = filepath.Clean(path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, []byte{}, 0600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	hostKeysCB, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}
	return hostKeysCB, nil
}

func (srv *Server) parsePermitConnect(permitconnect string) (*PermitConnect, error) {
	if permitconnect != "" && len(permitconnect) < 1024 {
		// Try format <user>@<host>[:<port>]
		if i := strings.LastIndex(permitconnect, "@"); i != -1 {
			user, addr := permitconnect[:i], permitconnect[i+1:]
			host, port, err := net.SplitHostPort(addr)
			if err == nil && user != "" && host != "" && port != "" {
				return &PermitConnect{User: user, Host: host, Port: port}, nil
			} else if user != "" && addr != "" {
				host := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
				if ip := net.ParseIP(host); ip != nil {
					return &PermitConnect{User: user, Host: ip.String(), Port: "22"}, nil
				} else if host != "" && !strings.Contains(host, ":") {
					return &PermitConnect{User: user, Host: host, Port: "22"}, nil
				}
			}
		}

		// Try format <user>+<host>[+<port>]
		if parts := strings.Split(permitconnect, "+"); len(parts) == 3 {
			user, host, port := parts[0], parts[1], parts[2]
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
			_, _, err := net.SplitHostPort(net.JoinHostPort(host, port))
			if err == nil && user != "" && host != "" && port != "" {
				return &PermitConnect{User: user, Host: host, Port: port}, nil
			}
		} else if len(parts) == 2 {
			user, host := parts[0], parts[1]
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
			if user != "" && host != "" {
				if ip := net.ParseIP(host); ip != nil {
					return &PermitConnect{User: user, Host: ip.String(), Port: "22"}, nil
				} else if host != "" && !strings.Contains(host, ":") {
					return &PermitConnect{User: user, Host: host, Port: "22"}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("invalid permitconnect format, expected <user>@<host>[:<port>] or <user>+<host>[+<port>], got %s", permitconnect)
}

func (srv *Server) parsePermitOpen(permitopen string) (*PermitOpen, error) {
	if permitopen != "" && len(permitopen) < 512 {
		host, port, err := net.SplitHostPort(permitopen)
		if err == nil && host != "" && port != "" {
			return &PermitOpen{Host: host, Port: port}, nil
		}
	}

	return nil, fmt.Errorf("invalid permitopen format, expected <host>:<port>, got %s", permitopen)
}

func (srv *Server) matchUserPattern(pattern, user string) bool {
	if user == "" || len(user) > 255 {
		return false
	}

	return srv.matchShellPattern(pattern, user)
}

func (srv *Server) matchHostPattern(pattern, host string) bool {
	if host == "" || len(host) > 255 {
		return false
	}

	if srv.matchShellPattern(pattern, host) {
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
	if err != nil || targetPort < 1 || targetPort > math.MaxUint16 {
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

	dirs := map[string]struct{}{}
	dirs[filepath.Dir(authorizedKeysFile)] = struct{}{}
	dirs[filepath.Dir(knownHostsFile)] = struct{}{}
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
			if file != authorizedKeysFile && file != knownHostsFile {
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
