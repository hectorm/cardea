package mock

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	sshServerConfig   *ssh.ServerConfig
	signer            ssh.Signer
	publicKeyCallback func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)
	listener          net.Listener
	connMap           sync.Map
	ctx               context.Context
	cancel            context.CancelFunc
	done              chan struct{}
	wg                sync.WaitGroup
}

type Option func(*Server) error

func NewServer(opts ...Option) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	for _, opt := range opts {
		if err := opt(srv); err != nil {
			cancel()
			return nil, err
		}
	}

	if srv.publicKeyCallback == nil {
		srv.publicKeyCallback = AlwaysAllowPublicKey
	}

	if srv.signer == nil {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewSignerFromKey(privateKey)
		if err != nil {
			return nil, err
		}
		srv.signer = signer
	}

	srv.sshServerConfig = &ssh.ServerConfig{
		PublicKeyCallback: srv.publicKeyCallback,
		MaxAuthTries:      6,
	}
	srv.sshServerConfig.AddHostKey(srv.signer)

	return srv, nil
}

func WithPublicKeyCallback(callback func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)) Option {
	return func(srv *Server) error {
		srv.publicKeyCallback = callback
		return nil
	}
}

func WithSigner(signer ssh.Signer) Option {
	return func(srv *Server) error {
		srv.signer = signer
		return nil
	}
}

func (srv *Server) Start() error {
	slog.Info("starting server")

	var err error
	if srv.listener, err = net.Listen("tcp", "[::1]:0"); err != nil {
		if srv.listener, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			return err
		}
	}

	slog.Info("listening", "address", srv.Address())

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

	sshConn, channels, requests, err := ssh.NewServerConn(tcpConn, srv.sshServerConfig)
	if err != nil {
		if _, ok := err.(*ssh.ServerAuthError); !ok {
			return err
		}
		return nil
	}
	defer func() { _ = sshConn.Close() }()

	go srv.handleGlobalRequests(requests, sshConn)

	for newChannel := range channels {
		switch newChannel.ChannelType() {
		case "session":
			go func() {
				if err := srv.handleSession(newChannel); err != nil {
					slog.Error("session error", "error", err)
				}
			}()
		case "direct-tcpip":
			go func() {
				if err := srv.handleDirectTCPIP(newChannel); err != nil {
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

func (srv *Server) handleSession(newChannel ssh.NewChannel) error {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = channel.Close() }()

	environ := NewEnviron()

	for req := range requests {
		ok := false
		switch req.Type {
		case "pty-req":
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
			environ.Set("TERM", payload.Term)
			environ.Set("COLUMNS", strconv.FormatUint(uint64(payload.Columns), 10))
			environ.Set("LINES", strconv.FormatUint(uint64(payload.Rows), 10))
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
			environ.Set("COLUMNS", strconv.FormatUint(uint64(payload.Columns), 10))
			environ.Set("LINES", strconv.FormatUint(uint64(payload.Rows), 10))
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
			environ.Set(payload.Name, payload.Value)
			ok = true
		case "exec":
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				slog.Error("failed to parse exec payload", "error", err)
				break
			}
			go func() {
				time.Sleep(5 * time.Millisecond)
				_ = srv.handleSessionExec(channel, payload.Command, environ)
			}()
			ok = true
		case "shell":
			go func() {
				time.Sleep(5 * time.Millisecond)
				_ = srv.handleSessionShell(channel, environ)
			}()
			ok = true
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
				go func() {
					time.Sleep(5 * time.Millisecond)
					_ = srv.handleSFTPSubsystem(channel)
				}()
				ok = true
			default:
				slog.Warn("unsupported subsystem", "subsystem", payload.Subsystem)
			}
		case "simple@putty.projects.tartarus.org", "winadj@putty.projects.tartarus.org":
			continue
		default:
			slog.Warn("unsupported request type", "type", req.Type)
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}

	return nil
}

func (srv *Server) handleSessionExec(channel ssh.Channel, command string, environ *Environ) error {
	defer func() { _ = channel.Close() }()

	exitStatus, _ := ExecCommand(command, environ, channel)
	_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{uint32(exitStatus)}))

	return err
}

func (srv *Server) handleSessionShell(channel ssh.Channel, environ *Environ) error {
	shell := &InteractiveShell{channel: channel, environ: environ}
	shell.Run()

	return nil
}

func (srv *Server) handleSFTPSubsystem(channel ssh.Channel) error {
	return channel.Close()
}

func (srv *Server) handleDirectTCPIP(newChannel ssh.NewChannel) error {
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

	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = channel.Close() }()

	go ssh.DiscardRequests(requests)

	// Copy everything received back to the sender
	buffer := make([]byte, 4096)
	for {
		n, readErr := channel.Read(buffer)
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
		if n > 0 {
			_, writeErr := channel.Write(buffer[:n])
			if writeErr != nil {
				return writeErr
			}
		}
	}
}

func (srv *Server) handleGlobalRequests(requests <-chan *ssh.Request, sshConn *ssh.ServerConn) {
	for req := range requests {
		switch req.Type {
		case "tcpip-forward":
			var payload struct {
				BindAddr string
				BindPort uint32
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}

			listener, err := net.Listen("tcp", net.JoinHostPort(payload.BindAddr, fmt.Sprintf("%d", payload.BindPort)))
			if err != nil {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}

			boundPort := uint32(listener.Addr().(*net.TCPAddr).Port) // #nosec G115
			if req.WantReply {
				_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{boundPort}))
			}

			go func() {
				defer func() { _ = listener.Close() }()
				for {
					select {
					case <-srv.ctx.Done():
						return
					default:
					}

					conn, err := listener.Accept()
					if err != nil {
						select {
						case <-srv.ctx.Done():
							return
						default:
							continue
						}
					}

					go srv.handleForwardedTCPIP(sshConn, conn, payload.BindAddr, boundPort)
				}
			}()

		case "cancel-tcpip-forward":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (srv *Server) handleForwardedTCPIP(sshConn *ssh.ServerConn, conn net.Conn, bindAddr string, bindPort uint32) {
	defer func() { _ = conn.Close() }()

	channelData := ssh.Marshal(struct {
		ConnectedAddr  string
		ConnectedPort  uint32
		OriginatorAddr string
		OriginatorPort uint32
	}{
		ConnectedAddr:  bindAddr,
		ConnectedPort:  bindPort,
		OriginatorAddr: conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		OriginatorPort: uint32(conn.RemoteAddr().(*net.TCPAddr).Port), // #nosec G115
	})

	channel, requests, err := sshConn.OpenChannel("forwarded-tcpip", channelData)
	if err != nil {
		return
	}
	defer func() { _ = channel.Close() }()

	go ssh.DiscardRequests(requests)

	// Copy everything received back to the sender
	buffer := make([]byte, 4096)
	for {
		n, readErr := channel.Read(buffer)
		if readErr != nil {
			if readErr == io.EOF {
				return
			}
			return
		}
		if n > 0 {
			_, writeErr := channel.Write(buffer[:n])
			if writeErr != nil {
				return
			}
		}
	}
}

func AlwaysAllowPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return &ssh.Permissions{}, nil
}

func AlwaysDenyPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return nil, fmt.Errorf("authentication denied")
}

func ExecCommand(command string, environ *Environ, wri io.Writer) (uint8, bool) {
	if argv := strings.Fields(command); len(argv) > 0 {
		switch argv[0] {
		case "echo":
			_, _ = wri.Write([]byte(strings.Join(argv[1:], " ") + "\r\n"))
		case "printenv":
			if len(argv) > 1 {
				for _, arg := range argv[1:] {
					if val, exists := environ.Get(arg); exists {
						_, _ = fmt.Fprintf(wri, "%s\r\n", val)
					}
				}
			} else {
				for key, val := range environ.GetAll() {
					_, _ = fmt.Fprintf(wri, "%s=%s\r\n", key, val)
				}
			}
		case "nologin":
			_, _ = fmt.Fprintf(wri, "This account is currently not available.\r\n")
			return 0, true
		case "exit":
			exitStatus := uint8(0)
			if len(argv) > 1 {
				exitStatus = 1
				if n, err := strconv.Atoi(argv[1]); err == nil {
					if n >= 0 && n <= 255 {
						exitStatus = uint8(n)
					}
				}
			}
			return exitStatus, true
		case "rsync":
			_, _ = fmt.Fprintf(wri, "mock: %s: NOOP\r\n", argv[0])
			return 0, true
		default:
			_, _ = fmt.Fprintf(wri, "mock: %s: command not found\r\n", argv[0])
			return 1, false
		}
	}
	return 0, false
}

type InteractiveShell struct {
	channel ssh.Channel
	environ *Environ
	line    []rune
	escape  []byte
	cursor  int
}

func (shell *InteractiveShell) Run() {
	shell.prompt()

	exitStatus := uint8(0)
	buf := make([]byte, 1)
	for {
		n, err := shell.channel.Read(buf)
		if err != nil {
			break
		}
		if n == 0 {
			continue
		}
		var exit bool
		if exitStatus, exit = shell.handleInput(buf[0]); exit {
			break
		}
	}

	_, _ = shell.channel.Write([]byte("logout\r\n"))
	shell.Exit(exitStatus)
}

func (shell *InteractiveShell) Exit(exitStatus uint8) {
	_, _ = shell.channel.SendRequest("exit-status", false, ssh.Marshal(struct{ ExitStatus uint32 }{uint32(exitStatus)}))
	_ = shell.channel.Close()
}

func (shell *InteractiveShell) prompt() {
	_, _ = fmt.Fprintf(shell.channel, "mock$ ")
	shell.line = shell.line[:0]
	shell.cursor = 0
}

func (shell *InteractiveShell) handleInput(char byte) (uint8, bool) {
	if len(shell.escape) > 0 {
		shell.escape = append(shell.escape, char)
		if len(shell.escape) == 3 && shell.escape[1] == '[' {
			switch shell.escape[2] {
			case 'C': // Right Arrow
				if shell.cursor < len(shell.line) {
					shell.cursor++
					_, _ = shell.channel.Write([]byte("\033[C"))
				}
			case 'D': // Left Arrow
				if shell.cursor > 0 {
					shell.cursor--
					_, _ = shell.channel.Write([]byte("\033[D"))
				}
			}
			shell.escape = nil
		} else if len(shell.escape) > 3 {
			shell.escape = nil
		}
		return 0, false
	}

	switch char {
	case 0x03: // Ctrl+C
		_, _ = shell.channel.Write([]byte("^C\r\n"))
		shell.prompt()
	case 0x04: // Ctrl+D
		_, _ = shell.channel.Write([]byte("\r\n"))
		return 0, true
	case 0x7F: // Delete
		if shell.cursor > 0 {
			shell.line = append(shell.line[:shell.cursor-1], shell.line[shell.cursor:]...)
			shell.cursor--
			if shell.cursor == len(shell.line) {
				_, _ = shell.channel.Write([]byte("\b \b"))
			} else {
				rem := string(shell.line[shell.cursor:])
				_, _ = shell.channel.Write([]byte("\b" + rem + " "))
				for i := 0; i < len(rem)+1; i++ {
					_, _ = shell.channel.Write([]byte("\b"))
				}
			}
		}
	case 0x0D: // Carriage Return
		_, _ = shell.channel.Write([]byte("\r\n"))
		if exitStatus, exit := ExecCommand(string(shell.line), shell.environ, shell.channel); exit {
			return exitStatus, true
		}
		shell.prompt()
	case 0x1B: // Escape
		shell.escape = []byte{char}
	default:
		if char > 31 && char < 127 {
			shell.line = append(shell.line[:shell.cursor], append([]rune{rune(char)}, shell.line[shell.cursor:]...)...)
			shell.cursor++
			if shell.cursor == len(shell.line) {
				_, _ = shell.channel.Write([]byte{char})
			} else {
				rem := string(shell.line[shell.cursor:])
				_, _ = shell.channel.Write([]byte{char})
				_, _ = shell.channel.Write([]byte(rem))
				for i := 0; i < len(rem); i++ {
					_, _ = shell.channel.Write([]byte("\b"))
				}
			}
		}
	}

	return 0, false
}

type Environ struct {
	vars map[string]string
	mu   sync.RWMutex
}

func NewEnviron() *Environ {
	return &Environ{vars: make(map[string]string)}
}

func (e *Environ) Set(key, value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.vars[key] = value
}

func (e *Environ) Get(key string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	val, exists := e.vars[key]
	return val, exists
}

func (e *Environ) GetAll() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]string, len(e.vars))
	maps.Copy(result, e.vars)
	return result
}
