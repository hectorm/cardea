package health

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hectorm/cardea/internal/metrics"
)

type Server struct {
	listen     string
	httpServer *http.Server
	listener   net.Listener
	readyCheck ReadyCheckFunc
	metrics    *metrics.Metrics
}

type ReadyCheckFunc func() bool

func NewServer(listen string, readyCheck ReadyCheckFunc, metrics *metrics.Metrics) *Server {
	return &Server{
		listen:     listen,
		readyCheck: readyCheck,
		metrics:    metrics,
	}
}

func (s *Server) Start() error {
	if s.listen == "" {
		slog.Info("health server disabled")
		return nil
	}

	slog.Info("starting health server")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	s.httpServer = &http.Server{
		Addr:              s.listen,
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	listener, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("health server listen: %w", err)
	}
	s.listener = listener

	slog.Info("health server listening", "address", s.Address())

	go func() {
		if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("health server error", "error", err)
		}
	}()

	return nil
}

func (s *Server) Stop() error {
	slog.Info("stopping health server")

	if s.httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Address() *net.TCPAddr {
	if s.listener != nil {
		if addr, ok := s.listener.Addr().(*net.TCPAddr); ok {
			return addr
		}
	}
	return &net.TCPAddr{}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.readyCheck != nil && !s.readyCheck() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	if err := s.metrics.WritePrometheus(&buf); err != nil {
		slog.Error("failed to write metrics", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	contentType := "text/plain; charset=utf-8"
	if strings.Contains(r.Header.Get("Accept"), "application/openmetrics-text") {
		contentType = "application/openmetrics-text; version=1.0.0; charset=utf-8"
	}

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}
