package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hectorm/cardea/internal/config"
	"github.com/hectorm/cardea/internal/health"
	"github.com/hectorm/cardea/internal/server"
)

func main() {
	cfg := config.NewConfig()

	srv, err := server.NewServer(cfg)
	if err != nil {
		slog.Error("failed to create SSH server", "error", err)
		os.Exit(1)
	}

	err = srv.Start()
	if err != nil {
		slog.Error("failed to start SSH server", "error", err)
		os.Exit(1)
	}

	healthSrv := health.NewServer(cfg.HealthListen, func() bool {
		addr := srv.Address()
		return addr != nil && addr.Port > 0
	}, srv.Metrics())
	if err := healthSrv.Start(); err != nil {
		slog.Error("failed to start health server", "error", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	exitCode := 0
	if err := healthSrv.Stop(); err != nil {
		slog.Error("failed to stop health server", "error", err)
		exitCode = 1
	}
	if err := srv.Stop(); err != nil {
		slog.Error("failed to stop SSH server", "error", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}
