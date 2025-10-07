package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hectorm/cardea/internal/config"
	"github.com/hectorm/cardea/internal/server"
)

func main() {
	cfg := config.NewConfig()

	srv, err := server.NewServer(cfg)
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	err = srv.Start()
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	if err := srv.Stop(); err != nil {
		slog.Error("failed to stop server", "error", err)
		os.Exit(1)
	}
}
