package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Kandler3/tutor-space/internal/api"
	"github.com/Kandler3/tutor-space/internal/store"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	database, err := store.Open(connectCtx, databaseURL)
	cancel()
	if err != nil {
		return errors.New("cannot connect to database; check DATABASE_URL and database availability")
	}
	defer database.Close()
	app, err := api.New(database, logger)
	if err != nil {
		return errors.New("cannot initialize authentication")
	}
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: addr, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 * 1024}
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	logger.Info("server starting", "address", addr)
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTP server failed; check HTTP_ADDR and port availability")
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return errors.New("HTTP server graceful shutdown failed")
		}
		if err := <-result; !errors.Is(err, http.ErrServerClosed) && err != nil {
			return errors.New("HTTP server failed during shutdown")
		}
		return nil
	}
}
