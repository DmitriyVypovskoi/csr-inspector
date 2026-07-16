package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/DmitriyVypovskoi/csr-inspector/internal/config"
	httptransport "github.com/DmitriyVypovskoi/csr-inspector/internal/transport/http"
)

func main() {
	logger := slog.New(
		slog.NewJSONHandler(os.Stdout, nil),
	)

	if err := run(logger); err != nil {
		logger.Error(
			"application stopped",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	handler := httptransport.NewHandler()

	server := &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	shutdownSignal, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	serverErrors := make(chan error, 1)

	go func() {
		logger.Info(
			"HTTP server started",
			slog.String("address", cfg.HTTP.Address),
		)

		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err

	case <-shutdownSignal.Done():
		logger.Info("shutdown signal received")
	}

	shutdownContext, cancel := context.WithTimeout(
		context.Background(),
		cfg.HTTP.WriteTimeout,
	)
	defer cancel()

	if err := server.Shutdown(shutdownContext); err != nil {
		return err
	}

	logger.Info("HTTP server stopped")

	return nil
}
