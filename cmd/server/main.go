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
	"github.com/DmitriyVypovskoi/csr-inspector/web"
)

func main() {
	logger := slog.New(
		slog.NewJSONHandler(
			os.Stdout,
			nil,
		),
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

	apiHandler := httptransport.NewHandler(
		cfg.HTTP.MaxRequestSize,
		logger,
	)

	apiRoutes := apiHandler.Routes()

	router := http.NewServeMux()

	/*
		Передаём API-запросы существующему роутеру.

		Более конкретные пути имеют приоритет
		над корневым маршрутом "/".
	*/
	router.Handle(
		"/api/",
		apiRoutes,
	)

	router.Handle(
		"/health",
		apiRoutes,
	)

	/*
		Web UI и его статические файлы:

			/
			/styles.css
			/app.js

		Здесь нельзя использовать "GET /" вместе
		с method-agnostic шаблоном "/api/", потому что
		новый ServeMux считает такие шаблоны конфликтующими.
	*/
	router.Handle(
		"/",
		web.Handler(),
	)

	handler := httptransport.RequestID(
		httptransport.AccessLog(
			logger,
			httptransport.Recover(
				logger,
				httptransport.SecurityHeaders(
					router,
				),
			),
		),
	)

	server := &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           handler,
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
			slog.String(
				"address",
				cfg.HTTP.Address,
			),
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
