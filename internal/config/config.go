package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	defaultHTTPAddress       = ":8080"
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 10 * time.Second
	defaultWriteTimeout      = 10 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultMaxRequestSize    = 128 * 1024 // 128 KiB
)

type Config struct {
	HTTP HTTPConfig
}

type HTTPConfig struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxRequestSize    int64
}

func Load() (Config, error) {
	maxRequestSize, err := getEnvInt64(
		"HTTP_MAX_REQUEST_SIZE",
		defaultMaxRequestSize,
	)
	if err != nil {
		return Config{}, err
	}

	if maxRequestSize <= 0 {
		return Config{}, fmt.Errorf(
			"HTTP_MAX_REQUEST_SIZE must be greater than zero",
		)
	}

	return Config{
		HTTP: HTTPConfig{
			Address:           getEnv("HTTP_ADDRESS", defaultHTTPAddress),
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			ReadTimeout:       defaultReadTimeout,
			WriteTimeout:      defaultWriteTimeout,
			IdleTimeout:       defaultIdleTimeout,
			MaxRequestSize:    maxRequestSize,
		},
	}, nil
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func getEnvInt64(key string, fallback int64) (int64, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	result, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(
			"parse environment variable %s: %w",
			key,
			err,
		)
	}

	return result, nil
}
