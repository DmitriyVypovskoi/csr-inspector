package httptransport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

type requestIDContextKey struct{}

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			requestID := newRequestID()

			writer.Header().Set(
				"X-Request-ID",
				requestID,
			)

			ctx := context.WithValue(
				request.Context(),
				requestIDContextKey{},
				requestID,
			)

			next.ServeHTTP(
				writer,
				request.WithContext(ctx),
			)
		},
	)
}

func requestIDFromContext(
	ctx context.Context,
) string {
	requestID, ok := ctx.Value(
		requestIDContextKey{},
	).(string)

	if !ok {
		return ""
	}

	return requestID
}

func newRequestID() string {
	var value [16]byte

	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}

	return fmt.Sprintf(
		"fallback-%d",
		time.Now().UnixNano(),
	)
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			writer.Header().Set(
				"Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self'; "+
					"style-src 'self'; "+
					"img-src 'self' data:; "+
					"font-src 'self'; "+
					"connect-src 'self'; "+
					"object-src 'none'; "+
					"base-uri 'none'; "+
					"frame-ancestors 'none'; "+
					"form-action 'self'",
			)

			writer.Header().Set(
				"X-Content-Type-Options",
				"nosniff",
			)

			writer.Header().Set(
				"X-Frame-Options",
				"DENY",
			)

			writer.Header().Set(
				"Referrer-Policy",
				"no-referrer",
			)

			writer.Header().Set(
				"Permissions-Policy",
				"camera=(), "+
					"microphone=(), "+
					"geolocation=(), "+
					"payment=(), "+
					"usb=()",
			)

			writer.Header().Set(
				"Cross-Origin-Opener-Policy",
				"same-origin",
			)

			writer.Header().Set(
				"Cross-Origin-Resource-Policy",
				"same-origin",
			)

			next.ServeHTTP(writer, request)
		},
	)
}

func Recover(
	logger *slog.Logger,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			defer func() {
				recovered := recover()
				if recovered == nil {
					return
				}

				logger.ErrorContext(
					request.Context(),
					"HTTP handler panic recovered",
					slog.String(
						"request_id",
						requestIDFromContext(
							request.Context(),
						),
					),
					slog.String(
						"method",
						request.Method,
					),
					slog.String(
						"path",
						request.URL.Path,
					),
					slog.Any(
						"panic",
						recovered,
					),
					slog.String(
						"stack",
						string(debug.Stack()),
					),
				)

				writer.Header().Set(
					"Cache-Control",
					"no-store",
				)

				http.Error(
					writer,
					"Internal server error",
					http.StatusInternalServerError,
				)
			}()

			next.ServeHTTP(writer, request)
		},
	)
}

func AccessLog(
	logger *slog.Logger,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			startedAt := time.Now()

			recorder := &responseRecorder{
				ResponseWriter: writer,
			}

			next.ServeHTTP(recorder, request)

			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}

			if request.URL.Path == "/health" &&
				status == http.StatusOK {
				return
			}

			duration := time.Since(startedAt)

			logger.InfoContext(
				request.Context(),
				"HTTP request completed",
				slog.String(
					"request_id",
					requestIDFromContext(request.Context()),
				),
				slog.String(
					"method",
					request.Method,
				),
				slog.String(
					"path",
					request.URL.Path,
				),
				slog.Int(
					"status",
					status,
				),
				slog.Int(
					"response_bytes",
					recorder.bytes,
				),
				slog.Float64(
					"duration_ms",
					float64(duration.Microseconds())/1000,
				),
			)
		},
	)
}

type responseRecorder struct {
	http.ResponseWriter

	status int
	bytes  int
}

func (recorder *responseRecorder) WriteHeader(
	status int,
) {
	if recorder.status != 0 {
		return
	}

	recorder.status = status

	recorder.ResponseWriter.WriteHeader(status)
}

func (recorder *responseRecorder) Write(
	data []byte,
) (int, error) {
	if recorder.status == 0 {
		recorder.WriteHeader(http.StatusOK)
	}

	written, err := recorder.ResponseWriter.Write(data)

	recorder.bytes += written

	return written, err
}
