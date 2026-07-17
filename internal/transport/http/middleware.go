package httptransport

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			/*
				Наш frontend загружает CSS, JavaScript и выполняет
				fetch только с текущего origin.

				Поэтому можно использовать достаточно строгую CSP.
			*/
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

			next.ServeHTTP(
				writer,
				request,
			)
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

				/*
					Stack trace пишем только в серверный лог.

					Пользователю не раскрываем внутренние пути,
					названия функций и детали panic.
				*/
				logger.Error(
					"HTTP handler panic recovered",
					slog.Any(
						"panic",
						recovered,
					),
					slog.String(
						"method",
						request.Method,
					),
					slog.String(
						"path",
						request.URL.Path,
					),
					slog.String(
						"stack",
						string(debug.Stack()),
					),
				)

				writer.Header().Set(
					"Content-Type",
					"text/plain; charset=utf-8",
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

			next.ServeHTTP(
				writer,
				request,
			)
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

			next.ServeHTTP(
				recorder,
				request,
			)

			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}

			logger.Info(
				"HTTP request completed",
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
				slog.Duration(
					"duration",
					time.Since(startedAt),
				),
				slog.String(
					"remote_address",
					request.RemoteAddr,
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
