package httptransport

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestIDAndAccessLog(
	t *testing.T,
) {
	var logBuffer bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&logBuffer,
			nil,
		),
	)

	handler := RequestID(
		AccessLog(
			logger,
			http.HandlerFunc(
				func(
					writer http.ResponseWriter,
					_ *http.Request,
				) {
					writer.WriteHeader(
						http.StatusTeapot,
					)

					_, _ = writer.Write(
						[]byte("teapot"),
					)
				},
			),
		),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/test",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		request,
	)

	requestID := recorder.Header().Get(
		"X-Request-ID",
	)

	if requestID == "" {
		t.Fatal("X-Request-ID header is empty")
	}

	logOutput := logBuffer.String()

	for _, expected := range []string{
		requestID,
		`"path":"/test"`,
		`"status":418`,
	} {
		if !strings.Contains(
			logOutput,
			expected,
		) {
			t.Errorf(
				"log does not contain %q:\n%s",
				expected,
				logOutput,
			)
		}
	}
}

func TestRecoverMiddleware(
	t *testing.T,
) {
	var logBuffer bytes.Buffer

	logger := slog.New(
		slog.NewJSONHandler(
			&logBuffer,
			nil,
		),
	)

	handler := RequestID(
		AccessLog(
			logger,
			Recover(
				logger,
				http.HandlerFunc(
					func(
						http.ResponseWriter,
						*http.Request,
					) {
						panic("test panic")
					},
				),
			),
		),
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/panic",
		nil,
	)

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(
		recorder,
		request,
	)

	if recorder.Code !=
		http.StatusInternalServerError {
		t.Errorf(
			"status = %d, want %d",
			recorder.Code,
			http.StatusInternalServerError,
		)
	}

	requestID := recorder.Header().Get(
		"X-Request-ID",
	)

	if requestID == "" {
		t.Fatal("X-Request-ID header is empty")
	}

	logOutput := logBuffer.String()

	if !strings.Contains(
		logOutput,
		"HTTP handler panic recovered",
	) {
		t.Errorf(
			"panic log was not written:\n%s",
			logOutput,
		)
	}
}
