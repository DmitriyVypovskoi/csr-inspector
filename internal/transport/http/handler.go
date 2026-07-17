package httptransport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/DmitriyVypovskoi/csr-inspector/internal/csr"
)

type Handler struct {
	maxRequestSize int64
	logger         *slog.Logger
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type parseErrorDetails struct {
	Status   int
	Code     string
	Message  string
	LogCause bool
}

func NewHandler(
	maxRequestSize int64,
	logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return &Handler{
		maxRequestSize: maxRequestSize,
		logger:         logger,
	}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("POST /api/v1/csr/parse", h.parseCSR)

	return mux
}

func (h *Handler) health(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	response := struct {
		Status string `json:"status"`
	}{
		Status: "ok",
	}

	_ = writeJSON(
		writer,
		http.StatusOK,
		response,
	)
}

func (h *Handler) parseCSR(
	writer http.ResponseWriter,
	request *http.Request,
) {
	writer.Header().Set(
		"Cache-Control",
		"no-store",
	)

	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		h.maxRequestSize,
	)
	defer request.Body.Close()

	input, err := io.ReadAll(request.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError

		if errors.As(err, &maxBytesError) {
			h.logger.WarnContext(
				request.Context(),
				"CSR request rejected",
				slog.String(
					"request_id",
					requestIDFromContext(
						request.Context(),
					),
				),
				slog.String(
					"error_code",
					"request_too_large",
				),
				slog.Int(
					"status",
					http.StatusRequestEntityTooLarge,
				),
			)

			h.writeError(
				writer,
				http.StatusRequestEntityTooLarge,
				"request_too_large",
				"CSR exceeds the maximum allowed request size.",
			)

			return
		}

		h.logger.ErrorContext(
			request.Context(),
			"Failed to read CSR request body",
			slog.String(
				"request_id",
				requestIDFromContext(
					request.Context(),
				),
			),
			slog.String(
				"error",
				err.Error(),
			),
		)

		h.writeError(
			writer,
			http.StatusBadRequest,
			"read_request_failed",
			"Failed to read the request body.",
		)

		return
	}

	info, err := csr.ParsePEM(input)
	if err != nil {
		h.writeParseError(
			writer,
			request,
			err,
		)

		return
	}

	_ = writeJSON(
		writer,
		http.StatusOK,
		info,
	)
}

func (h *Handler) writeParseError(
	writer http.ResponseWriter,
	request *http.Request,
	err error,
) {
	details := classifyParseError(err)

	attributes := []slog.Attr{
		slog.String(
			"request_id",
			requestIDFromContext(
				request.Context(),
			),
		),
		slog.String(
			"error_code",
			details.Code,
		),
		slog.Int(
			"status",
			details.Status,
		),
	}

	if details.LogCause {
		attributes = append(
			attributes,
			slog.String(
				"cause",
				err.Error(),
			),
		)
	}

	h.logger.LogAttrs(
		request.Context(),
		slog.LevelWarn,
		"CSR parsing rejected",
		attributes...,
	)

	h.writeError(
		writer,
		details.Status,
		details.Code,
		details.Message,
	)
}

func classifyParseError(
	err error,
) parseErrorDetails {
	switch {
	case errors.Is(err, csr.ErrEmptyInput):
		return parseErrorDetails{
			Status:  http.StatusBadRequest,
			Code:    "empty_request",
			Message: "The certificate signing request is empty.",
		}

	case errors.Is(err, csr.ErrInvalidPEM):
		return parseErrorDetails{
			Status: http.StatusBadRequest,
			Code:   "invalid_pem",
			Message: "The input is not a valid PEM-encoded CSR.\n\n" +
				"Check that the BEGIN and END lines are present, " +
				"contain exactly five hyphens on each side, " +
				"and use matching supported labels.\n\n" +
				"Expected format:\n" +
				"-----BEGIN CERTIFICATE REQUEST-----\n" +
				"...\n" +
				"-----END CERTIFICATE REQUEST-----\n\n" +
				"The legacy NEW CERTIFICATE REQUEST label " +
				"is also supported.",
		}

	case errors.Is(err, csr.ErrUnsupportedPEMType):
		return classifyUnsupportedPEMType(err)

	case errors.Is(err, csr.ErrPEMHeaders):
		return parseErrorDetails{
			Status: http.StatusBadRequest,
			Code:   "unsupported_pem_headers",
			Message: "The CSR PEM block must not contain " +
				"additional headers.",
		}

	case errors.Is(err, csr.ErrTrailingData):
		return parseErrorDetails{
			Status: http.StatusBadRequest,
			Code:   "unexpected_trailing_data",
			Message: "Unexpected data was found after " +
				"the CSR PEM block.",
		}

	default:
		return parseErrorDetails{
			Status:   http.StatusUnprocessableEntity,
			Code:     "csr_parse_failed",
			Message:  "The CSR could not be parsed. The PKCS#10 structure may be malformed.",
			LogCause: true,
		}
	}
}

func classifyUnsupportedPEMType(
	err error,
) parseErrorDetails {
	var pemTypeError *csr.UnsupportedPEMTypeError

	if !errors.As(err, &pemTypeError) {
		return parseErrorDetails{
			Status:  http.StatusUnprocessableEntity,
			Code:    "unsupported_pem_type",
			Message: "Unsupported PEM type.",
		}
	}

	switch pemTypeError.Type {
	case "CERTIFICATE", "X509 CERTIFICATE":
		return parseErrorDetails{
			Status: http.StatusUnprocessableEntity,
			Code:   "certificate_instead_of_csr",
			Message: "This appears to be an X.509 certificate, " +
				"not a certificate signing request. " +
				"Certificate inspection may be added " +
				"in a future version.",
		}

	case "PRIVATE KEY",
		"RSA PRIVATE KEY",
		"EC PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY",
		"OPENSSH PRIVATE KEY":

		return parseErrorDetails{
			Status: http.StatusUnprocessableEntity,
			Code:   "private_key_instead_of_csr",
			Message: "This appears to be a private key, " +
				"not a CSR. Do not upload or share private keys.",
		}

	default:
		return parseErrorDetails{
			Status: http.StatusUnprocessableEntity,
			Code:   "unsupported_pem_type",
			Message: fmt.Sprintf(
				"Unsupported PEM type %q. Expected "+
					"CERTIFICATE REQUEST or "+
					"NEW CERTIFICATE REQUEST.",
				pemTypeError.Type,
			),
		}
	}
}

func (h *Handler) writeError(
	writer http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	response := errorResponse{
		Error: apiError{
			Code:    code,
			Message: message,
		},
	}

	_ = writeJSON(
		writer,
		status,
		response,
	)
}

func writeJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) error {
	writer.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	writer.Header().Set(
		"X-Content-Type-Options",
		"nosniff",
	)

	writer.WriteHeader(status)

	return json.NewEncoder(writer).Encode(value)
}
