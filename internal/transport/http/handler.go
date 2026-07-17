package httptransport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/DmitriyVypovskoi/csr-inspector/internal/csr"
)

type Handler struct {
	maxRequestSize int64
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHandler(maxRequestSize int64) *Handler {
	return &Handler{
		maxRequestSize: maxRequestSize,
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
	/*
		CSR может содержать внутренние доменные имена,
		IP-адреса и сведения об организации.

		Запрещаем кэширование как успешных ответов,
		так и сообщений об ошибках.
	*/
	writer.Header().Set(
		"Cache-Control",
		"no-store",
	)

	/*
		Ограничиваем размер запроса до чтения тела.

		Если HTTP_MAX_REQUEST_SIZE равен 131072,
		то максимальный размер тела — 128 KiB.
	*/
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
			h.writeError(
				writer,
				http.StatusRequestEntityTooLarge,
				"request_too_large",
				"CSR exceeds the maximum allowed request size.",
			)

			return
		}

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
		h.writeParseError(writer, err)

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
	err error,
) {
	switch {
	case errors.Is(err, csr.ErrEmptyInput):
		h.writeError(
			writer,
			http.StatusBadRequest,
			"empty_request",
			"The certificate signing request is empty.",
		)

	case errors.Is(err, csr.ErrInvalidPEM):
		h.writeError(
			writer,
			http.StatusBadRequest,
			"invalid_pem",
			"The input is not a valid PEM-encoded CSR.\n\n"+
				"Check that the BEGIN and END lines are present, "+
				"contain exactly five hyphens on each side, "+
				"and use matching supported labels.\n\n"+
				"Expected format:\n"+
				"-----BEGIN CERTIFICATE REQUEST-----\n"+
				"...\n"+
				"-----END CERTIFICATE REQUEST-----\n\n"+
				"The legacy NEW CERTIFICATE REQUEST label "+
				"is also supported.",
		)

	case errors.Is(err, csr.ErrUnsupportedPEMType):
		h.writeUnsupportedPEMTypeError(
			writer,
			err,
		)

	case errors.Is(err, csr.ErrPEMHeaders):
		h.writeError(
			writer,
			http.StatusBadRequest,
			"unsupported_pem_headers",
			"The CSR PEM block must not contain additional headers.",
		)

	case errors.Is(err, csr.ErrTrailingData):
		h.writeError(
			writer,
			http.StatusBadRequest,
			"unexpected_trailing_data",
			"Unexpected data was found after the CSR PEM block.",
		)

	default:
		/*
			Не возвращаем пользователю err.Error(), поскольку
			там могут находиться внутренние ошибки ASN.1 parser.
		*/
		h.writeError(
			writer,
			http.StatusUnprocessableEntity,
			"csr_parse_failed",
			"The CSR could not be parsed. "+
				"The PKCS#10 structure may be malformed.",
		)
	}
}

func (h *Handler) writeUnsupportedPEMTypeError(
	writer http.ResponseWriter,
	err error,
) {
	var pemTypeError *csr.UnsupportedPEMTypeError

	if !errors.As(err, &pemTypeError) {
		h.writeError(
			writer,
			http.StatusBadRequest,
			"unsupported_pem_type",
			"Unsupported PEM type. Expected CERTIFICATE REQUEST "+
				"or NEW CERTIFICATE REQUEST.",
		)

		return
	}

	switch pemTypeError.Type {
	case "CERTIFICATE", "X509 CERTIFICATE":
		h.writeError(
			writer,
			http.StatusUnprocessableEntity,
			"certificate_instead_of_csr",
			"This appears to be an X.509 certificate, "+
				"not a certificate signing request. "+
				"Certificate inspection may be added in a future version.",
		)

	case "PRIVATE KEY",
		"RSA PRIVATE KEY",
		"EC PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY",
		"OPENSSH PRIVATE KEY":

		h.writeError(
			writer,
			http.StatusUnprocessableEntity,
			"private_key_instead_of_csr",
			"This appears to be a private key, not a CSR. "+
				"Do not upload or share private keys.",
		)

	default:
		h.writeError(
			writer,
			http.StatusUnprocessableEntity,
			"unsupported_pem_type",
			fmt.Sprintf(
				"Unsupported PEM type %q. Expected "+
					"CERTIFICATE REQUEST or "+
					"NEW CERTIFICATE REQUEST.",
				pemTypeError.Type,
			),
		)
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
