package httptransport

import (
	"encoding/json"
	"net/http"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", h.health)

	return mux
}

func (h *Handler) health(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writer.Header().Set("Content-Type", "application/json")

	response := struct {
		Status string `json:"status"`
	}{
		Status: "ok",
	}

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		http.Error(
			writer,
			http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError,
		)
	}
}
