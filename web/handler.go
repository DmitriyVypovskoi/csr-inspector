package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var staticFiles embed.FS

func Handler() http.Handler {
	staticFS, err := fs.Sub(
		staticFiles,
		"static",
	)
	if err != nil {
		panic(
			"create web filesystem: " +
				err.Error(),
		)
	}

	return http.FileServer(
		http.FS(staticFS),
	)
}
