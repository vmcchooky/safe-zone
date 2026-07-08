package app

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embeddedFiles embed.FS

// StaticFS exposes the embedded React build mounted by core-api under /app.
var StaticFS = mustSubFS(embeddedFiles, "dist")

func mustSubFS(root fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(root, dir)
	if err != nil {
		panic(err)
	}
	return sub
}
