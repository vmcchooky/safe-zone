package views

import (
	_ "embed"
	"html/template"
	"io"

	apiassets "safe-zone/internal/api/assets"
)

//go:embed block.html
var blockHTML string

var blockTemplate = template.Must(template.New("block").Parse(renderAssets(blockHTML)))

func renderAssets(base string) string {
	return apiassets.ReplaceRevisionPlaceholders(base)
}

func ExecuteBlockPage(w io.Writer, data any) error {
	return blockTemplate.Execute(w, data)
}
