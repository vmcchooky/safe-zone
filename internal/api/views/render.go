package views

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"strings"

	apiassets "safe-zone/internal/api/assets"
)

const sessionBootstrapPlaceholder = "__SAFE_ZONE_SESSION_BOOTSTRAP__"

//go:embed dashboard.html
var dashboardHTML string

//go:embed login.html
var loginHTML string

//go:embed block.html
var blockHTML string

var blockTemplate = template.Must(template.New("block").Parse(renderAssets(blockHTML)))

func renderAssets(base string) string {
	return apiassets.ReplaceRevisionPlaceholders(base)
}

func Login() string {
	return renderAssets(loginHTML)
}

func Dashboard(session any) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	page := renderAssets(dashboardHTML)
	page = strings.Replace(page, sessionBootstrapPlaceholder, string(payload), 1)
	return page, nil
}

func ExecuteBlockPage(w io.Writer, data any) error {
	return blockTemplate.Execute(w, data)
}
