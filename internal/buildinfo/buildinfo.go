package buildinfo

import "strings"

var (
	Version    = "dev"
	GitCommit  = "unknown"
	BuildTime  = "unknown"
	ImageTag   = "unreleased"
	SourceRepo = "unknown"
)

type Metadata struct {
	Service        string `json:"service"`
	Version        string `json:"version"`
	GitCommit      string `json:"git_commit"`
	BuildTime      string `json:"build_time"`
	ImageTag       string `json:"image_tag"`
	SourceRepo     string `json:"source_repo"`
	DeploymentTier string `json:"deployment_tier,omitempty"`
}

func Snapshot(service, deploymentTier string) Metadata {
	return Metadata{
		Service:        fallback(service, "unknown"),
		Version:        fallback(Version, "dev"),
		GitCommit:      fallback(GitCommit, "unknown"),
		BuildTime:      fallback(BuildTime, "unknown"),
		ImageTag:       fallback(ImageTag, "unreleased"),
		SourceRepo:     fallback(SourceRepo, "unknown"),
		DeploymentTier: fallback(deploymentTier, "unknown"),
	}
}

// Link keeps the package in command binaries that do not otherwise surface
// build metadata directly but still receive ldflags during release builds.
func Link() {}

func fallback(value, defaultValue string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}
	return value
}
