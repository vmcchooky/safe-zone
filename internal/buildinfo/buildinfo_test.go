package buildinfo

import "testing"

func TestSnapshotUsesDefaultsForEmptyValues(t *testing.T) {
	previous := snapshotVars()
	defer restoreVars(previous)

	Version = ""
	GitCommit = ""
	BuildTime = ""
	ImageTag = ""
	SourceRepo = ""

	got := Snapshot("", "")
	if got.Service != "unknown" {
		t.Fatalf("expected unknown service, got %q", got.Service)
	}
	if got.Version != "dev" {
		t.Fatalf("expected default version, got %q", got.Version)
	}
	if got.GitCommit != "unknown" {
		t.Fatalf("expected default git commit, got %q", got.GitCommit)
	}
	if got.BuildTime != "unknown" {
		t.Fatalf("expected default build time, got %q", got.BuildTime)
	}
	if got.ImageTag != "unreleased" {
		t.Fatalf("expected default image tag, got %q", got.ImageTag)
	}
	if got.SourceRepo != "unknown" {
		t.Fatalf("expected default source repo, got %q", got.SourceRepo)
	}
	if got.DeploymentTier != "unknown" {
		t.Fatalf("expected default deployment tier, got %q", got.DeploymentTier)
	}
}

func TestSnapshotUsesInjectedValues(t *testing.T) {
	previous := snapshotVars()
	defer restoreVars(previous)

	Version = "1.2.3"
	GitCommit = "abc123"
	BuildTime = "2026-05-26T12:00:00Z"
	ImageTag = "safe-zone:1.2.3-abc123"
	SourceRepo = "https://github.com/quorix/safe-zone"

	got := Snapshot("core-api", "shared-vps")
	if got.Service != "core-api" {
		t.Fatalf("expected service core-api, got %q", got.Service)
	}
	if got.Version != "1.2.3" {
		t.Fatalf("expected injected version, got %q", got.Version)
	}
	if got.GitCommit != "abc123" {
		t.Fatalf("expected injected git commit, got %q", got.GitCommit)
	}
	if got.BuildTime != "2026-05-26T12:00:00Z" {
		t.Fatalf("expected injected build time, got %q", got.BuildTime)
	}
	if got.ImageTag != "safe-zone:1.2.3-abc123" {
		t.Fatalf("expected injected image tag, got %q", got.ImageTag)
	}
	if got.SourceRepo != "https://github.com/quorix/safe-zone" {
		t.Fatalf("expected injected source repo, got %q", got.SourceRepo)
	}
	if got.DeploymentTier != "shared-vps" {
		t.Fatalf("expected deployment tier shared-vps, got %q", got.DeploymentTier)
	}
}

type varsSnapshot struct {
	version    string
	gitCommit  string
	buildTime  string
	imageTag   string
	sourceRepo string
}

func snapshotVars() varsSnapshot {
	return varsSnapshot{
		version:    Version,
		gitCommit:  GitCommit,
		buildTime:  BuildTime,
		imageTag:   ImageTag,
		sourceRepo: SourceRepo,
	}
}

func restoreVars(snapshot varsSnapshot) {
	Version = snapshot.version
	GitCommit = snapshot.gitCommit
	BuildTime = snapshot.buildTime
	ImageTag = snapshot.imageTag
	SourceRepo = snapshot.sourceRepo
}
