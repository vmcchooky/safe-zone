#!/usr/bin/env sh
set -eu

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$project_dir"

edge_mode="production-edge"
release_version="${SAFE_ZONE_RELEASE_VERSION:-unreleased}"
source_repo="${SAFE_ZONE_SOURCE_REPO:-}"
evidence_dir=""

usage() {
  cat <<'USAGE'
Usage: scripts/release-preflight.sh [options]

Options:
  --edge-mode production-edge|shared-host-edge
  --version <release-version>
  --source-repo <repo-url>
  --evidence-dir <path>

The script runs the formal local release gate checks, writes all evidence under
tmp/release-gate by default, and builds Docker images with explicit provenance.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --edge-mode)
      edge_mode="${2:-}"
      shift 2
      ;;
    --version)
      release_version="${2:-}"
      shift 2
      ;;
    --source-repo)
      source_repo="${2:-}"
      shift 2
      ;;
    --evidence-dir)
      evidence_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$edge_mode" in
  production-edge|shared-host-edge) ;;
  *)
    printf 'ERROR: unsupported edge mode: %s\n' "$edge_mode" >&2
    exit 2
    ;;
esac

if [ -z "$source_repo" ]; then
  source_repo="$(git config --get remote.origin.url 2>/dev/null || true)"
fi
if [ -z "$source_repo" ]; then
  source_repo="unknown"
fi

git_commit="$(git rev-parse HEAD)"
short_commit="$(git rev-parse --short HEAD)"
build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
evidence_stamp="$(date -u +%Y%m%d-%H%M%S)"
release_tag="${release_version}-${short_commit}"

if [ -z "$evidence_dir" ]; then
  evidence_dir="${project_dir}/tmp/release-gate/${evidence_stamp}_${edge_mode}"
fi

mkdir -p "$evidence_dir"/binaries "$evidence_dir"/docker

run_capture() {
  label="$1"
  shift
  output_file="${evidence_dir}/${label}.txt"
  printf '==> %s\n' "$label"
  if "$@" >"$output_file" 2>&1; then
    return 0
  fi
  cat "$output_file" >&2
  printf 'ERROR: %s failed\n' "$label" >&2
  exit 1
}

build_binary() {
  service="$1"
  image_ref="safe-zone-${service}:${release_tag}"
  output_file="${evidence_dir}/build-${service}.txt"
  binary_path="${evidence_dir}/binaries/${service}"
  ldflags="-s -w -X safe-zone/internal/buildinfo.Version=${release_version} -X safe-zone/internal/buildinfo.GitCommit=${git_commit} -X safe-zone/internal/buildinfo.BuildTime=${build_time} -X safe-zone/internal/buildinfo.ImageTag=${image_ref} -X safe-zone/internal/buildinfo.SourceRepo=${source_repo}"
  printf '==> build-%s\n' "$service"
  if CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="$ldflags" -o "$binary_path" "./cmd/${service}" >"$output_file" 2>&1; then
    return 0
  fi
  cat "$output_file" >&2
  printf 'ERROR: build-%s failed\n' "$service" >&2
  exit 1
}

build_image() {
  service="$1"
  image_ref="safe-zone-${service}:${release_tag}"
  log_file="${evidence_dir}/docker/${service}.build.txt"
  inspect_file="${evidence_dir}/docker/${service}.inspect.json"
  printf '==> docker-build-%s\n' "$service"
  attempt=1
  while [ "$attempt" -le 3 ]; do
    if docker build \
      --build-arg SERVICE="$service" \
      --build-arg VERSION="$release_version" \
      --build-arg GIT_COMMIT="$git_commit" \
      --build-arg BUILD_TIME="$build_time" \
      --build-arg IMAGE_TAG="$image_ref" \
      --build-arg SOURCE_REPO="$source_repo" \
      -t "$image_ref" . >"$log_file" 2>&1; then
      docker image inspect "$image_ref" >"$inspect_file"
      return 0
    fi
    if [ "$attempt" -lt 3 ]; then
      printf 'WARN: docker-build-%s attempt %s failed, retrying...\n' "$service" "$attempt" >&2
      attempt=$((attempt + 1))
      sleep 2
      continue
    fi
    break
  done
  cat "$log_file" >&2
  printf 'ERROR: docker-build-%s failed\n' "$service" >&2
  exit 1
}

cat >"${evidence_dir}/metadata.env" <<EOF
EDGE_MODE=${edge_mode}
RELEASE_VERSION=${release_version}
RELEASE_TAG=${release_tag}
GIT_COMMIT=${git_commit}
BUILD_TIME=${build_time}
SOURCE_REPO=${source_repo}
EVIDENCE_DIR=${evidence_dir}
EOF

cat >"${evidence_dir}/metadata.json" <<EOF
{
  "edge_mode": "${edge_mode}",
  "release_version": "${release_version}",
  "release_tag": "${release_tag}",
  "git_commit": "${git_commit}",
  "build_time": "${build_time}",
  "source_repo": "${source_repo}",
  "evidence_dir": "${evidence_dir}"
}
EOF

run_capture go-test go test ./...
run_capture go-build go build ./...
run_capture gosec go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
run_capture govulncheck go run golang.org/x/vuln/cmd/govulncheck@latest ./...

build_binary core-api
build_binary dns-resolver

for service in core-api dns-resolver feed-sync feed-syncd; do
  build_image "$service"
done

cat >"${evidence_dir}/summary.txt" <<EOF
Release preflight completed successfully.

Edge mode: ${edge_mode}
Release version: ${release_version}
Release tag: ${release_tag}
Git commit: ${git_commit}
Build time: ${build_time}
Source repo: ${source_repo}

Artifacts:
- ${evidence_dir}/metadata.env
- ${evidence_dir}/metadata.json
- ${evidence_dir}/go-test.txt
- ${evidence_dir}/go-build.txt
- ${evidence_dir}/gosec.txt
- ${evidence_dir}/govulncheck.txt
- ${evidence_dir}/build-core-api.txt
- ${evidence_dir}/build-dns-resolver.txt
- ${evidence_dir}/docker/
EOF

printf 'Release preflight evidence written to %s\n' "$evidence_dir"
