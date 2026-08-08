#!/bin/sh
set -eu

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
bundle_root="${SAFE_ZONE_ML_BUNDLE_ROOT:-${project_dir}/deploy/model-bundle}"
source_dir="${SAFE_ZONE_ML_BUNDLE_SOURCE:-${project_dir}/ml/models/v1}"
version="${SAFE_ZONE_ML_BUNDLE_VERSION:-v1}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  ml-bundle.sh validate [path]
  ml-bundle.sh provision [source] [version]
  ml-bundle.sh rollback <version>
  ml-bundle.sh status

Environment:
  SAFE_ZONE_ML_BUNDLE_ROOT     Versioned release root (default: deploy/model-bundle)
  SAFE_ZONE_ML_BUNDLE_SOURCE   Source bundle directory (default: ml/models/v1)
  SAFE_ZONE_ML_BUNDLE_VERSION  Release directory name (default: v1)
EOF
}

hash_file() {
  canonical_tmp="$(mktemp)"
  # The Go loader hashes canonical UTF-8 text with CRLF normalized to LF.
  # Bundle files are text artifacts, so removing CR preserves that contract
  # for artifacts copied from a Windows host as well.
  tr -d '\015' < "$1" > "$canonical_tmp"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$canonical_tmp" | awk '{print tolower($1)}'
    rm -f "$canonical_tmp"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$canonical_tmp" | awk '{print tolower($1)}'
    rm -f "$canonical_tmp"
    return
  fi
  rm -f "$canonical_tmp"
  die "sha256sum or shasum is required to validate an ML bundle"
}

validate_bundle() {
  bundle_dir="$1"
  [ -d "$bundle_dir" ] || die "ML bundle directory does not exist: $bundle_dir"

  sums_file="${bundle_dir}/SHA256SUMS"
  [ -f "$sums_file" ] || die "ML bundle is missing SHA256SUMS: $bundle_dir"
  [ ! -L "$sums_file" ] || die "ML bundle checksum file must not be a symlink: $sums_file"

  for name in \
    domain_threat_lgbm.txt \
    feature_manifest.v1.json \
    calibration.json \
    policy.json \
    model_report.json
  do
    path="${bundle_dir}/${name}"
    [ -f "$path" ] || die "ML bundle is missing ${name}: ${bundle_dir}"
    [ ! -L "$path" ] || die "ML bundle file must not be a symlink: $path"
    count="$(awk -v name="$name" '$2 == name { count++ } END { print count + 0 }' "$sums_file")"
    [ "$count" = "1" ] || die "SHA256SUMS must contain exactly one entry for ${name}"
    expected="$(awk -v name="$name" '$2 == name { print tolower($1) }' "$sums_file")"
    printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' || die "invalid checksum for ${name}"
    actual="$(hash_file "$path")"
    [ "$actual" = "$expected" ] || die "SHA256 mismatch for ${name}: expected ${expected}, got ${actual}"
  done

  if awk 'NF && NF != 2 { bad = 1 } END { exit bad }' "$sums_file"; then
    :
  else
    die "malformed SHA256SUMS: ${sums_file}"
  fi

  printf 'ML bundle valid: %s\n' "$bundle_dir"
}

normalise_path() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$project_dir" "$1" ;;
  esac
}

safe_version() {
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' || die "invalid ML bundle version: $1"
}

activate_version() {
  requested_version="$1"
  safe_version "$requested_version"
  release_dir="${bundle_root}/${requested_version}"
  validate_bundle "$release_dir"
  mkdir -p "$bundle_root"

  current_link="${bundle_root}/.current.$$"
  rm -f "$current_link"
  ln -s "$requested_version" "$current_link"

  current="${bundle_root}/current"
  if [ -e "$current" ] && [ ! -L "$current" ]; then
    if [ -d "$current" ] && [ -z "$(find "$current" -mindepth 1 -print -quit 2>/dev/null)" ]; then
      rmdir "$current"
    else
      rm -f "$current_link"
      die "current exists and is not an empty symlink: ${current}"
    fi
  fi
  mv -f "$current_link" "$current"
  printf 'ML bundle activated: %s -> %s\n' "$current" "$requested_version"
}

provision() {
  source_path="$(normalise_path "${1:-$source_dir}")"
  requested_version="${2:-$version}"
  safe_version "$requested_version"
  [ -d "$source_path" ] || die "ML bundle source directory does not exist: $source_path"

  validate_bundle "$source_path"
  mkdir -p "$bundle_root"
  release_dir="${bundle_root}/${requested_version}"

  if [ -e "$release_dir" ] || [ -L "$release_dir" ]; then
    validate_bundle "$release_dir"
    cmp -s "${source_path}/SHA256SUMS" "${release_dir}/SHA256SUMS" || die "immutable release already exists with different checksums: ${release_dir}"
  else
    staging_dir="$(mktemp -d "${bundle_root}/.provision.XXXXXX")"
    trap 'rm -rf "$staging_dir"' EXIT HUP INT TERM
    cp -R "${source_path}/." "$staging_dir/"
    validate_bundle "$staging_dir"
    mv "$staging_dir" "$release_dir"
    trap - EXIT HUP INT TERM
    find "$release_dir" -type d -exec chmod 0555 {} \;
    find "$release_dir" -type f -exec chmod 0444 {} \;
    printf 'ML bundle provisioned: %s\n' "$release_dir"
  fi

  activate_version "$requested_version"
}

rollback() {
  requested_version="${1:-}"
  [ -n "$requested_version" ] || die "rollback requires a version, for example: ml-bundle.sh rollback v1"
  activate_version "$requested_version"
}

command_name="${1:-status}"
case "$command_name" in
  validate)
    validate_bundle "$(normalise_path "${2:-${bundle_root}/current}")"
    ;;
  provision)
    provision "${2:-$source_dir}" "${3:-$version}"
    ;;
  rollback)
    rollback "${2:-}"
    ;;
  status)
    current="${bundle_root}/current"
    if [ -e "$current" ] || [ -L "$current" ]; then
      validate_bundle "$current"
      if command -v readlink >/dev/null 2>&1; then
        printf 'ML bundle current target: %s\n' "$(readlink "$current" 2>/dev/null || true)"
      fi
    else
      printf 'ML bundle is not provisioned: %s\n' "$current"
    fi
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
