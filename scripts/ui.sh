#!/usr/bin/env sh
set -eu

command_name="${1:-dev}"
project_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ui_root="${project_root}/ui"
backend_bundle_root="${project_root}/internal/api/app/dist"
ui_lockfile="${ui_root}/package-lock.json"

if [ ! -d "$ui_root" ]; then
  printf 'ui workspace not found: %s\n' "$ui_root" >&2
  exit 1
fi

install_arg() {
  if [ -f "$ui_lockfile" ]; then
    printf '%s\n' ci
  else
    printf '%s\n' install
  fi
}

invoke_ui_npm() {
  cd "$ui_root"
  npm "$@"
}

ensure_ui_dependencies() {
  if [ ! -d "${ui_root}/node_modules" ]; then
    invoke_ui_npm "$(install_arg)"
  fi
}

sync_ui_bundle() {
  ui_dist_root="${ui_root}/dist"
  if [ ! -d "$ui_dist_root" ]; then
    printf 'ui dist output not found: %s\n' "$ui_dist_root" >&2
    exit 1
  fi

  rm -rf "$backend_bundle_root"
  mkdir -p "$backend_bundle_root"
  cp -R "$ui_dist_root"/. "$backend_bundle_root"/
  : > "${backend_bundle_root}/.keep"
}

case "$command_name" in
  install)
    invoke_ui_npm "$(install_arg)"
    ;;
  dev)
    ensure_ui_dependencies
    invoke_ui_npm run dev
    ;;
  build)
    ensure_ui_dependencies
    invoke_ui_npm run build
    ;;
  bundle)
    ensure_ui_dependencies
    invoke_ui_npm run check
    sync_ui_bundle
    ;;
  preview)
    ensure_ui_dependencies
    invoke_ui_npm run preview
    ;;
  typecheck)
    ensure_ui_dependencies
    invoke_ui_npm run typecheck
    ;;
  check)
    ensure_ui_dependencies
    invoke_ui_npm run check
    ;;
  *)
    printf 'unsupported ui command: %s\n' "$command_name" >&2
    exit 2
    ;;
esac
