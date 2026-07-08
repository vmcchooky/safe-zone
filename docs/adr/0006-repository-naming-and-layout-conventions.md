# ADR 0006: Repository naming and layout conventions

## Status

Accepted

## Date

2026-07-08

## Context

The repository had started to drift into mixed naming styles:

- HTTP files inside `internal/api/handlers` repeated the package name with suffixes like `_handlers`.
- Some files used overly generic names such as `api.go`.
- A few files bundled unrelated route families together, making ownership and discovery harder.
- The new `ui/` workspace needs a lightweight convention that does not conflict with Go package layout.

Go's official guidance is strongest at the package level: keep package names short, lower-case, and clear. Go is less prescriptive about file names, so the file and folder rules below are repository conventions derived from that package-first design.

References:

- [Effective Go: Package names](https://go.dev/doc/effective_go)
- [Go blog: Package names](https://go.dev/blog/package-names)
- [Organizing a Go module](https://go.dev/doc/modules/layout)

## Decision

We standardize naming and layout as follows.

### Go package rules

- Use short, lower-case package names with no mixedCaps or underscores.
- Name a package for its domain or responsibility, not for implementation detail.
- Avoid package names that force frequent import aliases unless there is a real collision.

### Go directory rules

- One directory should represent one primary package responsibility.
- Keep browser templates and static assets out of logic-heavy handler packages.
- `cmd/<service>` remains for executable entrypoints only.
- `internal/...` remains for private Go packages only.

### Go file rules

- File names should describe the main route family or concern in that file.
- Do not repeat the package name in the file name unless it adds real meaning.
- Avoid vague bucket names such as `api.go`, `common.go`, or `utils.go` when a more specific name is available.
- Prefer splitting files by route family or cohesive concern once a file starts mixing unrelated handlers.
- Keep test file names aligned with the source concern when practical.

### UI workspace rules

- Keep standalone frontend code under `ui/`, not under Go `internal/` packages.
- Use `PascalCase.tsx` for React component files.
- Keep route-local assets adjacent to the route or component they support.
- Treat `ui/` as an independent workspace and do not let its build artifacts leak into Go package directories.

## Consequences

- The codebase becomes easier to scan because file names map to route families and responsibilities.
- New contributors have a documented baseline before adding more packages or frontend code.
- Future refactors should follow these conventions instead of adding new parallel naming styles.

## Initial application

This ADR is applied immediately in:

- `internal/api/handlers`
- `internal/dns/resolver`
- the new `internal/api/views` and `internal/api/assets` split
- the root `ui/` workspace
