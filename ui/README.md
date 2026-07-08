# Safe Zone UI Workspace

This directory is reserved for the standalone frontend workspace.

Why it lives here:

- `ui/` is a better fit than `internal/` for Node.js and npm-based code.
- Go `internal/` directories are reserved for private Go packages, not frontend toolchains.

Current status:

- `ui/src/` contains early React dashboard route prototypes.
- The production dashboard currently served by `core-api` still lives under `internal/api/handlers`.
- This workspace is not part of the current `go build ./...` pipeline yet.
