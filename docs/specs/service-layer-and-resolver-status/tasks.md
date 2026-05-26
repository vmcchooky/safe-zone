# Tasks: Shared Risk Service and Resolver Status

- [x] Write requirements for shared risk behavior and resolver root status.
- [x] Write design for `internal/risk` service boundaries.
- [x] Add `internal/risk` with shared analysis, policy, cache, recent-history, and status methods.
- [x] Update `core-api` to use `internal/risk` instead of local cache/analyze methods.
- [x] Update `dns-resolver` to use `internal/risk` instead of local cache/analyze methods.
- [x] Add `GET /` JSON status to `dns-resolver`.
- [x] Update README with resolver root/status endpoint.
- [x] Run `gofmt`, `go test ./...`, and `go build ./...`.
- [x] Smoke test local endpoints and DoH block response.
