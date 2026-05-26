# Tasks: Local Threat Feed

- [x] Write threat feed requirements.
- [x] Write threat feed design.
- [x] Add Redis Set helper methods.
- [x] Add `cmd/feed-sync` with local file/URL loading, TXT/CSV parsing, dry-run, and Redis write mode.
- [x] Add threat feed env/config defaults.
- [x] Integrate exact and suffix feed checks into `internal/risk`.
- [x] Ensure feed match produces `MALICIOUS`, score `100`, confidence `1`, reason `matched local threat feed`.
- [x] Keep dashboard reason rendering compatible with feed reason.
- [x] Add tests for exact match, suffix match, invalid domain, and Redis-disabled fail-open.
- [x] Update README with feed sync usage.
- [x] Run `gofmt`, `go test ./...`, `go build ./...`, and smoke checks.
