# Shared secret files

This directory is reserved for local file-based secrets and is mounted into the service containers at `/app/ops/secrets`.

That means a single relative path such as `./ops/secrets/admin_password` works in:

- local `go run` / `go test` workflows started from the repo root
- `scripts/duckdns-update.sh`
- Docker Compose services running with `/app` as the container workdir

Recommended usage:

```env
SAFE_ZONE_ADMIN_PASSWORD_FILE=./ops/secrets/admin_password
SAFE_ZONE_ADMIN_API_KEY_FILE=./ops/secrets/admin_api_key
SAFE_ZONE_GEMINI_API_KEY_FILE=./ops/secrets/gemini_api_key
SAFE_ZONE_DUCKDNS_TOKEN_FILE=./ops/secrets/duckdns_token
```

Do not commit real secret material. The repository ignores everything in this directory except this README.
