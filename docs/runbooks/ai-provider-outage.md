# AI provider outage runbook

AI refinement is optional and fail-open. If Ollama or Gemini is unavailable, Safe Zone keeps deterministic analysis results.

## Detect

```sh
docker compose logs core-api --tail=200 | grep -i "refinement"
```

## Mitigate local Ollama

```sh
curl -fsS http://127.0.0.1:11434/api/tags
```

Confirm `SAFE_ZONE_AI_PROVIDER=ollama` or `hybrid`, and that `SAFE_ZONE_OLLAMA_BASE_URL` points to localhost or the Docker-internal host you actually run.

## Mitigate Gemini fallback

Confirm:

- `SAFE_ZONE_GEMINI_API_KEY` is set only when cloud fallback is acceptable.
- `SAFE_ZONE_GEMINI_TIMEOUT_MS` is bounded.

## Follow-up

If privacy/offline operation matters more than refinement quality, set `SAFE_ZONE_AI_PROVIDER=ollama` or `none`.
