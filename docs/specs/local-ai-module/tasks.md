# Tasks: Local AI Risk Refinement

## Milestone 1: AI Client

- [x] Add an internal Gemini client with configurable base URL, API key, model, and timeout.
- [x] Parse the structured JSON response from the local AI endpoint.
- [x] Treat client errors as fail-open.

## Milestone 2: Risk Integration

- [x] Wire the AI client into `internal/risk` as an optional refinement step.
- [x] Only call AI for ambiguous lexical results.
- [x] Keep cached, feed-matched, and lexical-only paths unchanged when AI is disabled.

## Milestone 3: Configuration and Docs

- [x] Add environment variables for Gemini base URL, API key, model, and timeout.
- [x] Document the local AI path in README and OPEX notes if needed.
- [x] Keep the module optional by default.

## Milestone 4: Tests

- [x] Add client tests for valid and invalid AI responses.
- [x] Add risk tests proving ambiguous cases can be refined and failures fail open.
- [x] Verify the full repository still passes `go test ./...` and `go build ./...`.

## Completion Rule

Do not enable the AI module by default unless the local endpoint is explicitly configured.