# Requirements: Local AI Risk Refinement

## Goal

Add an optional local AI module powered by Gemini 2.5 Flash Lite so Safe Zone can refine ambiguous risk decisions without introducing paid APIs or breaking the current fail-open behavior.

## Functional Requirements

- Local AI must be optional and disabled when no Gemini API key is configured.
- Local AI must run against the Gemini API with a configurable base URL and API key.
- Local AI must use a short timeout and fail open if the model is unavailable, slow, or returns invalid data.
- Local AI must only refine ambiguous cases and must not block the current lexical or threat-feed path.
- Local AI must return structured JSON with verdict, confidence, and reason.
- Existing `/v1/analyze`, `/v1/policy`, and `/dns-query` behavior must remain compatible.

## Non-Functional Requirements

- Do not introduce a paid AI API.
- Do not require Redis for local AI to work.
- Keep the implementation simple enough to run locally with `go run`.
- Preserve the current local-first and fail-open design.

## Acceptance Criteria

- A configured Gemini endpoint can refine an ambiguous domain result.
- If Gemini is disabled or unavailable, analysis continues unchanged.
- Invalid AI responses do not break analysis.
- `go test ./...` and `go build ./...` continue to pass.