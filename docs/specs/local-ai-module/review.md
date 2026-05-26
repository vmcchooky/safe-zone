# Review: Local AI Risk Refinement

## Review Gate

Before merging a local AI change, confirm:

1. The AI path is optional and off by default.
2. The AI path only refines ambiguous cases.
3. Fail-open behavior is preserved when the model is unavailable.
4. The response is structured and parseable.
5. The change does not add any paid AI dependency.

## Review Questions

- Which ambiguous domains should trigger AI refinement?
- What timeout is short enough for local use but long enough for a cold start?
- Can the feature be turned off with a single env var?
- Does the feature change any public API response shape?
- Do tests prove the system still works when the AI endpoint is broken?

## Drift Prevention

- If the feature requires an AI API other than the approved Gemini path, reject it.
- If the AI module can block analysis, reject it.
- If the AI module cannot be disabled, reject it.

## Suggested Next Artifact

- Add a short README note for the optional Gemini settings once the implementation lands.