# Design: Local AI Risk Refinement

## Overview

The AI module is a refinement step inside `internal/risk`. It is not a new public API. The service first uses cached results and local threat feeds, then lexical analysis, and only then asks Gemini 2.5 Flash Lite to refine ambiguous cases.

## Control Flow

1. Normalize the domain.
2. Check cached analysis.
3. Check the local threat feed.
4. Run lexical analysis.
5. If the result is ambiguous and Gemini is configured, call the local AI module.
6. If the AI response is valid and more severe, upgrade the result.
7. Cache the final result and return it.

## AI Contract

The local AI endpoint must return JSON with:

- `verdict`: `SAFE`, `SUSPICIOUS`, or `MALICIOUS`
- `confidence`: number from 0 to 1
- `reason`: short explanation

## Failure Model

- If the AI endpoint is missing, the module is disabled.
- If the AI call times out, the service keeps the lexical result.
- If the AI response cannot be parsed, the service keeps the lexical result.
- If the AI result is less severe than the current result, the service keeps the current result.

## Scope Boundaries

- No AI providers other than Gemini.
- No streaming responses.
- No user-facing AI endpoint.
- No change to the current dashboard or resolver APIs beyond the refined analysis result.