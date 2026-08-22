# ML release evidence

This directory contains intentionally tracked, reviewable evidence bundles for
ML release decisions. It is separate from `tmp/`, which remains disposable.

Each bundle must include the run outputs, the human-label packet, the evidence
files referenced by the labels, provenance notes, and a SHA-256 checksum list.
AI-generated labels or adjudications are not release ground truth and belong in
quarantine, not in a signed evidence bundle.

- [Phase 5 representative replay — run 2026-08-08](representative-replay/run-20260808/)
