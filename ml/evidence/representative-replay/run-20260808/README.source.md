# Private ML representative replay packet

This directory contains domain-level candidates and must not be committed.

1. Run the staging shadow replay and inspect `results.jsonl`.
2. Have two authorized reviewers fill `labels.csv`; do not use source membership or model output as the label.
3. Produce `review-summary.json` and complete the Product/Security decision in the approval packet.

The 2026-08-14 AI-filled `labels.csv` was quarantined to
`tmp/gemini/quarantine-ai-adjudication-20260814/` and is **not** human ground
truth. Use `tmp/gemini/human-review/README.md` for the current review order.
