# Phase 5 representative replay — tracked evidence archive

This is the immutable, version-control-ready archive of the representative
replay packet generated under the disposable `tmp/` workspace. It is the
canonical path to use when reviewing or signing this run:

`ml/evidence/representative-replay/run-20260808/`

Contents:

- `labels.csv`, `review-summary.json`, and `approval-packet.md` — the reviewed
  decision packet;
- `approval-packet.generated.md` — the byte-for-byte packet before the archive
  disclosure was added;
- `manifest.json`, replay JSONL files, and `status-before-after.json` — model,
  input, and staging replay provenance;
- `manifest.generated.json` — the original generator manifest before it was
  rebound to the committed validator/reporter/test code;
- `evidence/` — the public-page/OSINT evidence files referenced by the labels;
- `ARCHIVE.md` and `checksums.sha256` — provenance and integrity instructions;
- `README.source.md` — the original private-run README retained as provenance.

The evidence was collected with AI-assisted tooling, but the labels in this
archive were entered and attested by the human reviewer recorded in
`labels.csv`. The quarantined AI-filled labels are deliberately excluded.

`evidence_refs` in `labels.csv` use paths relative to this run directory (for
example `evidence/cisco.vn.md`), so the references remain valid in a fresh
clone. Do not edit an artifact in place after signing; create a new run archive
and regenerate its checksum list instead.
