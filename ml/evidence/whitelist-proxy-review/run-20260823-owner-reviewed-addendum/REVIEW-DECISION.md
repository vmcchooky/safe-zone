# Owner-reviewed whitelist-proxy false-positive decision

## Decision

The authorized reviewer marked these three domains `Allow`, with the binary
human label `benign` and review outcome `false_positive`:

- `benhviendalieuthanhhoa.com`
- `benhviennoitietthanhhoa.com`
- `vietmassagebuiquocchau.com`

Reason: each domain is a legitimate website recognized by Tín Nhiệm Mạng, and
the reviewer supplied the exact official directory record for the matching
organization and domain.

- Decision date: 2026-08-23
- Owner: Vo Manh Cuong - Chooky (`reviewer.vmc`)
- Attestation type: typed human decision supplied in the Codex task; not a
  detached cryptographic signature

## Scope

This decision converts only the exact three-domain cohort into human-labelled
false-positive evidence. It does not create runtime allow overrides, modify the
Reports database, alter the signed representative replay archive, approve a
deployment or authorize `SAFE_ZONE_ML_MODE=enforce`.
