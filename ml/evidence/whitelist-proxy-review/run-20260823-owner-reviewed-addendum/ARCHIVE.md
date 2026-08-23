# Whitelist-proxy owner-reviewed false-positive addendum — 2026-08-23

## Summary

This addendum records three human-reviewed benign domains from the targeted
Vietnam whitelist-proxy ML-candidate cohort. All three have model probability
above the `0.85` block threshold and exact Tín Nhiệm Mạng evidence supplied by
the reviewer. The addendum is separate from the signed representative replay
archive and does not change its labels, packet or checksums.

## Provenance

- Curated replay manifest SHA-256:
  `4d0f56753420e08cb3ee3736403ec211b1b1fee3f377213aa1ce5db57d8be380`
- Revalidated Firecrawl manifest SHA-256:
  `33c116a80e91f1496f01916478a747d6158896e824c5d3581d7588a65a140438`
- Revalidated Firecrawl results SHA-256:
  `992c6681989f81263eaed19267ebd0153cf51b2766e179e89b323c26ae98ca39`
- Evidence validator commit:
  `d5debeaf59a55d3c5d8ce656ca664e56f52a4d55`
- Review packet source commit:
  `17b848360d1e413c2935b82b8911ad41dd6b15be`
- Model revision:
  `4632f9ea69124591db89dfb176aacf46323c18043c7b8c8d0972c3b2f92c3bca`
- Threshold: `0.85`

## Interpretation

The cohort FPR measures a deliberately selected hard-case supplement; it is
not an estimate of general production traffic FPR. A high result confirms a
specific feedback signal: long legitimate Vietnamese organization domains are
being scored above threshold. Model or policy remediation must be evaluated on
this supplement and the representative set together.

No runtime allow override, service restart, environment change, traffic-scope
change, deployment or enforcement action is part of this addendum.

## Replay result

The bounded shadow replay used three rounds, producing 9 requests per service.
Both offline and runtime-candidate FPR were `3/3 = 100%`. Offline probability,
runtime probability and cross-service response parity each had 0 mismatch;
both services reported 0 ML error and 0 enforce promotion.

- Labels SHA-256:
  `0f93be906a4da6352075634cd127ea89148dc7352df8249015c432f5ef8fcfb5`
- Private replay report SHA-256:
  `2ef8b8abe1b3babfdf47103206b63111b4ad47a27f0f2ce43df134b50407abd3`
- Bundle `SHA256SUMS` SHA-256:
  `be6a9034a764e33acfac8a639a84c0bad03e759fc4b962d91f17b6ca071c32d8`

The supplement is deliberately selected from ML hard cases, so its 100% FPR
must not be extrapolated to general traffic. It does establish three confirmed
critical false positives at the proposed threshold. The staging canary gate is
therefore blocked until model or policy remediation passes this supplement and
does not regress the representative replay.
