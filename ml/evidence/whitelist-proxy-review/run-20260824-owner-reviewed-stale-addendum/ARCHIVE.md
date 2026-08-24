# Owner-reviewed stale-domain addendum — 2026-08-24

## Summary

This addendum records four Vietnam whitelist-proxy ML candidates that the
reviewer could not classify as benign or malicious because each domain was
unallocated at the official `.vn` registry lookup and returned DNS NXDOMAIN.
The records use `human_label=unknown` and `review_outcome=unresolved`.

The addendum is separate from prior signed or owner-reviewed evidence. It does
not alter historical labels, create a runtime allow override, or authorize a
deployment, restart, traffic-scope change, or enforcement action.

## Audit treatment

These four exact domains remain visible in the model report as reviewed
unclassifiable predictions. They are separated from the SAFE VN benign FPR
denominator because inactive, unallocated domains cannot support a current
binary benign label. They are not added to training and do not change the
overall held-out candidate-cohort metrics.

## Provenance

- Review source commit:
  `f7966913b3965866d9b7f5b96ed9e0cabf582572`
- Model revision:
  `97b2ef1f3f6e77e043b3c26502a919f69fd2ca225140a3b13f4dfbafea3aa691`
- Threshold: `0.92`
- Official registry lookup:
  `https://tracuutenmien.gov.vn/tra-cuu-thong-tin-ten-mien`
- Reviewer observation: all four registry lookups returned unallocated and all
  four DNS lookups returned NXDOMAIN.
