# Design: OPEX-First Cost Optimization

## Overview

This design treats the OPEX estimate as the controlling document for scope. The implementation should minimize fixed monthly cost, keep the baseline on one VPS, and avoid paid dependencies unless they are explicitly opt-in.

## Cost Model

Budget categories:

- Compute: the VPS itself.
- Domain and DNS: only low-cost or free options.
- Storage and backup: capped and retention-based.
- Monitoring: free-tier or self-hosted.
- External intelligence: free-tier first, cache-first, paid only by exception.

## Runtime Shape

- `core-api`, `dns-resolver`, and `redis` remain the baseline services.
- `feed-syncd` is optional and disabled by default.
- The default compose and local runtime must not require paid services.
- Any additional service must be justified in the OPEX estimate before becoming default.

## Cost-Control Policies

- Prefer cache reuse over repeated remote lookups.
- Keep backup size and log growth bounded with retention limits.
- Make health checks and metrics dependency-free.
- Avoid adding hosted observability or managed queues for the baseline path.

## Review Policy

Before a feature ships, review:

1. Monthly cost impact.
2. Whether a free-tier or self-hosted alternative exists.
3. Whether the feature can be optional by default.
4. Whether the feature can be represented in the OPEX estimate with a clear budget delta.

## Non-Goals

- Multi-node HA as the default baseline.
- Paid AI or intelligence providers as the default path.
- Any feature whose only value is to widen the deployment footprint.