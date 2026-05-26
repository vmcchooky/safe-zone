# ADR 0004: Caddy as the public HTTP edge

Date: 2026-05-21

## Status

Accepted

## Decision

Caddy is the only public HTTP/HTTPS edge for the production stack. It terminates HTTPS and proxies dashboard/API traffic plus DoH to internal services. DoT stays on `dns-resolver` directly over port `853`.

## Rationale

Caddy gives automatic certificate management and a small operational footprint. It matches the single-VPS baseline better than adding another load balancer layer.

## Consequences

- Production keeps `8080` and `8081` on loopback only.
- Public HTTP surface is limited to `80` and `443` through Caddy.
- DoT certificate handling is documented separately because Caddy does not terminate native DoT.
