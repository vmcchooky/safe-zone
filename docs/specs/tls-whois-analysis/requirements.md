# Requirements: TLS Certificate (x.509) & WHOIS Age Analysis Module

## Goal

Add two new "real-world intelligence" signals to Safe Zone's analysis pipeline: TLS certificate inspection and domain registration age lookup. These provide strong evidence that pure lexical analysis cannot capture, significantly reducing false positives.

## Problem Statement

Current analysis is purely lexical (domain string patterns). This causes:
- **False positives**: Legitimate new domains with long names flagged as suspicious.
- **False negatives**: Phishing domains with innocent-looking names but freshly registered with free TLS certs pass through.
- **Missing signal**: A domain registered 2 days ago with a Let's Encrypt cert and mismatched CN is a much stronger phishing indicator than "domain has 3 hyphens".

## Milestones

### Milestone 1: TLS Certificate Inspector

Perform a TLS handshake to the domain and extract certificate metadata:
- **Certificate validity**: Is the cert valid, expired, or self-signed?
- **Issuer**: Let's Encrypt, Cloudflare, DigiCert, self-signed, etc.
- **Subject/SAN mismatch**: Does the cert's Common Name or SAN list match the queried domain?
- **Certificate age**: When was the cert issued? (days since `NotBefore`).
- **Wildcard cert**: Is it a `*.domain.com` wildcard?

Risk signals:
| Signal | Score | Rationale |
|---|---|---|
| Self-signed certificate | +25 | Uncommon for legitimate sites |
| Certificate < 7 days old | +15 | Freshly provisioned, common for phishing |
| Let's Encrypt + cert < 7 days | +10 | Free cert + new = medium risk |
| CN/SAN mismatch | +30 | Strong phishing indicator |
| Expired certificate | +20 | Abandoned or malicious domain |
| No TLS / connection refused | +5 | Minor signal (some legit sites lack TLS) |

### Milestone 2: WHOIS Domain Age Lookup

Query WHOIS data for domain registration age:
- **Registration date**: When was the domain first registered?
- **Domain age**: Days since registration.
- **Registrar**: Who registered the domain?

Risk signals:
| Signal | Score | Rationale |
|---|---|---|
| Domain < 7 days old | +25 | Very high phishing correlation |
| Domain < 30 days old | +15 | Still suspicious for financial/login domains |
| Domain < 90 days old | +5 | Mild signal |
| WHOIS privacy/redacted | +5 | Minor signal (common but slightly suspect) |
| WHOIS lookup failed | 0 | No penalty (fail-open) |

### Milestone 3: Pipeline Integration

- Both modules are **optional, async, and non-blocking**.
- Both run **only when lexical score is between 20-69** (suspicious zone) to avoid:
  - Wasting time on clearly safe domains (score < 20).
  - Unnecessary checks on already-malicious domains (score >= 70).
- Combined score from TLS + WHOIS adds to lexical score.
- Results are **cached in Redis** (TTL same as analysis cache) to avoid repeated lookups.
- Both modules have **individual timeouts** (default 3s each).

### Milestone 4: Caching & Performance

- TLS handshake results cached by domain (avoids repeated handshakes).
- WHOIS results cached by registered domain (e.g., cache `example.com` for `sub.example.com`).
- Cache TTL: same as analysis cache (3h for safe, 1h for suspicious, 6h for malicious).
- When cache hit, no network call made.

## Technical Constraints

- **No external API dependency for WHOIS** (free WHOIS APIs are unreliable/rate-limited). Use Go's `net` package to query WHOIS servers directly via TCP.
- **TLS handshake must not follow redirects** — only inspect the certificate, don't load the page.
- **Timeout strictly enforced** — both modules must respect their configured timeout.
- **CGO_ENABLED=0 compatible** — no CGo dependencies. Go's `crypto/tls` is pure Go.
- **Fail-open** — if TLS or WHOIS fails, analysis continues with lexical score only.

## Non-Functional Requirements

- TLS + WHOIS checks add < 4 seconds to analysis (with 3s timeout each, parallel execution).
- No impact on DNS resolver performance (DNS uses Policy, which uses cached results).
- Module failures must not crash the service.
- Results cached to avoid repeated network calls.

## Acceptance Criteria

- TLS inspector detects self-signed, expired, mismatched, and fresh certificates.
- WHOIS lookup extracts domain registration date from major registrars.
- Combined scoring correctly escalates suspicious domains.
- Both modules fail-open gracefully.
- Cached results prevent repeated network lookups.
- All existing tests continue to pass.
- New modules have comprehensive unit tests.

## What This Does NOT Include

- Passive DNS lookups.
- Reverse IP lookups.
- SSL/TLS vulnerability scanning (heartbleed, etc.).
- Domain reputation scoring from external databases.
- WHOIS for non-standard TLDs (ccTLDs with non-standard WHOIS protocols).
