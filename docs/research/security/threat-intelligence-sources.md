# Threat Intelligence Source Policy

Safe Zone treats every domain in the Redis threat-feed set as malicious.
Built-in presets therefore include only direct domain/URL feeds intended for
phishing or malware blocking.

## Built-In Presets

- `production-free`: URLhaus recent CSV and OpenPhish community feed.
- `production-vn`: `production-free` plus PhishDestroy Primary Active and
  Phishing.Database Active. These are global phishing feeds, not
  Vietnam-specific sources. The preset name means it is the recommended
  broader baseline for Vietnamese deployments while official Vietnamese feeds
  still require dedicated connectors.

The streaming parser accepts TXT, CSV, URL lists, gzip, and hosts-format lines
such as `0.0.0.0 phishing.example`.

## URL-host admission

The parser preserves whether an entry is a whole-domain indicator or a
path-scoped URL. `SAFE_ZONE_AGENT_FEED_ADMISSION_MODE` supports:

- `legacy`: current authoritative host behavior; this remains the runtime default.
- `corroborated-url-host-shadow`: calculate source-level authoritative/contextual
  counts while writing the unchanged legacy host set.
- `corroborated-url-host-filter`: dry-run/evaluation only. Runtime sync rejects
  this mode because the current ablation retained only `4/7` broad malicious
  matches and the additive Redis set cannot safely remove per-source membership.

A path-scoped URL host is corroborated only by a second distinct resource in
the same snapshot. Repeated identical lines do not count. Domain indicators,
root URLs, and IP URLs remain authoritative in the candidate policy.

## Planned Connectors

These sources need dedicated connectors instead of being placed in
`SAFE_ZONE_AGENT_FEED_SOURCES`:

| Source | Connector requirement |
| --- | --- |
| Google Safe Browsing, VirusTotal, urlscan.io, PhishTank, Pulsedive, AlienVault OTX, Destroy API | API key, quota handling, caching, and provider rotation |
| MISP, STIX/TAXII | Structured collection/client support and indicator expiry |
| `zen.spamhaus.org` | DNSBL lookup policy and license/rate-limit handling |
| Certstream / Certificate Transparency | Long-running stream consumer, keyword rules, and verification before promotion |
| Tranco / Cloudflare Radar Top Domains | Whitelist ingestion with revisioning and false-positive controls |
| dnstwist | Candidate generation followed by verification; generated domains are not evidence by themselves |
| Chống Lừa Đảo / Tín Nhiệm Mạng | Use an official documented feed or API when one is available |

AdGuard Home, Pi-hole, StevenBlack hosts, hostsVN, and broad "big blocklist"
collections are deployment/blocking tools or mixed-purpose lists. They are not
included in the malicious-domain preset because doing so would label ads,
trackers, and other unwanted but non-malicious domains as phishing.

## Current Retention Limitation

The scheduled multi-source sync is additive. A domain removed from an upstream
feed is not automatically removed from the aggregate Redis set. Operators
should periodically rebuild the aggregate feed, and a future source-aware sync
must track per-source membership and indicator expiry before promoting this
path to authoritative long-term retention.
