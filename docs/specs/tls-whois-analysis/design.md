# Design: TLS Certificate (x.509) & WHOIS Age Analysis Module

## Architecture

Two new packages added to the analysis pipeline as **enrichment modules**. They run only in the "suspicious zone" (lexical score 20-69) and execute in parallel with a combined timeout.

```
Current Pipeline:
Override → Whitelist → Cache → Feed → Lexical → AI → Cache Write

New Pipeline:
Override → Whitelist → Cache → Feed → Lexical → [TLS+WHOIS enrichment] → AI → Cache Write
                                                   ↑
                                          Only if score 20-69
                                          Parallel, with timeout
```

## Package: `internal/tlsinspect`

### Core Logic

```go
// Result contains TLS certificate analysis results.
type Result struct {
    HasTLS       bool          `json:"has_tls"`
    Valid        bool          `json:"valid"`
    SelfSigned   bool          `json:"self_signed"`
    Expired      bool          `json:"expired"`
    Issuer       string        `json:"issuer"`
    Subject      string        `json:"subject"`
    SANMatch     bool          `json:"san_match"`
    CertAgeDays  int           `json:"cert_age_days"`
    IsWildcard   bool          `json:"is_wildcard"`
    NotBefore    time.Time     `json:"not_before"`
    NotAfter     time.Time     `json:"not_after"`
    Score        int           `json:"score"`
    Reasons      []string      `json:"reasons"`
}

// Inspect performs a TLS handshake to domain:443 and analyzes the certificate.
func Inspect(ctx context.Context, domain string) Result
```

### TLS Handshake Strategy

```go
dialer := &tls.Dialer{
    Config: &tls.Config{
        InsecureSkipVerify: true,  // We inspect the cert ourselves
        ServerName:         domain,
    },
    NetDialer: &net.Dialer{Timeout: timeout},
}
conn, err := dialer.DialContext(ctx, "tcp", domain+":443")
```

- `InsecureSkipVerify: true` because we want to inspect invalid/self-signed certs.
- We manually validate the certificate chain and check for issues.
- Connection is closed immediately after getting the cert (no HTTP request made).

### Scoring Logic

```go
func score(domain string, cert *x509.Certificate) (int, []string) {
    score := 0
    reasons := []string{}

    // Self-signed
    if cert.Issuer.String() == cert.Subject.String() {
        score += 25
        reasons = append(reasons, "tls: self-signed certificate")
    }

    // Expired
    if time.Now().After(cert.NotAfter) {
        score += 20
        reasons = append(reasons, "tls: expired certificate")
    }

    // Fresh cert (< 7 days)
    certAge := time.Since(cert.NotBefore)
    if certAge < 7*24*time.Hour {
        score += 15
        reasons = append(reasons, "tls: certificate issued < 7 days ago")
    }

    // SAN mismatch
    if !certMatchesDomain(cert, domain) {
        score += 30
        reasons = append(reasons, "tls: certificate name mismatch")
    }

    return score, reasons
}
```

## Package: `internal/whois`

### Core Logic

```go
// Result contains WHOIS domain age analysis results.
type Result struct {
    Found          bool      `json:"found"`
    RegisteredDate time.Time `json:"registered_date"`
    DomainAgeDays  int       `json:"domain_age_days"`
    Registrar      string    `json:"registrar"`
    PrivacyGuard   bool      `json:"privacy_guard"`
    Score          int       `json:"score"`
    Reasons        []string  `json:"reasons"`
}

// Lookup queries WHOIS for the registered domain and extracts age.
func Lookup(ctx context.Context, domain string) Result
```

### WHOIS Query Strategy

1. Extract the **registered domain** from the full domain (e.g., `mail.example.com` → `example.com`).
2. Determine the WHOIS server for the TLD (hardcoded map of common TLDs):
   ```go
   var whoisServers = map[string]string{
       "com":  "whois.verisign-grs.com",
       "net":  "whois.verisign-grs.com",
       "org":  "whois.pir.org",
       "info": "whois.afilias.net",
       "io":   "whois.nic.io",
       // ... etc
   }
   ```
3. Connect via TCP, send `domain\r\n`, read response.
4. Parse response for `Creation Date`, `Registration Date`, or `created` fields using regex.
5. Calculate domain age in days.

### Parsing Strategy

WHOIS responses are unstructured text. We use a prioritized list of regex patterns:

```go
var datePatterns = []string{
    `Creation Date:\s*(.+)`,
    `Registration Date:\s*(.+)`,
    `created:\s*(.+)`,
    `Created:\s*(.+)`,
    `Registration Time:\s*(.+)`,
    `Domain Registration Date:\s*(.+)`,
}

var dateFormats = []string{
    time.RFC3339,
    "2006-01-02T15:04:05Z",
    "2006-01-02",
    "02-Jan-2006",
    "January 02 2006",
}
```

### Scoring Logic

```go
func score(ageDays int, privacyGuard bool) (int, []string) {
    score := 0
    reasons := []string{}

    switch {
    case ageDays < 7:
        score += 25
        reasons = append(reasons, "whois: domain registered < 7 days ago")
    case ageDays < 30:
        score += 15
        reasons = append(reasons, "whois: domain registered < 30 days ago")
    case ageDays < 90:
        score += 5
        reasons = append(reasons, "whois: domain registered < 90 days ago")
    }

    if privacyGuard {
        score += 5
        reasons = append(reasons, "whois: privacy guard enabled")
    }

    return score, reasons
}
```

## Pipeline Integration: `internal/risk/service.go`

### Enrichment Method

```go
func (s *Service) enrichSuspicious(ctx context.Context, domain string, result *analysis.Result) {
    if result.Score < 20 || result.Score >= 70 {
        return // Only enrich the suspicious zone
    }

    ctx, cancel := context.WithTimeout(ctx, s.enrichTimeout)
    defer cancel()

    var tlsResult tlsinspect.Result
    var whoisResult whois.Result
    var wg sync.WaitGroup

    wg.Add(2)
    go func() {
        defer wg.Done()
        tlsResult = tlsinspect.Inspect(ctx, domain)
    }()
    go func() {
        defer wg.Done()
        whoisResult = whois.Lookup(ctx, domain)
    }()
    wg.Wait()

    result.Score += tlsResult.Score + whoisResult.Score
    result.Reasons = append(result.Reasons, tlsResult.Reasons...)
    result.Reasons = append(result.Reasons, whoisResult.Reasons...)

    // Recalculate verdict based on new score
    if result.Score > 100 { result.Score = 100 }
    result.Verdict = verdictFromScore(result.Score)
    result.Confidence = confidenceFromScore(result.Score)
}
```

### Placement in `analyze()` Pipeline

```go
func (s *Service) analyze(ctx context.Context, domain string) (analysis.Result, bool) {
    // ... override, whitelist, cache, feed checks ...

    // 5. Lexical analysis
    result := s.analyzer.Analyze(normalized)

    // 6. TLS + WHOIS enrichment (only for suspicious zone)
    s.enrichSuspicious(ctx, normalized, &result)

    // 7. Local AI refinement (only for still-suspicious)
    // ... existing AI logic ...
}
```

## Caching Strategy

TLS and WHOIS results are cached separately:

```go
// Cache key format:
// "safe-zone:tls:{domain}" → JSON of tlsinspect.Result
// "safe-zone:whois:{registeredDomain}" → JSON of whois.Result

// Before network call:
cached, err := s.redis.Get(ctx, "safe-zone:tls:"+domain)
if err == nil {
    return unmarshalTLSResult(cached)
}

// After network call:
s.redis.Set(ctx, "safe-zone:tls:"+domain, marshalTLSResult(result), ttl)
```

WHOIS is cached by **registered domain** (not full domain) because `mail.example.com` and `www.example.com` share the same WHOIS data.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SAFE_ZONE_ENRICH_ENABLED` | `true` | Enable/disable TLS+WHOIS enrichment |
| `SAFE_ZONE_ENRICH_TIMEOUT_MS` | `3000` | Combined timeout for TLS+WHOIS (ms) |
| `SAFE_ZONE_TLS_INSPECT_ENABLED` | `true` | Enable/disable TLS inspection |
| `SAFE_ZONE_WHOIS_ENABLED` | `true` | Enable/disable WHOIS lookup |

## Files Changed

### New Files
| File | Description |
|---|---|
| `internal/tlsinspect/inspect.go` | TLS handshake + certificate analysis |
| `internal/tlsinspect/inspect_test.go` | Unit tests with mock TLS server |
| `internal/whois/lookup.go` | WHOIS TCP query + date parsing |
| `internal/whois/lookup_test.go` | Unit tests with mock WHOIS server |

### Modified Files
| File | Change |
|---|---|
| `internal/risk/service.go` | Add `enrichSuspicious()` method, call between lexical and AI |
| `internal/risk/env.go` | Add enrichment env vars |
| `internal/config/analysis.go` | Add enrichment config fields |
| `.env.example` | Add enrichment env vars |
| `docker-compose.yml` | Add enrichment env vars |

## What This Design Excludes

- Passive DNS lookups.
- WHOIS for non-ICANN TLDs (some ccTLDs use proprietary protocols).
- Certificate Transparency (CT) log queries.
- Domain reputation databases (VirusTotal, URLhaus, etc.).
- SSL vulnerability scanning.
