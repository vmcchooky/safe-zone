// Command feed-shared-host-audit inventories threat-feed members that the
// current admission policy would refuse today.
//
// It is strictly read-only: it never writes, deletes or mutates Redis. The
// purpose is to produce a reviewable inventory before any targeted purge, so
// the operator can confirm that a stale shared-host member is removable
// without guessing which hostnames the code currently treats as shared
// infrastructure.
//
//	feed-shared-host-audit [flags]
//	feed-shared-host-audit -member docs.google.com -member github.com
//
// The classification comes from feed.IsAdmissibleDomain, the same predicate
// every feed writer and the OSINT promotion path already use. Hardcoding a
// host list here would drift from production behavior as soon as the
// analysis registries change.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"safe-zone/internal/analysis"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/feed"
)

type memberVerdict struct {
	Domain    string `json:"domain"`
	Refused   bool   `json:"refused"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Score     int64  `json:"score,omitempty"`
}

type auditReport struct {
	FeedKey         string          `json:"feed_key"`
	FeedRevision    string          `json:"feed_revision,omitempty"`
	ScannedMembers  int64           `json:"scanned_members"`
	RefusedMembers  int             `json:"refused_members"`
	SampleCap       int             `json:"sample_cap"`
	Sample          []memberVerdict `json:"sample"`
	ExplicitMembers []memberVerdict `json:"explicit_members,omitempty"`
	ReadOnly        bool            `json:"read_only"`
}

// sampleCap bounds the reported sample so a large stale backlog cannot flood
// the operator terminal or a CI log.
const sampleCap = 200

// scanBatch keeps the ZSCAN cursor walk cheap on a half-million member set.
const scanBatch = 2000

func main() {
	buildinfo.Link()

	redisAddr := flag.String("redis-addr", config.String("SAFE_ZONE_REDIS_ADDR", ""), "Redis address")
	redisPassword := flag.String("redis-password", config.SecretString("SAFE_ZONE_REDIS_PASSWORD", ""), "Redis password")
	redisDB := flag.Int("redis-db", config.Int("SAFE_ZONE_REDIS_DB", 0), "Redis database")
	key := flag.String("key", config.String("SAFE_ZONE_THREAT_FEED_KEY", feed.DefaultThreatFeedKey), "Redis sorted-set key holding the threat feed")
	scanTimeout := flag.Duration("timeout", 5*time.Minute, "overall scan timeout")
	asJSON := flag.Bool("json", false, "emit the report as JSON")
	var members multiFlag
	flag.Var(&members, "member", "classify an explicit member instead of scanning (repeatable)")
	flag.Parse()

	report := auditReport{FeedKey: *key, ReadOnly: true, SampleCap: sampleCap}

	ctx, cancel := context.WithTimeout(context.Background(), *scanTimeout)
	defer cancel()

	if len(members) > 0 {
		report.ExplicitMembers = classifyMembers(members)
		for _, verdict := range report.ExplicitMembers {
			if verdict.Refused {
				report.RefusedMembers++
			}
		}
	} else {
		if strings.TrimSpace(*redisAddr) == "" {
			fmt.Fprintln(os.Stderr, "redis address is required for a scan; use -member to classify domains offline")
			os.Exit(2)
		}
		client := redis.NewClient(&redis.Options{Addr: *redisAddr, Password: *redisPassword, DB: *redisDB})
		defer func() { _ = client.Close() }()

		revision, err := client.Get(ctx, feed.RevisionKey(*key)).Result()
		if err != nil && err != redis.Nil {
			fmt.Fprintf(os.Stderr, "read feed revision: %v\n", err)
			os.Exit(1)
		}
		report.FeedRevision = revision

		total, err := client.ZCard(ctx, *key).Result()
		if err != nil {
			fmt.Fprintf(os.Stderr, "read feed size: %v\n", err)
			os.Exit(1)
		}
		report.ScannedMembers = total

		sample, refused, err := scanRefused(ctx, client, *key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan feed: %v\n", err)
			os.Exit(1)
		}
		report.Sample = sample
		report.RefusedMembers = refused
	}
	if *asJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(encoded))
		return
	}

	printHumanReport(report)
}

// scanRefused walks the feed with ZSCAN and returns a bounded sample plus the
// full refused count. The full count is what the operator needs to size a
// purge; the sample is what they need to review it.
//
// Redis ZSCAN returns interleaved member/score elements. go-redis exposes the
// generic ScanCmd, so the caller must walk the result in pairs; an odd length
// would mean a truncated page and is reported instead of silently misread.
func scanRefused(ctx context.Context, client *redis.Client, key string) ([]memberVerdict, int, error) {
	var (
		cursor   uint64
		refused  []memberVerdict
		complete bool
	)
	for !complete {
		page, next, err := client.ZScan(ctx, key, cursor, "*", scanBatch).Result()
		if err != nil {
			return nil, 0, err
		}
		if len(page)%2 != 0 {
			return nil, 0, fmt.Errorf("ZSCAN returned %d elements; expected member/score pairs", len(page))
		}
		for i := 0; i < len(page); i += 2 {
			score, err := strconv.ParseInt(page[i+1], 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("parse ZSCAN score %q: %w", page[i+1], err)
			}
			if feed.IsAdmissibleDomain(page[i]) {
				continue
			}
			refused = append(refused, classify(page[i], score))
		}
		cursor = next
		complete = cursor == 0
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
	}

	refusedCount := len(refused)
	if len(refused) > sampleCap {
		refused = refused[:sampleCap]
	}
	return refused, refusedCount, nil
}

func classifyMembers(domains []string) []memberVerdict {
	verdicts := make([]memberVerdict, 0, len(domains))
	for _, domain := range domains {
		verdicts = append(verdicts, classify(domain, 0))
	}
	return verdicts
}

// classify applies the production admission predicate to a single member and
// records why it would be refused. The reason is derived from the exported
// analysis predicates so the operator can tell a shared serving host from a
// shared hosting root.
func classify(rawMember string, score int64) memberVerdict {
	domain := strings.ToLower(strings.TrimSpace(rawMember))
	verdict := memberVerdict{Domain: domain, Score: score}
	if score > 0 {
		verdict.ExpiresAt = time.Unix(score, 0).UTC().Format(time.RFC3339)
	}
	if feed.IsAdmissibleDomain(domain) {
		return verdict
	}
	verdict.Refused = true
	switch {
	case analysis.IsSharedServingHost(domain):
		verdict.Reason = "shared serving host"
	case analysis.IsSharedHostingRoot(domain):
		verdict.Reason = "shared hosting root"
	default:
		verdict.Reason = "public suffix member"
	}
	return verdict
}

func printHumanReport(report auditReport) {
	fmt.Printf("feed key:        %s\n", report.FeedKey)
	if report.FeedRevision != "" {
		fmt.Printf("feed revision:   %s\n", report.FeedRevision)
	}
	fmt.Printf("read-only:       %t\n", report.ReadOnly)
	if len(report.ExplicitMembers) > 0 {
		fmt.Printf("explicit members refused: %d\n\n", report.RefusedMembers)
		for _, verdict := range report.ExplicitMembers {
			printVerdict(verdict)
		}
		return
	}
	fmt.Printf("scanned members: %d\n", report.ScannedMembers)
	fmt.Printf("refused members: %d (sample cap %d)\n", report.RefusedMembers, report.SampleCap)
	if report.RefusedMembers == 0 {
		fmt.Println("\nno stale shared-host members: nothing to purge.")
		return
	}
	fmt.Println("\nsample of refused members:")
	for _, verdict := range report.Sample {
		printVerdict(verdict)
	}
	if report.RefusedMembers > len(report.Sample) {
		fmt.Printf("... and %d more\n", report.RefusedMembers-len(report.Sample))
	}
}

func printVerdict(verdict memberVerdict) {
	if !verdict.Refused {
		fmt.Printf("  ADMISSIBLE  %s\n", verdict.Domain)
		return
	}
	line := fmt.Sprintf("  REFUSED     %-40s %s", verdict.Domain, verdict.Reason)
	if verdict.ExpiresAt != "" {
		line += " expires=" + verdict.ExpiresAt
	}
	fmt.Println(line)
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("member must not be empty")
	}
	*m = append(*m, value)
	return nil
}
