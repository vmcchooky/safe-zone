// Command block-audit turns the SQLite analysis log into a reviewable
// inventory of every domain the service has actually blocked.
//
// At low traffic volume a statistical false-positive rate is not measurable,
// but the *complete* set of blocked domains is finite and small. This command
// enumerates that set instead of sampling it, and sorts each domain by the
// blast radius of a wrong block: breaking a payment, banking, government,
// authentication or messaging endpoint is a service outage, while blocking an
// advertising endpoint is the product working as intended.
//
// The command is read-only. It never mutates the database and never changes
// policy, so it is safe to run against a live production copy.
//
//	block-audit [-db path] [-since RFC3339] [-json] [-csv out.csv]
package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"safe-zone/internal/analysis"
	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
)

// Class describes why a domain is on the blocked list and what a correct
// outcome would be.
type Class string

const (
	// ClassOperatorOverride is a block the operator set by hand. It is never a
	// false positive candidate: the human already decided.
	ClassOperatorOverride Class = "operator_override"
	// ClassCriticalService is infrastructure whose loss breaks a user-facing
	// capability such as payment, banking, identity or messaging.
	ClassCriticalService Class = "critical_service"
	// ClassAppCritical is infrastructure whose loss degrades an application
	// (crash reporting, push, configuration delivery) without taking the
	// user-facing feature offline.
	ClassAppCritical Class = "app_critical"
	// ClassSharedInfra is delegated CDN or self-service hosting infrastructure
	// whose blocking can cascade across unrelated tenants.
	ClassSharedInfra Class = "shared_infra"
	// ClassAdsTracking is advertising or telemetry the product intends to
	// suppress. Blocking is the expected behaviour, not a defect.
	ClassAdsTracking Class = "ads_tracking"
	// ClassUnclassified is anything the rules below do not recognize. These
	// are the entries an operator must judge.
	ClassUnclassified Class = "unclassified"
)

// severity orders classes from most to least damaging when blocked wrongly.
// It drives report ordering so the top of the output is the work that matters.
func (c Class) severity() int {
	switch c {
	case ClassCriticalService:
		return 0
	case ClassAppCritical:
		return 1
	case ClassSharedInfra:
		return 2
	case ClassOperatorOverride:
		return 3
	case ClassUnclassified:
		return 4
	case ClassAdsTracking:
		return 5
	default:
		return 6
	}
}

// recommendation is the operator-facing next step implied by the class.
func (c Class) recommendation() string {
	switch c {
	case ClassOperatorOverride:
		return "keep: operator already decided"
	case ClassCriticalService:
		return "scoped content exception required"
	case ClassAppCritical:
		return "scoped content exception recommended"
	case ClassSharedInfra:
		return "verify ownership, then exception if shared"
	case ClassAdsTracking:
		return "keep: intended suppression"
	default:
		return "operator review required"
	}
}

// DomainRecord is one distinct blocked domain with its observed history.
type DomainRecord struct {
	Domain    string   `json:"domain"`
	Blocks    int      `json:"blocks"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	ActiveDay int      `json:"active_days"`
	Verdicts  []string `json:"verdicts"`
	Reasons   []string `json:"reasons"`
	Sources   []string `json:"sources"`
	Class     Class    `json:"class"`
	Action    string   `json:"recommended_action"`
}

// Report is the full audit output.
type Report struct {
	GeneratedAt   string         `json:"generated_at"`
	Database      string         `json:"database"`
	Since         string         `json:"since,omitempty"`
	TotalBlocks   int            `json:"total_block_events"`
	DistinctHosts int            `json:"distinct_blocked_domains"`
	ByClass       map[string]int `json:"block_events_by_class"`
	Records       []DomainRecord `json:"records"`
}

// Hint matching is two-tier on purpose.
//
// A plain substring test over the whole host is too loose: it matched
// "scorecardresearch" as a payment hint because of "card", and "otpi00g" as an
// OTP hint. Those false labels push real work to the bottom of the report.
//
// exactLabelHints must equal a whole DNS label, so short ambiguous tokens
// ("log", "otp", "gov", "ads") only fire on a real label of that name.
// substringHints may match inside a label, which is required for compound
// infrastructure names such as "sdkconfig", "firebaselogging" and
// "crashlytics". Every substring hint is long enough that an incidental match
// inside an unrelated word is unlikely.
//
// This is still a triage aid, not a security decision: a wrong label only
// misranks an audit row for human review, it never unblocks or blocks anything.
// The three classes use separate hint lists because a single list cannot rank
// damage: "firebase" must outrank "analytics", and "ads" must lose to
// "crashlytics" even though both appear in the same SDK hostname.
var criticalExactHints = []string{
	"gov", "govvn", "sso", "oauth", "auth", "auths", "login", "account",
	"identity", "chat", "otp", "sms", "pay", "payment", "wallet",
}

var criticalSubstringHints = []string{
	"payment", "checkout", "billing", "wallet", "transaction",
	"shopeepay", "momo", "vnpay", "banking", "creditcard", "cardpay",
	"zalo", "messenger", "telepathy", "passkey", "notification",
}

var appExactHints = []string{"log", "logs", "config", "settings", "crash", "push", "fcm", "apns"}

var appSubstringHints = []string{
	"crashlytics", "firebase", "logging", "telemetry", "analytics",
	"config", "settings", "sdk", "fcm", "apns",
}

var adsExactHints = []string{"ads"}

var adsSubstringHints = []string{
	"doubleclick", "adserver", "adservice", "admaster", "admob",
	"applovin", "applvn", "inmobi", "fyber", "pangle", "appsflyer",
	"adjust", "mintegral", "liftoff", "rayjump", "mtgglobals",
	"scorecardresearch", "mixpanel", "gvt2", "googleads",
	"googlesyndication", "googletagmanager", "googletagservices",
	"doubleverify", "cookielaw", "fundingchoices", "kochava", "umeng",
	"sensorsdata", "talkingdata", "countly", "hotjar", "logrocket",
	"mouseflow", "crazyegg", "quantcast", "branch", "amplitude",
	"yandex", "mailru", "clicky", "piwik", "matomo", "clarity",
	"fullstory", "smartlook", "inspectlet", "growingio", "vungle",
	"unity3d", "singular",
}

// hostLabels splits a host into lowercase DNS labels.
func hostLabels(host string) []string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(host)), ".")
	labels := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			labels = append(labels, part)
		}
	}
	return labels
}

// matchesAny reports whether a host satisfies a hint list. An exact hint must
// equal a whole label; a substring hint may match inside a label.
func matchesAny(host string, exact, substring []string) bool {
	labels := hostLabels(host)
	for _, label := range labels {
		for _, hint := range exact {
			if label == hint {
				return true
			}
		}
	}
	joined := strings.Join(labels, ".")
	for _, hint := range substring {
		if strings.Contains(joined, hint) {
			return true
		}
	}
	return false
}

// classifyDomain assigns a blast-radius class.
//
// Order matters. An operator override wins over everything because a human
// already judged that domain. Shared infrastructure is checked before the
// hint lists so a CDN hostname is never mislabelled by a substring in
// "log" or "config". Ads and tracking are checked last because the hints
// overlap: an SDK can be both analytics and ad infrastructure, and treating
// that as "intended suppression" is the safe default for review noise.
func classifyDomain(domain string, reasons []string) Class {
	host := strings.ToLower(strings.TrimSpace(domain))
	if host == "" {
		return ClassUnclassified
	}

	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), "admin override") {
			return ClassOperatorOverride
		}
	}

	if analysis.IsSharedServingHost(host) || analysis.IsSharedHostingRoot(host) {
		return ClassSharedInfra
	}

	if matchesAny(host, criticalExactHints, criticalSubstringHints) {
		return ClassCriticalService
	}
	if matchesAny(host, appExactHints, appSubstringHints) {
		return ClassAppCritical
	}
	if matchesAny(host, adsExactHints, adsSubstringHints) {
		return ClassAdsTracking
	}
	return ClassUnclassified
}

// loadBlockedDomains reads every block event from the analysis log.
//
// The result set is small by construction: it holds one row per block event,
// and a low-traffic deployment produces thousands, not millions. Aggregating
// in Go keeps the SQL portable and lets the classifier see the full reason
// history of a domain instead of an arbitrary sample.
func loadBlockedDomains(ctx context.Context, dbPath, since string) (map[string]*DomainRecord, int, error) {
	dsn := "file:" + dbPath + "?mode=ro&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, 0, fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	query := `SELECT domain, verdict, reasons, source, created_at
	          FROM analysis_log
	          WHERE policy_action = 'block'`
	args := []any{}
	if since != "" {
		query += ` AND created_at >= ?`
		args = append(args, since)
	}
	query += ` ORDER BY created_at`

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query analysis_log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	records := map[string]*DomainRecord{}
	days := map[string]map[string]struct{}{}
	total := 0
	for rows.Next() {
		var domain, verdict, reasons, source, createdAt string
		if err := rows.Scan(&domain, &verdict, &reasons, &source, &createdAt); err != nil {
			return nil, 0, fmt.Errorf("scan row: %w", err)
		}
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		total++

		record, ok := records[domain]
		if !ok {
			record = &DomainRecord{Domain: domain, FirstSeen: createdAt}
			records[domain] = record
			days[domain] = map[string]struct{}{}
		}
		record.Blocks++
		record.LastSeen = createdAt
		record.Verdicts = appendUnique(record.Verdicts, verdict)
		record.Sources = appendUnique(record.Sources, source)
		// reasons is a JSON array string; keep the raw text so an operator can
		// see exactly which signals fired without this tool re-implementing
		// the reason vocabulary.
		if strings.TrimSpace(reasons) != "" {
			record.Reasons = appendUnique(record.Reasons, reasons)
		}
		days[domain][createdAt[:min(len(createdAt), 10)]] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate rows: %w", err)
	}

	for domain, record := range records {
		record.ActiveDay = len(days[domain])
		record.Class = classifyDomain(domain, record.Reasons)
		record.Action = record.Class.recommendation()
	}
	return records, total, nil
}

func appendUnique(list []string, value string) []string {
	if value == "" {
		return list
	}
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

func main() {
	buildinfo.Link()

	dbPath := flag.String("db", config.String("SAFE_ZONE_SQLITE_PATH", ""), "path to the Safe Zone SQLite database (read-only)")
	since := flag.String("since", "", "only include block events at or after this timestamp, e.g. 2026-09-13")
	asJSON := flag.Bool("json", false, "emit the report as JSON")
	csvOut := flag.String("csv", "", "also write the inventory as CSV to this path")
	flag.Parse()

	if strings.TrimSpace(*dbPath) == "" {
		fmt.Fprintln(os.Stderr, "database path is required; pass -db or set SAFE_ZONE_SQLITE_PATH")
		os.Exit(2)
	}
	if _, err := os.Stat(*dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "database not readable: %v\n", err)
		os.Exit(1)
	}

	records, total, err := loadBlockedDomains(context.Background(), *dbPath, *since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "block audit failed: %v\n", err)
		os.Exit(1)
	}

	list := make([]DomainRecord, 0, len(records))
	byClass := map[string]int{}
	for _, record := range records {
		list = append(list, *record)
		byClass[string(record.Class)] += record.Blocks
	}
	// Most damaging class first, then by how often it actually fires, then by
	// domain so the ordering is stable across runs.
	sort.Slice(list, func(i, j int) bool {
		si, sj := list[i].Class.severity(), list[j].Class.severity()
		if si != sj {
			return si < sj
		}
		if list[i].Blocks != list[j].Blocks {
			return list[i].Blocks > list[j].Blocks
		}
		return list[i].Domain < list[j].Domain
	})

	report := Report{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Database:      *dbPath,
		Since:         *since,
		TotalBlocks:   total,
		DistinctHosts: len(list),
		ByClass:       byClass,
		Records:       list,
	}

	if *asJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(encoded))
	} else {
		printHumanReport(report)
	}

	if strings.TrimSpace(*csvOut) != "" {
		if err := writeCSV(*csvOut, list); err != nil {
			fmt.Fprintf(os.Stderr, "write csv: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nCSV written to %s\n", *csvOut)
	}
}

func printHumanReport(report Report) {
	fmt.Printf("database:         %s\n", report.Database)
	if report.Since != "" {
		fmt.Printf("since:            %s\n", report.Since)
	}
	fmt.Printf("block events:     %d across %d distinct domains\n", report.TotalBlocks, report.DistinctHosts)
	fmt.Printf("read-only:        true\n")

	if report.TotalBlocks == 0 {
		fmt.Println("\nno block events: nothing to review.")
		return
	}

	fmt.Println("\nblock events by class:")
	classes := make([]string, 0, len(report.ByClass))
	for class := range report.ByClass {
		classes = append(classes, class)
	}
	sort.Slice(classes, func(i, j int) bool {
		return Class(classes[i]).severity() < Class(classes[j]).severity()
	})
	for _, class := range classes {
		fmt.Printf("  %-20s %8d\n", class, report.ByClass[class])
	}

	fmt.Println("\ninventory (most damaging class first):")
	fmt.Printf("  %-20s %7s %6s %-28s %s\n", "CLASS", "BLOCKS", "DAYS", "VERDICTS", "DOMAIN")
	for _, record := range report.Records {
		fmt.Printf("  %-20s %7d %6d %-28s %s\n",
			record.Class, record.Blocks, record.ActiveDay,
			strings.Join(record.Verdicts, ","), record.Domain)
	}

	// Surface the work that matters first instead of making the operator hunt
	// for it in a long table.
	fmt.Println("\nrequires operator action:")
	actioned := 0
	for _, record := range report.Records {
		if record.Class == ClassAdsTracking || record.Class == ClassOperatorOverride {
			continue
		}
		fmt.Printf("  [%s] %s (blocks=%d days=%d) -> %s\n",
			record.Class, record.Domain, record.Blocks, record.ActiveDay, record.Action)
		actioned++
	}
	if actioned == 0 {
		fmt.Println("  none")
	}
}

func writeCSV(path string, records []DomainRecord) error {
	// #nosec G304 -- the output path is supplied by the operator running this
	// CLI, not by a remote caller, and the tool has no server surface. The
	// read-only guarantee applies to the database, not to where the operator
	// chooses to write the report.
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"class", "domain", "blocks", "active_days", "verdicts", "sources", "first_seen", "last_seen", "reasons", "recommended_action"}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, record := range records {
		row := []string{
			string(record.Class),
			record.Domain,
			strconv.Itoa(record.Blocks),
			strconv.Itoa(record.ActiveDay),
			strings.Join(record.Verdicts, "|"),
			strings.Join(record.Sources, "|"),
			record.FirstSeen,
			record.LastSeen,
			strings.Join(record.Reasons, " | "),
			record.Action,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}
