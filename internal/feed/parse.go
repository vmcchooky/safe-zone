package feed

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"safe-zone/internal/analysis"
)

type ParseStats struct {
	Valid      int `json:"valid"`
	Invalid    int `json:"invalid"`
	Duplicates int `json:"duplicates"`
	Skipped    int `json:"skipped"`
}

type ParseResult struct {
	Domains []string   `json:"domains"`
	Stats   ParseStats `json:"stats"`
}

// Parse parses the input stream line by line in a memory-efficient streaming manner.
// To protect against decompression bombs, it caps the decompressed stream size at 100MB.
func Parse(r io.Reader) (ParseResult, error) {
	var result ParseResult
	err := ParseEach(r, func(domain string) error {
		result.Domains = append(result.Domains, domain)
		return nil
	}, &result.Stats)
	if err != nil {
		return ParseResult{}, err
	}
	return result, nil
}

// ParseEach streams domain names from the reader and invokes the handler callback
// for each successfully parsed domain. Caps parsing at 100MB to avoid OOM crashes.
func ParseEach(r io.Reader, onDomain func(domain string) error, stats *ParseStats) error {
	if onDomain == nil {
		return errors.New("domain handler is required")
	}
	if stats == nil {
		stats = &ParseStats{}
	}

	// Enforce 100MB decompression limit
	limited := io.LimitReader(r, 100*1024*1024)

	br := bufio.NewReader(limited)
	peekBytes, _ := br.Peek(4096)

	seen := make(map[string]struct{})

	if isProbablyCSV(peekBytes) {
		return parseCSVStream(br, seen, stats, onDomain)
	}

	return parseTextStream(br, seen, stats, onDomain)
}

func parseCSVStream(r io.Reader, seen map[string]struct{}, stats *ParseStats, onDomain func(string) error) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // Allow variable fields per row to prevent drift crashes

	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			stats.Invalid++
			continue
		}

		if len(row) == 0 {
			stats.Skipped++
			continue
		}

		domain, ok := firstDomain(row)
		if !ok {
			stats.Invalid++
			continue
		}

		if err := addDomain(stats, seen, domain, onDomain); err != nil {
			return err
		}
	}

	return nil
}

func parseTextStream(r io.Reader, seen map[string]struct{}, stats *ParseStats, onDomain func(string) error) error {
	scanner := bufio.NewScanner(r)
	// Enforce maximum line size of 1MB (1024*1024 bytes) as asserted by tests
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			stats.Skipped++
			continue
		}
		if strings.HasPrefix(line, "#") {
			stats.Skipped++
			continue
		}

		parsedAny := false
		lineHadValid := false
		lineInvalid := 0
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "#") {
				break
			}
			field = stripComment(strings.TrimSpace(field))
			if field == "" {
				continue
			}
			// Hosts-format feeds start with a sinkhole IP such as 0.0.0.0 or
			// 127.0.0.1. It is metadata, not an invalid domain candidate.
			if net.ParseIP(strings.Trim(field, "[]")) != nil {
				continue
			}
			parsedAny = true

			domain, err := normalizeCandidate(field)
			if err != nil {
				lineInvalid++
				continue
			}

			lineHadValid = true
			if err := addDomain(stats, seen, domain, onDomain); err != nil {
				return err
			}
		}
		if !parsedAny {
			stats.Skipped++
			continue
		}
		if lineHadValid {
			stats.Invalid += lineInvalid
			continue
		}
		if lineInvalid > 0 {
			stats.Invalid++
		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("feed line exceeds 1048576 bytes: %w", err)
		}
		return err
	}

	return nil
}

func firstDomain(fields []string) (string, bool) {
	for _, field := range fields {
		field = stripComment(strings.TrimSpace(field))
		if field == "" {
			continue
		}

		domain, err := normalizeCandidate(field)
		if err == nil {
			return domain, true
		}
	}

	return "", false
}

func addDomain(stats *ParseStats, seen map[string]struct{}, domain string, onDomain func(string) error) error {
	if _, exists := seen[domain]; exists {
		stats.Duplicates++
		return nil
	}

	seen[domain] = struct{}{}
	stats.Valid++
	return onDomain(domain)
}

func stripComment(value string) string {
	if strings.HasPrefix(value, "#") {
		return ""
	}
	if index := strings.Index(value, "#"); index >= 0 {
		return strings.TrimSpace(value[:index])
	}

	return value
}

func normalizeCandidate(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty feed candidate")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", errors.New("invalid feed url candidate")
		}
		value = parsed.Hostname()
	}

	domain, err := analysis.NormalizeDomain(value)
	if err != nil {
		return "", err
	}
	if !strings.Contains(domain, ".") {
		return "", errors.New("feed candidate must be a domain, not a single label")
	}

	return domain, nil
}

func isProbablyCSV(peek []byte) bool {
	if len(peek) == 0 {
		return false
	}
	lines := strings.Split(string(peek), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.Contains(line, ",")
	}

	return false
}
