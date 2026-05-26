package feed

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"safe-zone/internal/cache"
	"safe-zone/internal/safefile"
)

const DefaultThreatFeedKey = "safe-zone:threat:feed"
const DefaultMaxFeedBytes int64 = 50 * 1024 * 1024
const defaultRedisBatchSize = 1000

type SyncOptions struct {
	Source                     string
	FileRoot                   string
	MaxBytes                   int64
	RedisAddr                  string
	RedisPassword              string
	RedisDB                    int
	Key                        string
	DryRun                     bool
	Replace                    bool
	Timeout                    time.Duration
	Client                     *http.Client
	ParserDriftInvalidRatio    float64
	ParserDriftMinInvalid      int
	CacheInvalidationMinWrites int64
}

type SyncReport struct {
	Source            string     `json:"source"`
	Key               string     `json:"key"`
	DryRun            bool       `json:"dry_run"`
	Replace           bool       `json:"replace"`
	Stats             ParseStats `json:"stats"`
	Written           int64      `json:"written"`
	RedisAddr         string     `json:"redis_addr,omitempty"`
	FinishedAt        string     `json:"finished_at"`
	ParserDrift       bool       `json:"parser_drift"`
	ParserDriftReason string     `json:"parser_drift_reason,omitempty"`
	CacheInvalidated  bool       `json:"cache_invalidated"`
	FeedRevision      int64      `json:"feed_revision,omitempty"`
}

func Sync(parent context.Context, options SyncOptions) (SyncReport, error) {
	if strings.TrimSpace(options.Source) == "" {
		return SyncReport{}, errors.New("feed source is required")
	}
	if strings.TrimSpace(options.Key) == "" {
		options.Key = DefaultThreatFeedKey
	}
	if strings.TrimSpace(options.FileRoot) == "" {
		options.FileRoot = "./data"
	}
	if options.MaxBytes <= 0 {
		options.MaxBytes = DefaultMaxFeedBytes
	}

	ctx := parent
	var cancel context.CancelFunc = func() {}
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, options.Timeout)
	}
	defer cancel()

	var redisCache *cache.Redis
	if !options.DryRun && strings.TrimSpace(options.RedisAddr) != "" {
		redisCache = cache.NewRedis(options.RedisAddr, options.RedisPassword, options.RedisDB)
		defer func() {
			_ = redisCache.Close()
		}()
	}

	fail := func(syncErr error) (SyncReport, error) {
		if redisCache != nil {
			_ = recordSyncFailure(ctx, redisCache, options.Key, options.Source, syncErr)
		}
		return SyncReport{}, syncErr
	}

	reader, closeReader, err := OpenSourceWithin(ctx, options.Source, options.Client, options.FileRoot, options.MaxBytes)
	if err != nil {
		return fail(err)
	}
	defer closeReader()

	report := SyncReport{
		Source:     options.Source,
		Key:        options.Key,
		DryRun:     options.DryRun,
		Replace:    options.Replace,
		FinishedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}

	if options.DryRun {
		var stats ParseStats
		err := ParseEach(reader, func(string) error { return nil }, &stats)
		if err != nil {
			return fail(err)
		}
		report.Stats = stats
		report.ParserDrift, report.ParserDriftReason = parserDriftStatus(
			report.Stats,
			options.ParserDriftInvalidRatio,
			options.ParserDriftMinInvalid,
		)
		return report, nil
	}
	if redisCache == nil {
		return fail(errors.New("redis address is required unless dry-run is set"))
	}

	targetKey := options.Key
	stagingKey := ""
	if options.Replace {
		stagingKey = fmt.Sprintf("%s:staging:%d", options.Key, time.Now().UnixNano())
		targetKey = stagingKey
	}

	var (
		stats   ParseStats
		written int64
		batch   []string
	)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := redisCache.SetAdd(ctx, targetKey, batch...)
		if err != nil {
			return err
		}
		written += n
		batch = batch[:0]
		return nil
	}

	err = ParseEach(reader, func(domain string) error {
		batch = append(batch, domain)
		if len(batch) >= defaultRedisBatchSize {
			return flush()
		}
		return nil
	}, &stats)
	if err != nil {
		if stagingKey != "" {
			_ = redisCache.Delete(ctx, stagingKey)
		}
		return fail(err)
	}
	if err := flush(); err != nil {
		if stagingKey != "" {
			_ = redisCache.Delete(ctx, stagingKey)
		}
		return fail(err)
	}
	if stagingKey != "" {
		if stats.Valid == 0 {
			if err := redisCache.Delete(ctx, options.Key); err != nil {
				_ = redisCache.Delete(ctx, stagingKey)
				return fail(err)
			}
			_ = redisCache.Delete(ctx, stagingKey)
		} else {
			if err := redisCache.Rename(ctx, stagingKey, options.Key); err != nil {
				_ = redisCache.Delete(ctx, stagingKey)
				return fail(err)
			}
		}
	}

	report.Written = written
	report.Stats = stats
	report.RedisAddr = options.RedisAddr
	report.ParserDrift, report.ParserDriftReason = parserDriftStatus(
		report.Stats,
		options.ParserDriftInvalidRatio,
		options.ParserDriftMinInvalid,
	)
	if report.Written >= cacheInvalidationMinWrites(options.CacheInvalidationMinWrites) || report.Replace {
		revision, err := redisCache.Increment(ctx, RevisionKey(options.Key))
		if err != nil {
			return fail(err)
		}
		report.CacheInvalidated = true
		report.FeedRevision = revision
	} else {
		revision, err := redisCache.GetInt64(ctx, RevisionKey(options.Key))
		if err == nil {
			report.FeedRevision = revision
		}
	}
	if err := recordSyncSuccess(ctx, redisCache, report); err != nil {
		return fail(err)
	}
	return report, nil
}

func OpenSource(ctx context.Context, source string, client *http.Client) (io.ReadCloser, func(), error) {
	return OpenSourceWithin(ctx, source, client, "./data", DefaultMaxFeedBytes)
}

func OpenSourceWithin(ctx context.Context, source string, client *http.Client, fileRoot string, maxBytes int64) (io.ReadCloser, func(), error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFeedBytes
	}

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, func() {}, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, func() {}, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return nil, func() {}, fmt.Errorf("feed source returned HTTP %d", resp.StatusCode)
		}

		reader, closeReader, err := wrapMaybeCompressedReadCloser(resp.Body, source, resp.Header.Get("Content-Encoding"))
		if err != nil {
			return nil, func() {}, err
		}
		return limitReadCloser(reader, maxBytes), closeReader, nil
	}

	file, err := safefile.OpenWithin(fileRoot, source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, func() {}, fmt.Errorf("feed source file does not exist: %s", source)
		}
		return nil, func() {}, err
	}

	reader, closeReader, err := wrapMaybeCompressedReadCloser(file, source, "")
	if err != nil {
		_ = file.Close()
		return nil, func() {}, err
	}

	return limitReadCloser(reader, maxBytes), closeReader, nil
}

func wrapMaybeCompressedReadCloser(body io.ReadCloser, source string, contentEncoding string) (io.ReadCloser, func(), error) {
	isCompressed := strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip") || strings.HasSuffix(strings.ToLower(source), ".gz")
	if !isCompressed {
		return body, func() { _ = body.Close() }, nil
	}

	gzipReader, err := gzip.NewReader(body)
	if err != nil {
		_ = body.Close()
		return nil, func() {}, err
	}

	return gzipReader, func() {
		_ = gzipReader.Close()
		_ = body.Close()
	}, nil
}

type maxBytesReadCloser struct {
	reader    io.ReadCloser
	limit     int64
	remaining int64
}

func limitReadCloser(reader io.ReadCloser, limit int64) io.ReadCloser {
	return &maxBytesReadCloser{reader: reader, limit: limit, remaining: limit}
}

func (r *maxBytesReadCloser) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var one [1]byte
		n, err := r.reader.Read(one[:])
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return 0, fmt.Errorf("feed source exceeds maximum size of %d bytes", r.limit)
		}
		return 0, nil
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func (r *maxBytesReadCloser) Close() error {
	return r.reader.Close()
}
