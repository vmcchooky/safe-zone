package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
)

const defaultBrandCacheKey = "safe-zone:analysis:trusted-brands"
const defaultBrandCacheTTL = 5 * time.Minute

// BrandStore wraps SQLite with process memory and Redis caching for hot-path analysis reads.
type BrandStore struct {
	db           *DB
	redis        *cache.Redis
	redisTimeout time.Duration
	cacheKey     string
	cacheTTL     time.Duration

	mu        sync.RWMutex
	brands    []analysis.Brand
	expiresAt time.Time
}

func NewBrandStore(db *DB, redis *cache.Redis, redisTimeout, cacheTTL time.Duration) *BrandStore {
	if cacheTTL <= 0 {
		cacheTTL = defaultBrandCacheTTL
	}
	if redisTimeout <= 0 {
		redisTimeout = 250 * time.Millisecond
	}
	return &BrandStore{
		db:           db,
		redis:        redis,
		redisTimeout: redisTimeout,
		cacheKey:     defaultBrandCacheKey,
		cacheTTL:     cacheTTL,
	}
}

func (s *BrandStore) ListBrands(ctx context.Context) ([]analysis.Brand, error) {
	if s == nil {
		return analysis.DefaultTrustedBrands(), nil
	}
	if brands, ok := s.memoryBrands(); ok {
		return brands, nil
	}
	if brands, ok := s.redisBrands(ctx); ok {
		s.setMemoryBrands(brands)
		return brands, nil
	}
	if s.db == nil || !s.db.Enabled() {
		brands := analysis.DefaultTrustedBrands()
		s.setMemoryBrands(brands)
		return brands, nil
	}
	brands, err := s.db.ListBrands(ctx)
	if err != nil {
		return nil, err
	}
	if len(brands) == 0 {
		brands = analysis.DefaultTrustedBrands()
	}
	s.setMemoryBrands(brands)
	s.setRedisBrands(ctx, brands)
	return cloneAnalysisBrands(brands), nil
}

func (s *BrandStore) GetBrand(ctx context.Context, id int64) (analysis.Brand, error) {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return analysis.Brand{}, fmt.Errorf("sqlite store disabled")
	}
	return s.db.GetBrand(ctx, id)
}

func (s *BrandStore) CreateBrand(ctx context.Context, brand analysis.Brand) (analysis.Brand, error) {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return analysis.Brand{}, fmt.Errorf("sqlite store disabled")
	}
	created, err := s.db.CreateBrand(ctx, brand)
	if err != nil {
		return analysis.Brand{}, err
	}
	s.invalidate(ctx)
	return created, nil
}

func (s *BrandStore) UpdateBrand(ctx context.Context, id int64, brand analysis.Brand) (analysis.Brand, error) {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return analysis.Brand{}, fmt.Errorf("sqlite store disabled")
	}
	updated, err := s.db.UpdateBrand(ctx, id, brand)
	if err != nil {
		return analysis.Brand{}, err
	}
	s.invalidate(ctx)
	return updated, nil
}

func (s *BrandStore) DeleteBrand(ctx context.Context, id int64) error {
	if s == nil || s.db == nil || !s.db.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	if err := s.db.DeleteBrand(ctx, id); err != nil {
		return err
	}
	s.invalidate(ctx)
	return nil
}

func (s *BrandStore) memoryBrands() ([]analysis.Brand, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.brands) == 0 || time.Now().After(s.expiresAt) {
		return nil, false
	}
	return cloneAnalysisBrands(s.brands), true
}

func (s *BrandStore) setMemoryBrands(brands []analysis.Brand) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.brands = cloneAnalysisBrands(brands)
	s.expiresAt = time.Now().Add(s.cacheTTL)
}

func (s *BrandStore) redisBrands(parent context.Context) ([]analysis.Brand, bool) {
	if s.redis == nil || !s.redis.Enabled() {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(parent, s.redisTimeout)
	defer cancel()
	var brands []analysis.Brand
	found, err := s.redis.GetJSON(ctx, s.cacheKey, &brands)
	if err != nil || !found || len(brands) == 0 {
		return nil, false
	}
	return cloneAnalysisBrands(brands), true
}

func (s *BrandStore) setRedisBrands(parent context.Context, brands []analysis.Brand) {
	if s.redis == nil || !s.redis.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(parent, s.redisTimeout)
	defer cancel()
	_ = s.redis.SetJSON(ctx, s.cacheKey, brands, s.cacheTTL)
}

func (s *BrandStore) invalidate(parent context.Context) {
	s.mu.Lock()
	s.brands = nil
	s.expiresAt = time.Time{}
	s.mu.Unlock()
	if s.redis == nil || !s.redis.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(parent, s.redisTimeout)
	defer cancel()
	_ = s.redis.Delete(ctx, s.cacheKey)
}

func (d *DB) SeedDefaultBrands() error {
	if !d.Enabled() {
		return nil
	}
	for _, brand := range analysis.DefaultTrustedBrands() {
		if _, err := d.CreateBrand(context.Background(), brand); err != nil && !isUniqueConstraint(err) {
			return err
		}
	}
	return nil
}

func (d *DB) ListBrands(_ context.Context) ([]analysis.Brand, error) {
	if !d.Enabled() {
		return nil, nil
	}
	rows, err := d.db.Query(`
		SELECT id, name, official_domain, COALESCE(alt_domains, '[]'), created_at, updated_at
		FROM trusted_brands ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list brands: %w", err)
	}
	defer rows.Close()

	var brands []analysis.Brand
	for rows.Next() {
		brand, err := scanBrand(rows)
		if err != nil {
			return nil, err
		}
		brands = append(brands, brand)
	}
	return brands, rows.Err()
}

func (d *DB) GetBrand(_ context.Context, id int64) (analysis.Brand, error) {
	if !d.Enabled() {
		return analysis.Brand{}, fmt.Errorf("sqlite store disabled")
	}
	row := d.db.QueryRow(`
		SELECT id, name, official_domain, COALESCE(alt_domains, '[]'), created_at, updated_at
		FROM trusted_brands WHERE id = ?`, id)
	brand, err := scanBrand(row)
	if errors.Is(err, sql.ErrNoRows) {
		return analysis.Brand{}, fmt.Errorf("brand not found: id %d", id)
	}
	return brand, err
}

func (d *DB) CreateBrand(_ context.Context, brand analysis.Brand) (analysis.Brand, error) {
	if !d.Enabled() {
		return analysis.Brand{}, fmt.Errorf("sqlite store disabled")
	}
	if err := validateBrand(brand); err != nil {
		return analysis.Brand{}, err
	}
	brand = normalizeBrandForStore(brand)
	altJSON, _ := json.Marshal(brand.AltDomains)
	res, err := d.db.Exec(`
		INSERT INTO trusted_brands (name, official_domain, alt_domains, updated_at)
		VALUES (?, ?, ?, datetime('now'))`,
		brand.Name, brand.OfficialDomain, string(altJSON))
	if err != nil {
		return analysis.Brand{}, fmt.Errorf("create brand %q: %w", brand.Name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return analysis.Brand{}, err
	}
	return d.GetBrand(context.Background(), id)
}

func (d *DB) UpdateBrand(_ context.Context, id int64, brand analysis.Brand) (analysis.Brand, error) {
	if !d.Enabled() {
		return analysis.Brand{}, fmt.Errorf("sqlite store disabled")
	}
	if err := validateBrand(brand); err != nil {
		return analysis.Brand{}, err
	}
	brand = normalizeBrandForStore(brand)
	altJSON, _ := json.Marshal(brand.AltDomains)
	res, err := d.db.Exec(`
		UPDATE trusted_brands
		SET name = ?, official_domain = ?, alt_domains = ?, updated_at = datetime('now')
		WHERE id = ?`,
		brand.Name, brand.OfficialDomain, string(altJSON), id)
	if err != nil {
		return analysis.Brand{}, fmt.Errorf("update brand id %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return analysis.Brand{}, fmt.Errorf("brand not found: id %d", id)
	}
	return d.GetBrand(context.Background(), id)
}

func (d *DB) DeleteBrand(_ context.Context, id int64) error {
	if !d.Enabled() {
		return fmt.Errorf("sqlite store disabled")
	}
	res, err := d.db.Exec("DELETE FROM trusted_brands WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete brand id %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("brand not found: id %d", id)
	}
	return nil
}

type brandScanner interface {
	Scan(dest ...any) error
}

func scanBrand(scanner brandScanner) (analysis.Brand, error) {
	var brand analysis.Brand
	var altJSON string
	if err := scanner.Scan(&brand.ID, &brand.Name, &brand.OfficialDomain, &altJSON, &brand.CreatedAt, &brand.UpdatedAt); err != nil {
		return analysis.Brand{}, err
	}
	_ = json.Unmarshal([]byte(altJSON), &brand.AltDomains)
	return brand, nil
}

func validateBrand(brand analysis.Brand) error {
	brand = normalizeBrandForStore(brand)
	if brand.Name == "" {
		return fmt.Errorf("brand name is required")
	}
	if brand.OfficialDomain == "" {
		return fmt.Errorf("official_domain is required")
	}
	if _, err := analysis.NormalizeDomain(brand.OfficialDomain); err != nil {
		return fmt.Errorf("invalid official_domain: %w", err)
	}
	for _, alt := range brand.AltDomains {
		if _, err := analysis.NormalizeDomain(alt); err != nil {
			return fmt.Errorf("invalid alt_domain %q: %w", alt, err)
		}
	}
	return nil
}

func normalizeBrandForStore(brand analysis.Brand) analysis.Brand {
	brand.Name = strings.ToLower(strings.TrimSpace(brand.Name))
	brand.OfficialDomain = strings.ToLower(strings.TrimSpace(brand.OfficialDomain))
	alts := make([]string, 0, len(brand.AltDomains))
	seen := make(map[string]struct{}, len(brand.AltDomains))
	for _, alt := range brand.AltDomains {
		alt = strings.ToLower(strings.TrimSpace(alt))
		if alt == "" {
			continue
		}
		if _, ok := seen[alt]; ok {
			continue
		}
		seen[alt] = struct{}{}
		alts = append(alts, alt)
	}
	brand.AltDomains = alts
	return brand
}

func cloneAnalysisBrands(brands []analysis.Brand) []analysis.Brand {
	if len(brands) == 0 {
		return nil
	}
	cloned := make([]analysis.Brand, len(brands))
	for i, brand := range brands {
		brand.AltDomains = append([]string(nil), brand.AltDomains...)
		cloned[i] = brand
	}
	return cloned
}

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "constraint")
}
