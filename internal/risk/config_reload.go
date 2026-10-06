package risk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/store"
)

func configDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func (s *Service) shouldRunConfigReloadSubscriber() bool {
	if s == nil {
		return false
	}
	if !s.configReloadOn || s.configReloadChan == "" || s.subscribeReload == nil {
		return false
	}
	if s.redis == nil || !s.redis.Enabled() {
		return false
	}
	if s.store == nil || !s.store.Enabled() {
		return false
	}
	return true
}

func (s *Service) shouldRunConfigReloadReconciler() bool {
	if s == nil {
		return false
	}
	if !s.configReloadOn {
		return false
	}
	if s.store == nil || !s.store.Enabled() {
		return false
	}
	return configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval) > 0
}

func (s *Service) runConfigReloadSubscriber() {
	defer s.configReloadWG.Done()

	backoff := configDuration(s.reloadBackoffMin, analysisConfigReloadBackoffMin)
	maxBackoff := configDuration(s.reloadBackoffMax, analysisConfigReloadBackoffMax)
	if maxBackoff < backoff {
		maxBackoff = backoff
	}

	for {
		if s.lifecycleCtx.Err() != nil {
			return
		}

		messages, closeSub, err := s.subscribeReload(s.lifecycleCtx, s.configReloadChan)
		if err != nil {
			if s.lifecycleCtx.Err() != nil {
				return
			}
			logjson.Warn("analysis config reload subscribe failed; retrying", map[string]any{
				"service":   "risk",
				"channel":   s.configReloadChan,
				"backoff":   backoff.String(),
				"error":     err.Error(),
				"node_role": s.nodeRole,
			})
			if !waitForContextOrTimeout(s.lifecycleCtx, backoff) {
				return
			}
			backoff = nextConfigReloadBackoff(backoff, maxBackoff)
			continue
		}

		backoff = configDuration(s.reloadBackoffMin, analysisConfigReloadBackoffMin)
		err = s.consumeConfigReloadMessages(messages)
		if closeSub != nil {
			_ = closeSub()
		}
		if s.lifecycleCtx.Err() != nil {
			return
		}

		logFields := map[string]any{
			"service":   "risk",
			"channel":   s.configReloadChan,
			"backoff":   backoff.String(),
			"node_role": s.nodeRole,
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			logFields["error"] = err.Error()
		}
		logjson.Warn("analysis config reload subscriber disconnected; retrying", logFields)

		if !waitForContextOrTimeout(s.lifecycleCtx, backoff) {
			return
		}
		backoff = nextConfigReloadBackoff(backoff, maxBackoff)
	}
}

func (s *Service) consumeConfigReloadMessages(messages <-chan string) error {
	for {
		select {
		case <-s.lifecycleCtx.Done():
			return s.lifecycleCtx.Err()
		case raw, ok := <-messages:
			if !ok {
				return errors.New("subscription closed")
			}
			s.handleConfigReloadMessage(raw)
		}
	}
}

func (s *Service) runConfigReloadReconciler() {
	defer s.configReloadWG.Done()

	interval := configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval)
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.lifecycleCtx.Done():
			return
		case <-ticker.C:
			s.reconcileAnalysisConfig()
		}
	}
}

func (s *Service) handleConfigReloadMessage(raw string) {
	if s == nil {
		return
	}

	var event analysisConfigReloadEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		logjson.Warn("analysis config reload event decode failed", map[string]any{
			"service": "risk",
			"channel": s.configReloadChan,
			"error":   err.Error(),
		})
		return
	}
	if event.Type != analysisConfigReloadEventType || event.Revision == "" {
		return
	}
	currentRevision := s.currentConfigRevision()
	if event.Revision == currentRevision {
		logjson.Info("analysis config reload ignored", map[string]any{
			"service":          "risk",
			"channel":          s.configReloadChan,
			"event_revision":   event.Revision,
			"current_revision": currentRevision,
			"event_source":     event.Source,
			"event_time":       event.UpdatedAt,
			"ignore_reason":    "duplicate_or_self_loop",
			"node_role":        s.nodeRole,
		})
		return
	}

	oldRevision, newRevision, applied, err := s.reloadAnalysisConfigFromStore(configReloadSourcePubSub)
	if err != nil {
		logjson.Warn("analysis config reload from store failed", map[string]any{
			"service":        "risk",
			"channel":        s.configReloadChan,
			"event_revision": event.Revision,
			"event_source":   event.Source,
			"error":          err.Error(),
		})
		return
	}
	if !applied {
		return
	}

	logjson.Info("analysis config reload applied", map[string]any{
		"service":       "risk",
		"channel":       s.configReloadChan,
		"old_revision":  oldRevision,
		"new_revision":  newRevision,
		"event_source":  event.Source,
		"event_time":    event.UpdatedAt,
		"reload_source": configReloadSourcePubSub,
		"node_role":     s.nodeRole,
	})
}

func (s *Service) reconcileAnalysisConfig() {
	if s == nil {
		return
	}

	oldRevision, newRevision, applied, err := s.reloadAnalysisConfigFromStore(configReloadSourceReconcile)
	if err != nil {
		logjson.Warn("analysis config reconciliation failed", map[string]any{
			"service":       "risk",
			"poll_interval": configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval).String(),
			"error":         err.Error(),
			"node_role":     s.nodeRole,
		})
		return
	}
	if !applied {
		return
	}

	logjson.Info("analysis config reconciliation applied", map[string]any{
		"service":       "risk",
		"old_revision":  oldRevision,
		"new_revision":  newRevision,
		"poll_interval": configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval).String(),
		"reload_source": configReloadSourceReconcile,
		"node_role":     s.nodeRole,
	})
}

func (s *Service) reloadAnalysisConfigFromStore(source string) (string, string, bool, error) {
	if s == nil || s.store == nil || !s.store.Enabled() {
		return "", "", false, store.ErrDisabled
	}

	storedConfig, err := s.store.GetAnalysisConfig(context.Background())
	if err != nil {
		return "", "", false, err
	}
	if storedConfig == nil {
		currentRevision := s.currentConfigRevision()
		return currentRevision, currentRevision, false, nil
	}

	cfg := storedConfig.Clone()
	nextRevision := analysisConfigRevision(cfg)
	currentRevision := s.currentConfigRevision()
	if nextRevision == currentRevision {
		return currentRevision, nextRevision, false, nil
	}

	appliedRevision := s.applyAnalysisConfig(cfg, source)
	return currentRevision, appliedRevision, true, nil
}

func nextConfigReloadBackoff(current, max time.Duration) time.Duration {
	if current <= 0 {
		return max
	}
	next := current * 2
	if next < current || next > max {
		return max
	}
	return next
}

func waitForContextOrTimeout(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func analysisConfigRevision(cfg config.AnalysisConfig) string {
	encoded, _ := json.Marshal(cfg.Clone())
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum[:8])
}

func (s *Service) applyAnalysisConfigLocked(cfg config.AnalysisConfig) {
	s.analysisConfig = cfg
	s.configRevision = analysisConfigRevision(cfg)
	s.analyzer = analysis.NewAnalyzerWithBrandStore(cfg, s.brandStore)
}

func (s *Service) applyAnalysisConfig(cfg config.AnalysisConfig, source string) string {
	if s == nil {
		return ""
	}
	cfg = cfg.Clone()
	appliedAt := time.Now().UTC()

	s.analyzerMu.Lock()
	defer s.analyzerMu.Unlock()

	s.applyAnalysisConfigLocked(cfg)
	s.lastReloadSource = source
	s.lastReloadTime = appliedAt
	return s.configRevision
}

func (s *Service) currentConfigRevision() string {
	s.analyzerMu.RLock()
	defer s.analyzerMu.RUnlock()
	return s.configRevision
}

func (s *Service) currentConfigReloadState() (string, string, time.Time) {
	if s == nil {
		return "", "", time.Time{}
	}
	s.analyzerMu.RLock()
	defer s.analyzerMu.RUnlock()
	return s.configRevision, s.lastReloadSource, s.lastReloadTime
}

func (s *Service) GetAnalysisConfig() config.AnalysisConfig {
	if s == nil {
		return config.DefaultAnalysisConfig()
	}
	s.analyzerMu.RLock()
	defer s.analyzerMu.RUnlock()
	return s.analysisConfig.Clone()
}

func (s *Service) AnalysisConfigReloadStatus() AnalysisConfigReloadStatus {
	if s == nil {
		return AnalysisConfigReloadStatus{}
	}

	revision, source, reloadedAt := s.currentConfigReloadState()
	status := AnalysisConfigReloadStatus{
		Enabled:          s.configReloadOn,
		Channel:          s.configReloadChan,
		PollInterval:     configDuration(s.configReloadPoll, defaultAnalysisConfigReloadPollInterval).String(),
		NodeRole:         s.nodeRole,
		Revision:         revision,
		LastReloadSource: source,
		RedisConfigured:  s.redis != nil && s.redis.Enabled(),
		StoreConfigured:  s.store != nil && s.store.Enabled(),
		SubscriberActive: s.shouldRunConfigReloadSubscriber(),
		ReconcilerActive: s.shouldRunConfigReloadReconciler(),
	}
	if !reloadedAt.IsZero() {
		status.LastReloadAt = reloadedAt.UTC().Format(time.RFC3339Nano)
	}
	return status
}

func (s *Service) publishAnalysisConfigReloadEvent(ctx context.Context, revision string) {
	if s == nil || revision == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	channel := s.configReloadChan
	if channel == "" {
		channel = defaultAnalysisConfigReloadChannel
	}
	eventSource := configReloadSourceLocalWrite
	if s.nodeRole != "" {
		eventSource = s.nodeRole
	}

	event := analysisConfigReloadEvent{
		Type:      analysisConfigReloadEventType,
		Revision:  revision,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:    eventSource,
	}
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.PublishJSON(redisCtx, channel, event)
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		logjson.Warn("analysis config reload publish failed", correlation.Fields(ctx, map[string]any{
			"service":  "risk",
			"channel":  channel,
			"revision": revision,
			"error":    err.Error(),
		}))
		return
	}
	if err == nil {
		logjson.Info("analysis config reload published", correlation.Fields(ctx, map[string]any{
			"service":      "risk",
			"channel":      channel,
			"revision":     revision,
			"event_source": eventSource,
			"node_role":    s.nodeRole,
		}))
	}
}

func (s *Service) UpdateAnalysisConfig(ctx context.Context, cfg config.AnalysisConfig) error {
	if s == nil {
		return fmt.Errorf("risk service not configured")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cfg = cfg.Clone()
	if s.store == nil || !s.store.Enabled() {
		return store.ErrDisabled
	}
	if err := s.store.SetAnalysisConfig(ctx, cfg); err != nil {
		return err
	}
	revision := s.applyAnalysisConfig(cfg, configReloadSourceLocalWrite)
	s.publishAnalysisConfigReloadEvent(ctx, revision)
	return nil
}

func (s *Service) ResetAnalysisConfig(ctx context.Context) (config.AnalysisConfig, error) {
	defaults := config.DefaultAnalysisConfig()
	if err := s.UpdateAnalysisConfig(ctx, defaults); err != nil {
		return config.AnalysisConfig{}, err
	}
	return defaults.Clone(), nil
}
