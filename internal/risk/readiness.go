package risk

import (
	"context"
	"fmt"

	"safe-zone/internal/serve"
)

// ReadinessChecks returns the dependency checks for a service that uses this
// decision engine.
//
// SQLite is mandatory: the operator's overrides, the allow list, the
// telemetry and the block reports all live there, and the decision pipeline
// reads the overrides on every request. Without it an operator-set block
// silently stops applying, so the service is not ready.
//
// Redis is optional. A Redis outage takes the threat feed and the result
// cache away, but the service still answers with the layers that do not need
// Redis. Marking it mandatory would make an orchestrator restart a service
// that is working, and the restart would not bring Redis back.
//
// The allow list is optional for the same reason, but it is reported so an
// operator sees that the allow list is not in effect.
func (s *Service) ReadinessChecks() []serve.ReadinessCheck {
	if s == nil {
		return nil
	}

	return []serve.ReadinessCheck{
		{
			Name:      "sqlite",
			Mandatory: true,
			Check:     func(ctx context.Context) error { return s.checkStore(ctx) },
		},
		{
			Name:      "redis",
			Mandatory: false,
			Check:     func(ctx context.Context) error { return s.checkRedis(ctx) },
		},
		{
			Name:      "whitelist",
			Mandatory: false,
			Check: func(context.Context) error {
				if loadErr := s.Whitelist().LoadError(); loadErr != nil {
					return fmt.Errorf("allow list is not in effect: %w", loadErr)
				}
				return nil
			},
		},
	}
}

// checkStore verifies that the durable store is reachable.
func (s *Service) checkStore(ctx context.Context) error {
	db := s.StoreDB()
	if db == nil {
		// A disabled store is a valid local configuration. In production the
		// service refuses to start without it.
		return nil
	}
	return db.Ping(ctx)
}

// checkRedis verifies that the cache and feed store is reachable.
func (s *Service) checkRedis(ctx context.Context) error {
	redis := s.RedisCache()
	if redis == nil || !redis.Enabled() {
		// Redis is optional in the single-node profile.
		return nil
	}
	return redis.Ping(ctx)
}
