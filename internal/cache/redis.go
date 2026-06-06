package cache

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
)

var ErrDisabled = errors.New("redis cache disabled")

type Redis struct {
	client *redis.Client
}

func NewRedis(addr, password string, db int) *Redis {
	if addr == "" {
		return &Redis{}
	}

	return &Redis{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       db,
		}),
	}
}

func (r *Redis) Enabled() bool {
	return r != nil && r.client != nil
}

func (r *Redis) Close() error {
	if !r.Enabled() {
		return nil
	}

	return r.client.Close()
}

func (r *Redis) Ping(ctx context.Context) error {
	if !r.Enabled() {
		return ErrDisabled
	}

	return r.client.Ping(ctx).Err()
}

func (r *Redis) GetJSON(ctx context.Context, key string, target any) (bool, error) {
	if !r.Enabled() {
		return false, ErrDisabled
	}

	value, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal([]byte(value), target); err != nil {
		return false, err
	}

	return true, nil
}

func (r *Redis) SetJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if !r.Enabled() {
		return ErrDisabled
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, key, encoded, ttl).Err()
}

func (r *Redis) PublishJSON(ctx context.Context, channel string, value any) error {
	if !r.Enabled() {
		return ErrDisabled
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Publish(ctx, channel, encoded).Err()
}

func (r *Redis) Subscribe(ctx context.Context, channel string) (<-chan string, func() error, error) {
	if !r.Enabled() {
		return nil, nil, ErrDisabled
	}

	pubsub := r.client.Subscribe(ctx, channel)
	if _, err := pubsub.Receive(ctx); err != nil {
		_ = pubsub.Close()
		return nil, nil, err
	}

	source := pubsub.Channel()
	messages := make(chan string, 100)
	done := make(chan struct{})

	var (
		closeOnce sync.Once
		closeErr  error
	)
	closeSub := func() error {
		closeOnce.Do(func() {
			close(done)
			closeErr = pubsub.Close()
		})
		return closeErr
	}

	go func() {
		defer close(messages)

		for {
			select {
			case <-done:
				return
			case msg, ok := <-source:
				if !ok {
					return
				}

				select {
				case <-done:
					return
				case messages <- msg.Payload:
				}
			}
		}
	}()

	return messages, closeSub, nil
}

func (r *Redis) GetString(ctx context.Context, key string) (string, error) {
	if !r.Enabled() {
		return "", ErrDisabled
	}

	value, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return value, nil
}

func (r *Redis) SetString(ctx context.Context, key string, value string, ttl time.Duration) error {
	if !r.Enabled() {
		return ErrDisabled
	}

	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *Redis) Increment(ctx context.Context, key string) (int64, error) {
	if !r.Enabled() {
		return 0, ErrDisabled
	}

	return r.client.Incr(ctx, key).Result()
}

func (r *Redis) GetInt64(ctx context.Context, key string) (int64, error) {
	if !r.Enabled() {
		return 0, ErrDisabled
	}

	value, err := r.GetString(ctx, key)
	if err != nil || value == "" {
		return 0, err
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func (r *Redis) Delete(ctx context.Context, key string) error {
	if !r.Enabled() {
		return ErrDisabled
	}

	return r.client.Del(ctx, key).Err()
}

func (r *Redis) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if !r.Enabled() {
		return ErrDisabled
	}
	return r.client.Expire(ctx, key, ttl).Err()
}

func (r *Redis) Rename(ctx context.Context, fromKey, toKey string) error {
	if !r.Enabled() {
		return ErrDisabled
	}

	return r.client.Rename(ctx, fromKey, toKey).Err()
}

func (r *Redis) SetAdd(ctx context.Context, key string, members ...string) (int64, error) {
	if !r.Enabled() {
		return 0, ErrDisabled
	}
	if len(members) == 0 {
		return 0, nil
	}

	return r.client.SAdd(ctx, key, members).Result()
}

func (r *Redis) SetIsMember(ctx context.Context, key, member string) (bool, error) {
	if !r.Enabled() {
		return false, ErrDisabled
	}

	return r.client.SIsMember(ctx, key, member).Result()
}

func (r *Redis) ZAdd(ctx context.Context, key string, members ...redis.Z) (int64, error) {
	if !r.Enabled() {
		return 0, ErrDisabled
	}
	if len(members) == 0 {
		return 0, nil
	}

	return r.client.ZAdd(ctx, key, members...).Result()
}

func (r *Redis) ZScore(ctx context.Context, key, member string) (float64, error) {
	if !r.Enabled() {
		return 0, ErrDisabled
	}

	return r.client.ZScore(ctx, key, member).Result()
}

func (r *Redis) ZRemRangeByScore(ctx context.Context, key string, min, max string) (int64, error) {
	if !r.Enabled() {
		return 0, ErrDisabled
	}

	return r.client.ZRemRangeByScore(ctx, key, min, max).Result()
}

func (r *Redis) PushJSON(ctx context.Context, key string, value any, maxLen int64) error {
	if !r.Enabled() {
		return ErrDisabled
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}

	pipe := r.client.TxPipeline()
	pipe.LPush(ctx, key, encoded)
	if maxLen > 0 {
		pipe.LTrim(ctx, key, 0, maxLen-1)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (r *Redis) ListJSON(ctx context.Context, key string, start, stop int64, appendItem func([]byte) error) error {
	if !r.Enabled() {
		return ErrDisabled
	}

	values, err := r.client.LRange(ctx, key, start, stop).Result()
	if err != nil {
		return err
	}

	for _, value := range values {
		if err := appendItem([]byte(value)); err != nil {
			logjson.Warn("skip malformed cached item", correlation.Fields(ctx, map[string]any{
				"key":   key,
				"error": err.Error(),
			}))
		}
	}

	return nil
}
