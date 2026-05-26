package correlation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
)

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	runIDKey     contextKey = "run_id"
)

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return withValue(ctx, requestIDKey, requestID)
}

func RequestID(ctx context.Context) string {
	return value(ctx, requestIDKey)
}

func WithRunID(ctx context.Context, runID string) context.Context {
	return withValue(ctx, runIDKey, runID)
}

func RunID(ctx context.Context) string {
	return value(ctx, runIDKey)
}

func Fields(ctx context.Context, fields map[string]any) map[string]any {
	if fields == nil {
		fields = map[string]any{}
	}

	out := make(map[string]any, len(fields)+2)
	for key, value := range fields {
		out[key] = value
	}

	if requestID := RequestID(ctx); requestID != "" {
		out["request_id"] = requestID
	}
	if runID := RunID(ctx); runID != "" {
		out["run_id"] = runID
	}

	return out
}

func NewID(prefix string) string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		prefix = strings.Trim(SanitizeID(prefix), "-._/")
		if prefix == "" {
			return "safe-zone-fallback-id"
		}
		return prefix + "-fallback-id"
	}

	encoded := hex.EncodeToString(buf)
	prefix = strings.Trim(SanitizeID(prefix), "-._/")
	if prefix == "" {
		return encoded
	}

	return prefix + "-" + encoded
}

func SanitizeID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 120 {
		value = value[:120]
	}

	var out strings.Builder
	out.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			out.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			out.WriteRune(r)
		case r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-', r == '_', r == '.', r == '/':
			out.WriteRune(r)
		}
	}

	return out.String()
}

func withValue(ctx context.Context, key contextKey, value string) context.Context {
	value = SanitizeID(value)
	if value == "" {
		if ctx == nil {
			return context.Background()
		}
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, key, value)
}

func value(ctx context.Context, key contextKey) string {
	if ctx == nil {
		return ""
	}

	value, _ := ctx.Value(key).(string)
	return value
}
