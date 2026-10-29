package handlers

import (
	"context"

	"safe-zone/internal/logjson"
	"safe-zone/internal/store"
)

// publishClientMappingsReload notifies dns-resolver that the durable
// client_mappings revision changed, so it rebuilds its in-process CIDR index
// now instead of waiting for the poll reconciler. The write already committed;
// a publish failure is logged and never turned into an error response.
func publishClientMappingsReload(ctx context.Context, h *Handler, db *store.DB) {
	revision, err := db.GetClientMappingsRevision(ctx)
	if err != nil {
		logjson.Warn("client mappings reload revision read failed; the poll reconciler will apply it", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
		return
	}
	if _, err := h.Risk.PublishClientMappingsReload(ctx, revision); err != nil {
		logjson.Warn("client mappings reload could not be published; the poll reconciler will apply it", map[string]any{
			"service":  "core-api",
			"revision": revision,
			"error":    err.Error(),
		})
	}
}
