package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/logjson"
	"safe-zone/internal/store"
)

// WhitelistSnapshotHandler lists the rollback copies of the allow list.
//
// The allow list is the primary safety valve, and a replacement import
// replaces it wholesale. The snapshots are what makes that undoable.
func (h *Handler) WhitelistSnapshotHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "whitelist snapshots require the sqlite store")
		return
	}

	snapshot, err := db.LatestWhitelistSnapshot(r.Context())
	if errors.Is(err, store.ErrWhitelistSnapshotNotFound) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"snapshot": nil})
		return
	}
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "failed to read the whitelist snapshot")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"snapshot": map[string]any{
			"id":          snapshot.ID,
			"created_at":  snapshot.CreatedAt,
			"source":      snapshot.Source,
			"entry_count": snapshot.EntryCount,
			"sha256":      snapshot.SHA256,
		},
	})
}

// WhitelistRollbackHandler restores the allow list from a rollback snapshot.
//
// The id query parameter selects a snapshot; without it the most recent one
// is used. The RAM index is rebuilt afterwards, because the durable set and
// the in-process index must agree or the resolver answers with a different
// allow list than the one on disk.
func (h *Handler) WhitelistRollbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "whitelist rollback requires the sqlite store")
		return
	}

	ctx := r.Context()

	var (
		snapshotID int64
		err        error
	)
	if raw := r.URL.Query().Get("id"); raw != "" {
		snapshotID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "id must be an integer")
			return
		}
	} else {
		snapshot, latestErr := db.LatestWhitelistSnapshot(ctx)
		if errors.Is(latestErr, store.ErrWhitelistSnapshotNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "no whitelist snapshot is available")
			return
		}
		if latestErr != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "failed to read the whitelist snapshot")
			return
		}
		snapshotID = snapshot.ID
	}

	restored, err := db.RestoreWhitelistSnapshot(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, store.ErrWhitelistSnapshotNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "whitelist snapshot not found")
			return
		}
		httputil.WriteError(w, http.StatusInternalServerError, "failed to restore the whitelist snapshot")
		return
	}

	if err := h.Risk.Whitelist().LoadFromDB(); err != nil {
		// The durable set is restored but the RAM index is stale, so the
		// resolver would answer with the pre-rollback allow list.
		logjson.Error("whitelist rollback did not rebuild the in-process index", map[string]any{
			"service":  "core-api",
			"snapshot": snapshotID,
			"error":    err.Error(),
		})
		httputil.WriteError(w, http.StatusInternalServerError, "the whitelist was restored but the index could not be rebuilt")
		return
	}

	logjson.Info("whitelist rolled back", map[string]any{
		"service":  "core-api",
		"snapshot": snapshotID,
		"entries":  restored,
	})

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"snapshot": snapshotID,
		"entries":  restored,
	})
}
