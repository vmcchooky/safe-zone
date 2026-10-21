package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/logjson"
	"safe-zone/internal/serve"
	"safe-zone/internal/store"
)

// whitelistRollbackReasonMinRunes keeps a rollback attributable. The allow
// list is the primary safety valve and a rollback replaces it wholesale, so
// "why" is not optional paperwork; it is the only thing that distinguishes a
// recovery action from an unreviewed change when the audit log is read later.
const whitelistRollbackReasonMinRunes = 8

// whitelistRollbackDetails is the durable audit payload for a rollback. It is
// also the source of the last_rollback block in the snapshot listing, so the
// two views cannot disagree.
type whitelistRollbackDetails struct {
	SnapshotID    int64  `json:"snapshot_id"`
	Entries       int    `json:"entries"`
	Actor         string `json:"actor"`
	Reason        string `json:"reason"`
	Revision      int64  `json:"revision"`
	CorrelationID string `json:"correlation_id"`
}

type whitelistRollbackRequest struct {
	Reason string `json:"reason"`
}

// WhitelistSnapshotHandler lists the rollback copies of the allow list and the
// last durable rollback.
//
// The allow list is the primary safety valve, and a replacement import
// replaces it wholesale. The snapshots are what makes that undoable; listing
// all of them is what lets an operator choose one instead of guessing an id.
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

	snapshots, err := db.ListWhitelistSnapshots(r.Context())
	if err != nil {
		httputil.WriteStoreError(w, r, err, "failed to list the whitelist snapshots")
		return
	}

	items := make([]map[string]any, 0, len(snapshots))
	for _, snapshot := range snapshots {
		items = append(items, map[string]any{
			"id":          snapshot.ID,
			"created_at":  snapshot.CreatedAt,
			"source":      snapshot.Source,
			"entry_count": snapshot.EntryCount,
			"sha256":      snapshot.SHA256,
		})
	}

	event, err := db.LatestWhitelistRollback(r.Context())
	if err != nil {
		httputil.WriteStoreError(w, r, err, "failed to read the last whitelist rollback")
		return
	}
	var lastRollback any
	if event != nil {
		lastRollback = whitelistRollbackView(*event)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"snapshots":     items,
		"last_rollback": lastRollback,
	})
}

// whitelistRollbackView exposes the audit record without hiding a malformed
// payload: the fields an operator needs are parsed when possible, and the raw
// details are kept so a damaged record is still diagnosable.
func whitelistRollbackView(event store.AgentEvent) map[string]any {
	view := map[string]any{
		"audit_id":   event.ID,
		"created_at": event.CreatedAt,
		"details":    event.Details,
	}
	var details whitelistRollbackDetails
	if err := json.Unmarshal([]byte(event.Details), &details); err != nil {
		return view
	}
	view["snapshot_id"] = details.SnapshotID
	view["entries"] = details.Entries
	view["actor"] = details.Actor
	view["reason"] = details.Reason
	view["revision"] = details.Revision
	view["correlation_id"] = details.CorrelationID
	return view
}

// WhitelistRollbackHandler restores the allow list from a rollback snapshot.
//
// The id query parameter selects a snapshot; without it the most recent one
// is used. A reason is required and recorded with the actor and the request
// correlation id, because this endpoint replaces the whole allow list.
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

	reason, err := decodeWhitelistRollbackReason(w, r)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	var snapshotID int64
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
		switch {
		case errors.Is(err, store.ErrWhitelistSnapshotNotFound):
			httputil.WriteError(w, http.StatusNotFound, "whitelist snapshot not found")
		case errors.Is(err, store.ErrWhitelistSnapshotEmpty), errors.Is(err, store.ErrWhitelistSnapshotCorrupt):
			// The row is present but not safe to apply. That is a store
			// integrity failure, not a missing id.
			logjson.Error("whitelist snapshot failed verification", map[string]any{
				"service":  "core-api",
				"snapshot": snapshotID,
				"error":    err.Error(),
			})
			httputil.WriteError(w, http.StatusInternalServerError, "whitelist snapshot failed verification")
		default:
			httputil.WriteError(w, http.StatusInternalServerError, "failed to restore the whitelist snapshot")
		}
		return
	}

	if err := h.Risk.Whitelist().LoadFromDB(); err != nil {
		// The durable set is restored but this process's RAM index is stale.
		logjson.Error("whitelist rollback did not rebuild the in-process index", map[string]any{
			"service":  "core-api",
			"snapshot": snapshotID,
			"error":    err.Error(),
		})
		httputil.WriteError(w, http.StatusInternalServerError, "the whitelist was restored but the index could not be rebuilt")
		return
	}

	// core-api has the restored set; dns-resolver holds its own RAM copy.
	// Publish the new revision so it reloads now. When Redis is off the
	// publisher reports false and the 30s store reconciliation applies it;
	// either way the response says what happened instead of implying that
	// every process is already serving the rollback.
	revision := h.Risk.Whitelist().Revision()
	published, publishErr := h.Risk.PublishWhitelistReload(ctx, revision)
	if publishErr != nil {
		logjson.Warn("whitelist rollback could not publish the reload event; the poll reconciler will apply it", map[string]any{
			"service":  "core-api",
			"snapshot": snapshotID,
			"revision": revision,
			"error":    publishErr.Error(),
		})
	}

	actor := ""
	if identity, ok := authIdentityFromRequest(r); ok {
		actor = identity.Username
	}
	details := whitelistRollbackDetails{
		SnapshotID:    snapshotID,
		Entries:       restored,
		Actor:         actor,
		Reason:        reason,
		Revision:      revision,
		CorrelationID: serve.RequestID(ctx),
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		// Marshaling a struct of strings and integers cannot fail in practice;
		// if it does, the rollback already happened and the log is the only
		// record left.
		logjson.Error("whitelist rollback audit encode failed", map[string]any{
			"service":  "core-api",
			"snapshot": snapshotID,
			"error":    err.Error(),
		})
		encoded = []byte(`{}`)
	}

	// The audit write must survive the client disconnecting: the restore is
	// already durable, so a cancelled request context must not erase the only
	// record of who did it and why.
	auditErr := db.RecordAgentEvent(context.WithoutCancel(ctx), "whitelist", "rollback", "", string(encoded))
	if auditErr != nil {
		logjson.Error("whitelist rollback audit write failed", map[string]any{
			"service":  "core-api",
			"snapshot": snapshotID,
			"actor":    actor,
			"error":    auditErr.Error(),
		})
	}

	logjson.Info("whitelist rolled back", map[string]any{
		"service":        "core-api",
		"snapshot":       snapshotID,
		"entries":        restored,
		"revision":       revision,
		"published":      published,
		"actor":          actor,
		"correlation_id": serve.RequestID(ctx),
		"audit_recorded": auditErr == nil,
	})

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"snapshot":       snapshotID,
		"entries":        restored,
		"revision":       revision,
		"published":      published,
		"audit_recorded": auditErr == nil,
	})
}

// decodeWhitelistRollbackReason reads the JSON body and enforces a minimum
// reason length. A missing body is the same as an empty reason, not a parse
// error, so the error message can say what is actually required.
func decodeWhitelistRollbackReason(w http.ResponseWriter, r *http.Request) (string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer func() { _ = r.Body.Close() }()

	var req whitelistRollbackRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("invalid JSON body")
	}
	reason := strings.TrimSpace(req.Reason)
	if utf8.RuneCountInString(reason) < whitelistRollbackReasonMinRunes {
		return "", errors.New("reason is required and must be at least 8 characters")
	}
	return reason, nil
}
