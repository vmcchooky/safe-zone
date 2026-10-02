package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/store"
)

type proposalReviewRequest struct {
	ID       int64  `json:"id"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// AgentProposalsHandler lists agent enforcement proposals and records
// human approve/reject decisions. Reads are available to authenticated
// users; decisions require admin (wired in the router). Approving a block
// proposal creates a normal operator-owned override through the existing
// override path, so it stays revocable like any manual block.
func (h *Handler) AgentProposalsHandler(w http.ResponseWriter, r *http.Request) {
	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		httputil.WriteError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		status := r.URL.Query().Get("status")
		proposals, err := db.ListAgentProposals(r.Context(), status, 100)
		if err != nil {
			// Was a 400 with the store's own message in the body. A store failure
			// is not a client mistake, and an empty proposal queue reported as
			// "bad request" told the operator their status filter was wrong.
			httputil.WriteStoreError(w, r, err, "failed to list proposals")
			return
		}
		if proposals == nil {
			proposals = []store.AgentProposal{}
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"items": proposals})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer func() { _ = r.Body.Close() }()
		var req proposalReviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		decision := strings.ToLower(strings.TrimSpace(req.Decision))
		if req.ID <= 0 || (decision != "approve" && decision != "reject") {
			httputil.WriteError(w, http.StatusBadRequest, "id and decision approve|reject are required")
			return
		}
		reviewer := ""
		if identity, ok := authIdentityFromRequest(r); ok {
			reviewer = identity.Username
		}
		proposal, err := db.ReviewAgentProposal(r.Context(), req.ID, decision == "approve", reviewer, req.Reason)
		if err != nil {
			// Two distinct outcomes that used to share one branch. A proposal that
			// is decided, expired, or absent is a conflict the operator can act on,
			// and its detail names the proposal's own status, so it is echoed.
			// Everything else came out of the store and is not the caller's to see.
			switch {
			case errors.Is(err, store.ErrProposalNotReviewable), errors.Is(err, store.ErrAgentProposalConflict):
				httputil.WriteError(w, http.StatusConflict, err.Error())
			default:
				httputil.WriteStoreError(w, r, err, "failed to review proposal")
			}
			return
		}
		if decision == "approve" {
			reason := "approved agent proposal #" + strconv.FormatInt(proposal.ID, 10)
			if strings.TrimSpace(req.Reason) != "" {
				reason += ": " + strings.TrimSpace(req.Reason)
			}
			if reviewer != "" {
				reason += " (reviewer: " + reviewer + ")"
			}
			if err := h.Risk.UpsertOverride(r.Context(), proposal.Domain, proposal.Action, reason); err != nil {
				httputil.WriteStoreError(w, r, err, "failed to apply the reviewed override")
				return
			}
			_ = db.RecordAgentEvent(r.Context(), "audit", "proposal_approved", proposal.Domain,
				`{"proposal_id":`+strconv.FormatInt(proposal.ID, 10)+`}`)
		} else {
			_ = db.RecordAgentEvent(r.Context(), "audit", "proposal_rejected", proposal.Domain,
				`{"proposal_id":`+strconv.FormatInt(proposal.ID, 10)+`}`)
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": proposal.Status, "id": proposal.ID})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
