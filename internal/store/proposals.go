package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"safe-zone/internal/analysis"
)

// Agent proposal lifecycle states. Only pending proposals are actionable;
// approve/reject move them terminally, expiry is evaluated at read time
// against expires_at so no background sweeper is required.
const (
	AgentProposalPending  = "pending"
	AgentProposalApproved = "approved"
	AgentProposalRejected = "rejected"
	AgentProposalExpired  = "expired"
)

// DefaultAgentProposalTTL bounds how long an unreviewed proposal stays
// actionable. Expired proposals never auto-enforce; a reviewer can only
// act on pending, unexpired rows.
const DefaultAgentProposalTTL = 7 * 24 * time.Hour

// AgentProposal is a reviewable enforcement suggestion created by an
// agent task. It carries its own evidence and authority (actor/scope) so
// reviewers never have to reconstruct why the agent suggested it.
type AgentProposal struct {
	ID         int64    `json:"id"`
	TaskName   string   `json:"task"`
	Domain     string   `json:"domain"`
	Action     string   `json:"action"`
	Score      int      `json:"score"`
	Confidence float64  `json:"confidence"`
	Reasons    []string `json:"reasons"`
	Evidence   string   `json:"evidence"`
	Actor      string   `json:"actor"`
	Scope      string   `json:"scope"`
	Status     string   `json:"status"`
	ExpiresAt  string   `json:"expires_at"`
	Reviewer   string   `json:"reviewer,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
}

// CreateAgentProposal records a pending proposal. An identical pending
// proposal (same domain and action) is refreshed instead of duplicated so
// the review queue stays triageable across audit cycles.
func (d *DB) CreateAgentProposal(ctx context.Context, p AgentProposal) (AgentProposal, error) {
	if !d.Enabled() {
		return AgentProposal{}, ErrDisabled
	}
	p.Domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(p.Domain)), ".")
	if p.Domain == "" {
		return AgentProposal{}, fmt.Errorf("proposal domain cannot be empty")
	}
	if p.Action != "allow" && p.Action != "block" {
		return AgentProposal{}, fmt.Errorf("invalid action %q: must be 'allow' or 'block'", p.Action)
	}
	if p.TaskName == "" {
		p.TaskName = "audit"
	}
	if p.Actor == "" {
		p.Actor = "agent:" + p.TaskName
	}
	if p.Scope == "" {
		p.Scope = "exact"
	}
	expiresAt := strings.TrimSpace(p.ExpiresAt)
	if expiresAt == "" {
		expiresAt = time.Now().Add(DefaultAgentProposalTTL).UTC().Format(time.RFC3339Nano)
	}
	reasonsJSON, err := json.Marshal(append([]string(nil), p.Reasons...))
	if err != nil {
		return AgentProposal{}, fmt.Errorf("encode proposal reasons: %w", err)
	}

	// The lookup, the refresh and the insert are one transaction. They used to be
	// three separate statements, so two concurrent audit cycles (or an agent
	// task racing an API call) could both observe "no pending proposal" and both
	// insert — and the table has no uniqueness to stop them, so the documented
	// "an identical pending proposal is refreshed instead of duplicated" contract
	// was only true when nothing else was running.
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentProposal{}, fmt.Errorf("begin proposal transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existing int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM agent_proposals WHERE domain = ? AND action = ? AND status = ? LIMIT 1`,
		p.Domain, p.Action, AgentProposalPending).Scan(&existing)
	if err != nil && err != sql.ErrNoRows {
		return AgentProposal{}, fmt.Errorf("lookup pending proposal: %w", err)
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `
			UPDATE agent_proposals
			SET score = ?, confidence = ?, reasons = ?, evidence = ?,
			    expires_at = ?, updated_at = datetime('now')
			WHERE id = ?`,
			p.Score, p.Confidence, string(reasonsJSON), p.Evidence, expiresAt, existing); err != nil {
			return AgentProposal{}, fmt.Errorf("refresh pending proposal: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return AgentProposal{}, fmt.Errorf("commit proposal refresh: %w", err)
		}
		return d.GetAgentProposal(ctx, existing)
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO agent_proposals
			(task_name, domain, action, score, confidence, reasons, evidence, actor, scope, status, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.TaskName, p.Domain, p.Action, p.Score, p.Confidence, string(reasonsJSON),
		p.Evidence, p.Actor, p.Scope, AgentProposalPending, expiresAt)
	if err != nil {
		return AgentProposal{}, fmt.Errorf("insert proposal: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return AgentProposal{}, fmt.Errorf("proposal insert id: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AgentProposal{}, fmt.Errorf("commit proposal insert: %w", err)
	}
	return d.GetAgentProposal(ctx, id)
}

// GetAgentProposal returns a single proposal by id.
func (d *DB) GetAgentProposal(ctx context.Context, id int64) (AgentProposal, error) {
	var p AgentProposal
	if !d.Enabled() {
		return p, ErrDisabled
	}
	var reasonsJSON string
	err := d.db.QueryRowContext(ctx, `
		SELECT id, task_name, domain, action, score, confidence, reasons, evidence,
		       actor, scope, status, expires_at,
		       COALESCE(reviewer, ''), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM agent_proposals WHERE id = ?`, id).
		Scan(&p.ID, &p.TaskName, &p.Domain, &p.Action, &p.Score, &p.Confidence,
			&reasonsJSON, &p.Evidence, &p.Actor, &p.Scope, &p.Status,
			&p.ExpiresAt, &p.Reviewer, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return AgentProposal{}, err
	}
	if err := json.Unmarshal([]byte(reasonsJSON), &p.Reasons); err != nil {
		return AgentProposal{}, fmt.Errorf("decode proposal reasons: %w", err)
	}
	return p, nil
}

// ListAgentProposals returns proposals filtered by status (empty means
// all), newest first. Pending results exclude expired rows.
func (d *DB) ListAgentProposals(ctx context.Context, status string, limit int) ([]AgentProposal, error) {
	if !d.Enabled() {
		// An empty list here would render as "no proposals exist" in the UI,
		// which is indistinguishable from a real queue that happens to be
		// empty. Callers get ErrDisabled so they can tell the two apart.
		return nil, ErrDisabled
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `
		SELECT id, task_name, domain, action, score, confidence, reasons, evidence,
		       actor, scope, status, expires_at,
		       COALESCE(reviewer, ''), COALESCE(created_at, ''), COALESCE(updated_at, '')
		FROM agent_proposals`
	var args []any
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "":
	case AgentProposalPending:
		query += ` WHERE status = ? AND datetime(expires_at) > datetime('now')`
		args = append(args, AgentProposalPending)
	case AgentProposalApproved, AgentProposalRejected:
		query += ` WHERE status = ?`
		args = append(args, strings.ToLower(strings.TrimSpace(status)))
	case AgentProposalExpired:
		query += ` WHERE (status = ? OR (status = ? AND datetime(expires_at) <= datetime('now')))`
		args = append(args, AgentProposalExpired, AgentProposalPending)
	default:
		return nil, fmt.Errorf("unknown proposal status %q", status)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list proposals: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AgentProposal
	for rows.Next() {
		var p AgentProposal
		var reasonsJSON string
		if err := rows.Scan(&p.ID, &p.TaskName, &p.Domain, &p.Action, &p.Score,
			&p.Confidence, &reasonsJSON, &p.Evidence, &p.Actor, &p.Scope,
			&p.Status, &p.ExpiresAt, &p.Reviewer, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan proposal: %w", err)
		}
		if err := json.Unmarshal([]byte(reasonsJSON), &p.Reasons); err != nil {
			return nil, fmt.Errorf("decode proposal reasons: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ErrAgentProposalConflict reports that a proposal was transitioned by someone
// else between the caller's read and its write. The caller can re-read and
// report the real state instead of being handed the winner's row.
var ErrAgentProposalConflict = errors.New("agent proposal was reviewed concurrently")

// ErrProposalNotReviewable reports that a proposal cannot be reviewed in its
// current state: it does not exist, it has already been decided, or it has
// expired.
//
// This exists so an HTTP layer can tell "this proposal is not reviewable" from
// "the database failed". Those used to be the same opaque error, so a store
// failure was answered with 409 Conflict and the store's own message in the body,
// telling the operator their proposal was in the wrong state when the query had
// never run.
//
// The wrapped detail names the proposal's own status, which is the caller's own
// resource and safe to echo; only the sentinel decides the status code.
var ErrProposalNotReviewable = errors.New("agent proposal is not reviewable")

// ReviewAgentProposal transitions a pending, unexpired proposal to
// approved or rejected. Expired rows report AgentProposalExpired without
// mutating, so reviewers can distinguish stale evidence from rejection.
//
// The read, the expiry check and the write are not one operation, so the
// UPDATE carries `AND status = 'pending'` and the affected row count is
// checked. Without that check a caller that asked to reject a proposal that
// another reviewer approved a moment earlier got no error at all: its UPDATE
// matched zero rows, and the GetAgentProposal that followed returned the
// winner's row — so a rejection was reported back to the operator as a success
// carrying someone else's approval.
func (d *DB) ReviewAgentProposal(ctx context.Context, id int64, approve bool, reviewer, reason string) (AgentProposal, error) {
	p, err := d.GetAgentProposal(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AgentProposal{}, fmt.Errorf("%w: proposal %d does not exist", ErrProposalNotReviewable, id)
		}
		return AgentProposal{}, err
	}
	if p.Status != AgentProposalPending {
		return AgentProposal{}, fmt.Errorf("%w: proposal %d is %s, only pending proposals are reviewable",
			ErrProposalNotReviewable, id, p.Status)
	}
	if expired, err := time.Parse(time.RFC3339Nano, p.ExpiresAt); err != nil || !time.Now().Before(expired) {
		return AgentProposal{}, fmt.Errorf("%w: proposal %d is expired", ErrProposalNotReviewable, id)
	}
	next := AgentProposalRejected
	if approve {
		next = AgentProposalApproved
	}
	result, err := d.db.ExecContext(ctx, `
		UPDATE agent_proposals
		SET status = ?, reviewer = ?, review_reason = ?, reviewed_at = datetime('now'),
		    updated_at = datetime('now')
		WHERE id = ? AND status = ?`,
		next, strings.TrimSpace(reviewer), strings.TrimSpace(reason), id, AgentProposalPending)
	if err != nil {
		return AgentProposal{}, fmt.Errorf("review proposal: %w", err)
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
		return AgentProposal{}, fmt.Errorf("review proposal rows affected: %w", rowsErr)
	} else if affected == 0 {
		// Someone else transitioned it between the read above and this write.
		// Report the conflict instead of returning their row as our result.
		return AgentProposal{}, fmt.Errorf("%w: proposal %d", ErrAgentProposalConflict, id)
	}
	return d.GetAgentProposal(ctx, id)
}

// HasGroupOverrideForDomain reports whether any client group holds an
// override for the domain or one of its parents. Agent tasks use it to
// avoid proposing against explicit group policy they cannot see.
func (d *DB) HasGroupOverrideForDomain(ctx context.Context, domain string) (bool, error) {
	if !d.Enabled() {
		// This answer gates whether the agent is allowed to propose a block at
		// all. Returning false here would mean "no override exists, go ahead",
		// so a disabled store would actively invite new proposals rather than
		// stop them. Fail closed instead.
		return false, ErrDisabled
	}
	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	// Stop at the registrable label (eTLD+1): a row keyed on a public suffix
	// would report "already overridden" for every domain in that namespace,
	// and this answer gates whether the agent proposes a block at all.
	// UpsertGroupOverride refuses such rows; the floor covers older databases.
	parts := strings.Split(domain, ".")
	floor := analysis.RegistrableWalkFloor(domain)
	for i := 0; i < len(parts) && i <= floor; i++ {
		candidate := strings.Join(parts[i:], ".")
		var id int64
		err := d.db.QueryRowContext(ctx,
			`SELECT id FROM group_overrides WHERE domain = ? LIMIT 1`, candidate).Scan(&id)
		if err == nil {
			return true, nil
		}
		if err != sql.ErrNoRows {
			return false, fmt.Errorf("query group override candidate %s: %w", candidate, err)
		}
	}
	return false, nil
}
