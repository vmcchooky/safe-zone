package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A late review is rejected by the pre-check, so the conflict path is only
// reachable in a genuine interleaving: both reviewers read the row while it is
// still pending, and one UPDATE wins.
//
// The store is opened with a single connection, so goroutines sharing one handle
// barely interleave and the race would stay hidden. Two handles on the same
// file is both the reliable reproduction and the more faithful model: this is
// what two processes, or a service and a CLI, actually do.
func newTwoHandleDB(t *testing.T) (*DB, *DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "race.db")
	first, err := New(path, 30)
	if err != nil {
		t.Fatalf("first store: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	second, err := New(path, 30)
	if err != nil {
		t.Fatalf("second store: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	return first, second
}

func seedRaceProposal(t *testing.T, db *DB) int64 {
	t.Helper()
	created, err := db.CreateAgentProposal(context.Background(), AgentProposal{
		TaskName: "audit", Domain: "phish.example", Action: "block",
		Actor: "agent:audit", Score: 90, Confidence: 0.9,
	})
	if err != nil {
		t.Fatal(err)
	}
	return created.ID
}

// The core regression: a reviewer that lost the update must be told, not handed
// the winner's row. The UPDATE already carried "AND status = 'pending'", but the
// affected row count was discarded, so the loser saw no error and the
// GetAgentProposal that followed returned the winner's state — a request to
// reject a proposal was answered with someone else's approval.
func TestReviewAgentProposalReportsALostUpdate(t *testing.T) {
	writer, other := newTwoHandleDB(t)
	id := seedRaceProposal(t, writer)
	ctx := context.Background()

	const rounds = 40
	conflicts, wins := 0, 0
	for range rounds {
		// Reset to pending so each round is a fresh race.
		if _, err := writer.db.ExecContext(ctx,
			`UPDATE agent_proposals SET status = 'pending', reviewer = NULL, reviewed_at = NULL WHERE id = ?`, id); err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for i, db := range []*DB{writer, other} {
			wg.Add(1)
			go func(index int, handle *DB) {
				defer wg.Done()
				<-start
				_, errs[index] = handle.ReviewAgentProposal(ctx, id, index == 0, "reviewer", "racing")
			}(i, db)
		}
		close(start)
		wg.Wait()

		successes := 0
		for _, err := range errs {
			switch {
			case err == nil:
				successes++
				wins++
			case errors.Is(err, ErrAgentProposalConflict):
				conflicts++
			case strings.Contains(err.Error(), "only pending proposals are reviewable"):
				// The pre-check caught it: the read happened after the write.
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if successes > 1 {
			t.Fatalf("%d reviewers reported success on one proposal; at most one may", successes)
		}
	}

	if conflicts == 0 {
		t.Fatalf("no round produced ErrAgentProposalConflict in %d attempts, so the interleaving was never reached and this test proves nothing", rounds)
	}
	if wins < rounds {
		t.Fatalf("only %d of %d rounds produced a successful review; the fixture is not exercising the race", wins, rounds)
	}
	t.Logf("wins=%d conflicts=%d", wins, conflicts)
}

// The refresh-or-insert contract has to hold under concurrency. It is now one
// transaction; before that, two audit cycles could both see "no pending row" and
// both insert, and nothing in the schema stopped them.
func TestConcurrentCreatesDoNotDuplicatePendingProposals(t *testing.T) {
	writer, other := newTwoHandleDB(t)
	ctx := context.Background()

	const writers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range writers {
		wg.Add(1)
		go func(index int, db *DB) {
			defer wg.Done()
			<-start
			if _, err := db.CreateAgentProposal(ctx, AgentProposal{
				TaskName: "audit", Domain: "dup.example", Action: "block",
				Actor: "agent:audit", Score: 80 + index, Confidence: 0.8,
			}); err != nil {
				t.Errorf("create: %v", err)
			}
		}(i, func() *DB {
			if i%2 == 0 {
				return writer
			}
			return other
		}())
	}
	close(start)
	wg.Wait()

	pending, err := writer.ListAgentProposals(ctx, AgentProposalPending, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("%d pending proposals for the same domain and action, want 1", len(pending))
	}
}

// A single-threaded create must still refresh rather than duplicate.
func TestCreateRefreshesAnExistingPendingProposal(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	first, err := db.CreateAgentProposal(ctx, AgentProposal{
		TaskName: "audit", Domain: "refresh.example", Action: "block",
		Actor: "agent:audit", Score: 50, Confidence: 0.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.CreateAgentProposal(ctx, AgentProposal{
		TaskName: "audit", Domain: "refresh.example", Action: "block",
		Actor: "agent:audit", Score: 95, Confidence: 0.95,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("second create made a new row (%d) instead of refreshing %d", second.ID, first.ID)
	}
	if second.Score != 95 {
		t.Fatalf("score = %d, want the refreshed 95", second.Score)
	}
}

// A sequential second review is caught by the pre-check and must still say so,
// rather than reaching the UPDATE.
func TestReviewRejectsAnAlreadyReviewedProposal(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	id := seedRaceProposal(t, db)

	if _, err := db.ReviewAgentProposal(ctx, id, true, "alice", "ok"); err != nil {
		t.Fatalf("first review: %v", err)
	}
	_, err := db.ReviewAgentProposal(ctx, id, false, "bob", "no")
	if err == nil {
		t.Fatal("a second review must be refused")
	}
	if errors.Is(err, ErrAgentProposalConflict) {
		t.Fatal("a sequential second review is caught by the pre-check, not the conflict path")
	}

	final, err := db.GetAgentProposal(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if final.Reviewer != "alice" {
		t.Fatalf("reviewer = %q, want alice", final.Reviewer)
	}
}
