package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// mockTask is a test helper that implements the Task interface.
type mockTask struct {
	name    string
	runFunc func(ctx context.Context) error
	calls   atomic.Int64
}

func (t *mockTask) Name() string { return t.name }
func (t *mockTask) Run(ctx context.Context) error {
	t.calls.Add(1)
	if t.runFunc != nil {
		return t.runFunc(ctx)
	}
	return nil
}

func TestEngineStartStop(t *testing.T) {
	e := NewEngine()
	task := &mockTask{name: "test"}
	e.Register(task, time.Hour, time.Minute, true)

	e.Start()
	// Double start should be safe.
	e.Start()

	time.Sleep(50 * time.Millisecond)
	e.Stop()
	// Double stop should be safe.
	e.Stop()
}

func TestEngineStatus(t *testing.T) {
	e := NewEngine()
	e.Register(&mockTask{name: "a"}, time.Hour, time.Minute, true)
	e.Register(&mockTask{name: "b"}, time.Hour, time.Minute, false)

	status := e.Status()
	if !status.Enabled {
		t.Fatal("expected engine enabled")
	}
	if len(status.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(status.Tasks))
	}
	if status.Tasks[0].Name != "a" {
		t.Errorf("expected task name 'a', got %q", status.Tasks[0].Name)
	}
	if !status.Tasks[0].Enabled {
		t.Error("expected task 'a' enabled")
	}
	if status.Tasks[1].Enabled {
		t.Error("expected task 'b' disabled")
	}
}

func TestEngineManualTrigger(t *testing.T) {
	e := NewEngine()
	task := &mockTask{name: "trigger-me"}
	// Long interval so it won't fire on schedule.
	e.Register(task, 24*time.Hour, 5*time.Second, true)

	e.Start()
	defer e.Stop()

	// Wait for initial run to complete.
	time.Sleep(100 * time.Millisecond)
	initialCalls := task.calls.Load()

	// Manual trigger.
	found := e.Trigger("trigger-me")
	if !found {
		t.Fatal("expected trigger to find task")
	}

	time.Sleep(200 * time.Millisecond)

	if task.calls.Load() <= initialCalls {
		t.Error("expected task to run after trigger")
	}
}

func TestEngineTriggerUnknownTask(t *testing.T) {
	e := NewEngine()
	e.Register(&mockTask{name: "real"}, time.Hour, time.Minute, true)

	found := e.Trigger("nonexistent")
	if found {
		t.Error("expected trigger to return false for unknown task")
	}
}

func TestEngineDisabledTaskSkipped(t *testing.T) {
	e := NewEngine()
	task := &mockTask{name: "disabled"}
	e.Register(task, 100*time.Millisecond, time.Second, false) // disabled

	e.Start()
	time.Sleep(300 * time.Millisecond)
	e.Stop()

	if task.calls.Load() != 0 {
		t.Errorf("expected 0 runs for disabled task, got %d", task.calls.Load())
	}
}

func TestEngineTaskError(t *testing.T) {
	e := NewEngine()
	task := &mockTask{
		name: "fail",
		runFunc: func(ctx context.Context) error {
			return errors.New("boom")
		},
	}
	e.Register(task, 100*time.Millisecond, time.Second, true)

	e.Start()
	time.Sleep(200 * time.Millisecond)
	e.Stop()

	status := e.Status()
	for _, ts := range status.Tasks {
		if ts.Name == "fail" {
			if ts.State != "failed" {
				t.Errorf("expected state 'failed', got %q", ts.State)
			}
			if ts.LastError == "" {
				t.Error("expected last_error to be set")
			}
			if ts.ErrorCount == 0 {
				t.Error("expected error_count > 0")
			}
		}
	}
}

func TestEngineTaskTimeout(t *testing.T) {
	e := NewEngine()
	task := &mockTask{
		name: "slow",
		runFunc: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Second):
				return nil
			}
		},
	}
	// Very short timeout.
	e.Register(task, 100*time.Millisecond, 200*time.Millisecond, true)

	e.Start()
	time.Sleep(500 * time.Millisecond)
	e.Stop()

	if task.calls.Load() == 0 {
		t.Error("expected task to be called at least once")
	}

	status := e.Status()
	for _, ts := range status.Tasks {
		if ts.Name == "slow" {
			if ts.State != "failed" {
				t.Errorf("expected state 'failed', got %q", ts.State)
			}
		}
	}
}
