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

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("condition not met before timeout")
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

func TestEngineDoesNotBlockOtherTasks(t *testing.T) {
	e := NewEngine()

	slowStarted := make(chan struct{})
	slowRelease := make(chan struct{})
	fastRan := make(chan struct{}, 1)

	e.Register(&mockTask{
		name: "slow",
		runFunc: func(ctx context.Context) error {
			close(slowStarted)
			select {
			case <-slowRelease:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}, time.Hour, time.Second, true)

	e.Register(&mockTask{
		name: "fast",
		runFunc: func(ctx context.Context) error {
			select {
			case fastRan <- struct{}{}:
			default:
			}
			return nil
		},
	}, time.Hour, time.Second, true)

	e.Start()

	waitForCondition(t, time.Second, func() bool {
		select {
		case <-slowStarted:
			return true
		default:
			return false
		}
	})

	waitForCondition(t, time.Second, func() bool {
		select {
		case <-fastRan:
			return true
		default:
			return false
		}
	})

	close(slowRelease)
	e.Stop()
}

func TestEngineSkipsDuplicateRunsWhileTaskIsRunning(t *testing.T) {
	e := NewEngine()

	release := make(chan struct{})
	task := &mockTask{
		name: "single-flight",
		runFunc: func(ctx context.Context) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	e.Register(task, time.Hour, time.Second, true)

	e.Start()

	waitForCondition(t, time.Second, func() bool {
		return task.calls.Load() == 1
	})

	e.runTaskByName("single-flight")
	time.Sleep(50 * time.Millisecond)

	if got := task.calls.Load(); got != 1 {
		t.Fatalf("expected duplicate run to be skipped, got %d calls", got)
	}

	close(release)
	e.Stop()
}

func TestEngineRecoversFromTaskPanic(t *testing.T) {
	e := NewEngine()

	panicTask := &mockTask{
		name: "panic-task",
		runFunc: func(ctx context.Context) error {
			panic("kaboom")
		},
	}
	healthyTask := &mockTask{name: "healthy"}

	e.Register(panicTask, time.Hour, time.Second, true)
	e.Register(healthyTask, time.Hour, time.Second, true)

	e.Start()
	defer e.Stop()

	waitForCondition(t, time.Second, func() bool {
		return panicTask.calls.Load() > 0 && healthyTask.calls.Load() > 0
	})

	status := e.Status()
	for _, ts := range status.Tasks {
		if ts.Name != "panic-task" {
			continue
		}
		if ts.State != "failed" {
			t.Fatalf("expected panic task state 'failed', got %q", ts.State)
		}
		if ts.LastError == "" {
			t.Fatal("expected panic task to keep last_error")
		}
		if ts.ErrorCount == 0 {
			t.Fatal("expected panic task error_count to increment")
		}
		return
	}

	t.Fatal("panic task not found in engine status")
}
