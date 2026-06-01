package agent

import (
	"context"
	"sync"
	"time"

	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
)

// Task is the interface every agent task must implement.
type Task interface {
	// Name returns a unique identifier for this task.
	Name() string
	// Run executes the task. The context carries a deadline.
	Run(ctx context.Context) error
}

// TaskStatus tracks the runtime state of a registered task.
type TaskStatus struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	State      string `json:"state"`      // "idle", "running", "failed"
	Interval   string `json:"interval"`   // human-readable
	LastRun    string `json:"last_run"`   // RFC3339 or ""
	NextRun    string `json:"next_run"`   // RFC3339 or ""
	LastError  string `json:"last_error"` // empty if last run succeeded
	RunCount   int64  `json:"run_count"`
	ErrorCount int64  `json:"error_count"`
}

// EngineStatus is the JSON shape for GET /v1/agent/status.
type EngineStatus struct {
	Enabled bool         `json:"enabled"`
	Tasks   []TaskStatus `json:"tasks"`
}

type registeredTask struct {
	task     Task
	interval time.Duration
	timeout  time.Duration
	enabled  bool
	lastRun  time.Time
	lastErr  string
	runCount int64
	errCount int64
	state    string // "idle", "running", "failed"
}

// Engine is the central scheduler that manages and runs Tasks.
type Engine struct {
	mu        sync.Mutex
	tasks     []*registeredTask
	triggerCh chan string
	done      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	started   bool
	stopped   bool
}

const tickInterval = 30 * time.Second

// NewEngine creates an Engine with no tasks registered.
func NewEngine() *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		triggerCh: make(chan string, 8),
		done:      make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Register adds a task to the engine. Must be called before Start.
func (e *Engine) Register(task Task, interval, timeout time.Duration, enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.tasks = append(e.tasks, &registeredTask{
		task:     task,
		interval: interval,
		timeout:  timeout,
		enabled:  enabled,
		state:    "idle",
	})
}

// Start launches the scheduler goroutine.
func (e *Engine) Start() {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()

	logjson.Info("agent engine started", map[string]any{
		"service": "core-api",
		"tasks":   len(e.tasks),
	})
	e.wg.Add(1)
	go e.loop()
}

// Stop signals the scheduler to exit and waits for it to finish.
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.started || e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	e.mu.Unlock()

	e.cancel()

	close(e.done)
	e.wg.Wait()
	logjson.Info("agent engine stopped", map[string]any{"service": "core-api"})
}

// Trigger requests immediate execution of the named task.
// Returns true if the task exists, false otherwise.
func (e *Engine) Trigger(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rt := range e.tasks {
		if rt.task.Name() == name {
			select {
			case e.triggerCh <- name:
			default:
				// channel full, trigger will be processed on next tick
			}
			return true
		}
	}
	return false
}

// Status returns a snapshot of the engine and task states.
func (e *Engine) Status() EngineStatus {
	e.mu.Lock()
	defer e.mu.Unlock()

	tasks := make([]TaskStatus, len(e.tasks))
	for i, rt := range e.tasks {
		ts := TaskStatus{
			Name:       rt.task.Name(),
			Enabled:    rt.enabled,
			State:      rt.state,
			Interval:   rt.interval.String(),
			LastError:  rt.lastErr,
			RunCount:   rt.runCount,
			ErrorCount: rt.errCount,
		}
		if !rt.lastRun.IsZero() {
			ts.LastRun = rt.lastRun.UTC().Format(time.RFC3339)
			ts.NextRun = rt.lastRun.Add(rt.interval).UTC().Format(time.RFC3339)
		}
		tasks[i] = ts
	}

	return EngineStatus{
		Enabled: true,
		Tasks:   tasks,
	}
}

func (e *Engine) loop() {
	defer e.wg.Done()

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	// Run an initial check immediately on start.
	e.runDueTasks()

	for {
		select {
		case <-e.done:
			return
		case name := <-e.triggerCh:
			e.runTaskByName(name)
		case <-ticker.C:
			e.runDueTasks()
		}
	}
}

func (e *Engine) runDueTasks() {
	e.mu.Lock()
	snapshot := make([]*registeredTask, len(e.tasks))
	copy(snapshot, e.tasks)
	e.mu.Unlock()

	for _, rt := range snapshot {
		select {
		case <-e.done:
			return
		default:
		}

		if !rt.enabled {
			continue
		}
		if !rt.lastRun.IsZero() && time.Since(rt.lastRun) < rt.interval {
			continue
		}
		e.executeTask(rt)
	}
}

func (e *Engine) runTaskByName(name string) {
	e.mu.Lock()
	var target *registeredTask
	for _, rt := range e.tasks {
		if rt.task.Name() == name {
			target = rt
			break
		}
	}
	e.mu.Unlock()

	if target == nil {
		return
	}
	e.executeTask(target)
}

func (e *Engine) executeTask(rt *registeredTask) {
	e.mu.Lock()
	rt.state = "running"
	e.mu.Unlock()

	baseCtx := correlation.WithRunID(e.ctx, correlation.NewID("agent-"+rt.task.Name()))
	ctx, cancel := context.WithTimeout(baseCtx, rt.timeout)
	defer cancel()

	start := time.Now()
	err := rt.task.Run(ctx)
	elapsed := time.Since(start)

	e.mu.Lock()
	rt.lastRun = time.Now()
	rt.runCount++
	if err != nil {
		rt.state = "failed"
		rt.lastErr = err.Error()
		rt.errCount++
		logjson.Error("agent task failed", correlation.Fields(ctx, map[string]any{
			"service":     "core-api",
			"task":        rt.task.Name(),
			"duration_ms": elapsed.Milliseconds(),
			"error":       err.Error(),
		}))
	} else {
		rt.state = "idle"
		rt.lastErr = ""
		logjson.Info("agent task completed", correlation.Fields(ctx, map[string]any{
			"service":     "core-api",
			"task":        rt.task.Name(),
			"duration_ms": elapsed.Milliseconds(),
		}))
	}
	e.mu.Unlock()
}
