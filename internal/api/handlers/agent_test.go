package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"safe-zone/internal/agent"
)

type triggerTestTask struct {
	name string
}

func (t *triggerTestTask) Name() string {
	return t.name
}

func (t *triggerTestTask) Run(context.Context) error {
	return nil
}

func TestAgentTriggerHandlerPolicy(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		query      string
		engine     func(t *testing.T) *agent.Engine
		wantStatus int
		wantError  string
	}{
		{
			name:       "method not allowed",
			method:     http.MethodGet,
			query:      "task=audit",
			wantStatus: http.StatusMethodNotAllowed,
			wantError:  "method not allowed",
		},
		{
			name:       "engine disabled",
			method:     http.MethodPost,
			query:      "task=audit",
			wantStatus: http.StatusServiceUnavailable,
			wantError:  "agent engine not enabled",
		},
		{
			name:       "missing task",
			method:     http.MethodPost,
			wantStatus: http.StatusBadRequest,
			wantError:  "task query parameter is required",
			engine: func(t *testing.T) *agent.Engine {
				return agent.NewEngine()
			},
		},
		{
			name:       "unknown task",
			method:     http.MethodPost,
			query:      "task=missing",
			wantStatus: http.StatusNotFound,
			wantError:  "task not found: missing",
			engine: func(t *testing.T) *agent.Engine {
				return agent.NewEngine()
			},
		},
		{
			name:       "disabled task",
			method:     http.MethodPost,
			query:      "task=alert",
			wantStatus: http.StatusConflict,
			wantError:  "task is disabled: alert",
			engine: func(t *testing.T) *agent.Engine {
				engine := agent.NewEngine()
				engine.Register(&triggerTestTask{name: "alert"}, time.Hour, time.Minute, false)
				return engine
			},
		},
		{
			name:       "enabled task",
			method:     http.MethodPost,
			query:      "task=audit",
			wantStatus: http.StatusOK,
			engine: func(t *testing.T) *agent.Engine {
				engine := agent.NewEngine()
				engine.Register(&triggerTestTask{name: "audit"}, time.Hour, time.Minute, true)
				return engine
			},
		},
		{
			name:       "queue full",
			method:     http.MethodPost,
			query:      "task=audit",
			wantStatus: http.StatusTooManyRequests,
			wantError:  "agent trigger queue is full",
			engine: func(t *testing.T) *agent.Engine {
				engine := agent.NewEngine()
				engine.Register(&triggerTestTask{name: "audit"}, time.Hour, time.Minute, true)
				for i := 0; i < 100; i++ {
					result := engine.Trigger("audit")
					if result == agent.TriggerQueueFull {
						return engine
					}
					if result != agent.TriggerAccepted {
						t.Fatalf("fill trigger queue: got %q", result)
					}
				}
				t.Fatal("trigger queue did not report full")
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var engine *agent.Engine
			if tt.engine != nil {
				engine = tt.engine(t)
			}

			target := "/v1/agent/trigger"
			if tt.query != "" {
				target += "?" + tt.query
			}
			req := httptest.NewRequest(tt.method, target, nil)
			recorder := httptest.NewRecorder()

			AgentTriggerHandler(engine).ServeHTTP(recorder, req)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, recorder.Code)
			}

			var payload map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if tt.wantError != "" && payload["error"] != tt.wantError {
				t.Fatalf("expected error %q, got %#v", tt.wantError, payload)
			}
			if tt.wantError == "" {
				if payload["status"] != "triggered" || payload["task"] != "audit" {
					t.Fatalf("unexpected success payload: %#v", payload)
				}
			}
		})
	}
}
