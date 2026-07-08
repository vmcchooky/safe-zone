package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"safe-zone/internal/api/httputil"
	"safe-zone/internal/auth"
	"safe-zone/internal/store"
)

const (
	guestAccessConfigKey   = "dashboard_guest_access"
	guestReadOnlyMessage   = "Khách không được quyền thay đổi hoặc áp dụng các chính sách mới vào hệ thống, nếu muốn hãy liên hệ với quản trị viên của Safe Zone DNS tại contact@quorix.io.vn."
	minGuestPasswordLength = 10
)

var errGuestAccessRevoked = errors.New("guest access disabled or deleted")

type guestAccessConfig struct {
	Enabled      bool   `json:"enabled"`
	PasswordHash string `json:"password_hash,omitempty"`
}

func (cfg guestAccessConfig) Exists() bool {
	return strings.TrimSpace(cfg.PasswordHash) != ""
}

func (h *Handler) guestAccessStore() (*store.DB, error) {
	if h == nil || h.Risk == nil {
		return nil, fmt.Errorf("risk service not configured")
	}
	db := h.Risk.StoreDB()
	if db == nil || !db.Enabled() {
		return nil, fmt.Errorf("database not configured")
	}
	return db, nil
}

func (h *Handler) loadGuestAccessConfig(ctx context.Context) (guestAccessConfig, error) {
	db, err := h.guestAccessStore()
	if err != nil {
		return guestAccessConfig{}, err
	}
	raw, err := db.GetSystemConfig(ctx, guestAccessConfigKey)
	if err != nil {
		return guestAccessConfig{}, fmt.Errorf("load guest access config: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return guestAccessConfig{}, nil
	}

	var cfg guestAccessConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return guestAccessConfig{}, fmt.Errorf("decode guest access config: %w", err)
	}
	cfg.PasswordHash = strings.TrimSpace(cfg.PasswordHash)
	return cfg, nil
}

func (h *Handler) saveGuestAccessConfig(ctx context.Context, cfg guestAccessConfig) error {
	db, err := h.guestAccessStore()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode guest access config: %w", err)
	}
	return db.SetSystemConfig(ctx, guestAccessConfigKey, string(encoded))
}

func (h *Handler) clearGuestAccessConfig(ctx context.Context) error {
	db, err := h.guestAccessStore()
	if err != nil {
		return err
	}
	return db.SetSystemConfig(ctx, guestAccessConfigKey, "")
}

func validateGuestAccessPassword(password string) error {
	if len(password) < minGuestPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minGuestPasswordLength)
	}
	return nil
}

func (h *Handler) ensureGuestSessionActive(ctx context.Context, claims auth.SessionClaims) error {
	if auth.NormalizeRole(claims.Username, claims.Role) != auth.RoleGuest {
		return nil
	}

	cfg, err := h.loadGuestAccessConfig(ctx)
	if err != nil {
		return err
	}
	if !cfg.Exists() || !cfg.Enabled {
		return errGuestAccessRevoked
	}
	return nil
}

func guestAccessStatus(cfg guestAccessConfig) guestAccessStatusResponse {
	return guestAccessStatusResponse{
		Username: auth.RoleGuest,
		Exists:   cfg.Exists(),
		Enabled:  cfg.Enabled && cfg.Exists(),
	}
}

func (h *Handler) AuthSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	identity, ok := authIdentityFromRequest(r)
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, authSessionFromIdentity(identity))
}

func (h *Handler) GuestAccessHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := h.loadGuestAccessConfig(r.Context())
		if err != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, guestAccessStatus(cfg))

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()

		var req guestAccessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		password := strings.TrimSpace(req.Password)
		if password == "" {
			httputil.WriteError(w, http.StatusBadRequest, "password is required")
			return
		}
		if err := validateGuestAccessPassword(password); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}

		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		cfg := guestAccessConfig{
			Enabled:      enabled,
			PasswordHash: hash,
		}
		if err := h.saveGuestAccessConfig(r.Context(), cfg); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, guestAccessStatus(cfg))

	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()

		cfg, err := h.loadGuestAccessConfig(r.Context())
		if err != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if !cfg.Exists() {
			httputil.WriteError(w, http.StatusNotFound, "guest account does not exist")
			return
		}

		var req guestAccessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		if req.Enabled != nil {
			cfg.Enabled = *req.Enabled
		}
		if password := strings.TrimSpace(req.Password); password != "" {
			if err := validateGuestAccessPassword(password); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err.Error())
				return
			}
			hash, err := auth.HashPassword(password)
			if err != nil {
				httputil.WriteError(w, http.StatusInternalServerError, err.Error())
				return
			}
			cfg.PasswordHash = hash
		}

		if err := h.saveGuestAccessConfig(r.Context(), cfg); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, guestAccessStatus(cfg))

	case http.MethodDelete:
		if err := h.clearGuestAccessConfig(r.Context()); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		httputil.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) RequireAdminFunc(next http.HandlerFunc) http.HandlerFunc {
	return h.RequireAuthFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := authIdentityFromRequest(r)
		if !ok {
			httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !identity.isAdmin() {
			writeGuestReadOnlyError(w)
			return
		}
		next(w, r)
	})
}

func (h *Handler) RequireAdminForMutationFunc(next http.HandlerFunc) http.HandlerFunc {
	return h.RequireAuthFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := authIdentityFromRequest(r)
		if !ok {
			httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !identity.isAdmin() && isStateChangingMethod(r.Method) {
			writeGuestReadOnlyError(w)
			return
		}
		next(w, r)
	})
}
