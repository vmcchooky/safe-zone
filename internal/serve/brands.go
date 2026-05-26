package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"safe-zone/internal/analysis"
)

type BrandManager interface {
	ListBrands(ctx context.Context) ([]analysis.Brand, error)
	GetBrand(ctx context.Context, id int64) (analysis.Brand, error)
	CreateBrand(ctx context.Context, brand analysis.Brand) (analysis.Brand, error)
	UpdateBrand(ctx context.Context, id int64, brand analysis.Brand) (analysis.Brand, error)
	DeleteBrand(ctx context.Context, id int64) error
}

func BrandHandler(manager BrandManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if manager == nil {
			writeServeError(w, http.StatusServiceUnavailable, "brand store not configured")
			return
		}

		switch r.Method {
		case http.MethodGet:
			id, ok := brandIDFromQuery(w, r, false)
			if !ok {
				return
			}
			if id > 0 {
				brand, err := manager.GetBrand(r.Context(), id)
				if err != nil {
					writeServeError(w, http.StatusNotFound, err.Error())
					return
				}
				writeServeJSON(w, http.StatusOK, brand)
				return
			}
			brands, err := manager.ListBrands(r.Context())
			if err != nil {
				writeServeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if brands == nil {
				brands = []analysis.Brand{}
			}
			writeServeJSON(w, http.StatusOK, map[string]any{"items": brands})

		case http.MethodPost:
			brand, ok := decodeBrandRequest(w, r)
			if !ok {
				return
			}
			created, err := manager.CreateBrand(r.Context(), brand)
			if err != nil {
				writeServeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeServeJSON(w, http.StatusCreated, created)

		case http.MethodPut:
			id, ok := brandIDFromQuery(w, r, true)
			if !ok {
				return
			}
			brand, ok := decodeBrandRequest(w, r)
			if !ok {
				return
			}
			updated, err := manager.UpdateBrand(r.Context(), id, brand)
			if err != nil {
				writeServeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeServeJSON(w, http.StatusOK, updated)

		case http.MethodDelete:
			id, ok := brandIDFromQuery(w, r, true)
			if !ok {
				return
			}
			if err := manager.DeleteBrand(r.Context(), id); err != nil {
				writeServeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeServeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": id})

		default:
			writeServeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func decodeBrandRequest(w http.ResponseWriter, r *http.Request) (analysis.Brand, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	defer r.Body.Close()
	var brand analysis.Brand
	if err := json.NewDecoder(r.Body).Decode(&brand); err != nil {
		writeServeError(w, http.StatusBadRequest, "invalid JSON body")
		return analysis.Brand{}, false
	}
	return brand, true
}

func brandIDFromQuery(w http.ResponseWriter, r *http.Request, required bool) (int64, bool) {
	value := r.URL.Query().Get("id")
	if value == "" {
		if required {
			writeServeError(w, http.StatusBadRequest, "id query parameter is required")
			return 0, false
		}
		return 0, true
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		writeServeError(w, http.StatusBadRequest, "invalid brand id")
		return 0, false
	}
	return id, true
}

func writeServeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeServeError(w http.ResponseWriter, statusCode int, message string) {
	writeServeJSON(w, statusCode, map[string]string{"error": message})
}
