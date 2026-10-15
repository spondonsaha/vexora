package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/config"
	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

type Handler struct {
	store store.Store
	cfg   config.Config
}

func NewHandler(st store.Store, cfg config.Config) *Handler {
	return &Handler{store: st, cfg: cfg}
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	status, dbStatus := "ok", "ok"
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.store.Ping(ctx); err != nil {
		status, dbStatus = "degraded", "error"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   status,
		"database": dbStatus,
		"time":     time.Now().UTC(),
	})
}

type createScopeTargetRequest struct {
	Type          string `json:"type"`
	Value         string `json:"value"`
	Description   string `json:"description"`
	AuthConfirmed bool   `json:"auth_confirmed"`
}

func (h *Handler) CreateScopeTarget(w http.ResponseWriter, r *http.Request) {
	var req createScopeTargetRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	targetType := models.ScopeTargetType(strings.TrimSpace(req.Type))
	if !targetType.Valid() {
		writeError(w, http.StatusUnprocessableEntity, "invalid_type", "type must be one of: company, wildcard, url")
		return
	}
	value := strings.TrimSpace(req.Value)
	if value == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_value", "value is required")
		return
	}

	created, err := h.store.CreateScopeTarget(r.Context(), store.CreateScopeTargetInput{
		Type:          targetType,
		Value:         value,
		Description:   req.Description,
		AuthConfirmed: req.AuthConfirmed,
	})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "duplicate_target", "a scope target with this type and value already exists")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create scope target")
		return
	}

	_ = h.store.RecordAudit(r.Context(), store.AuditEntry{
		ScopeTargetID: &created.ID,
		Target:        created.Value,
		Action:        "scope_target.create",
		Detail:        map[string]any{"type": created.Type, "auth_confirmed": created.AuthConfirmed},
	})

	w.Header().Set("Location", "/api/v1/scope-targets/"+created.ID.String())
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) ListScopeTargets(w http.ResponseWriter, r *http.Request) {
	targetType := strings.TrimSpace(r.URL.Query().Get("type"))
	if targetType != "" && !models.ScopeTargetType(targetType).Valid() {
		writeError(w, http.StatusUnprocessableEntity, "invalid_type", "type filter must be one of: company, wildcard, url")
		return
	}

	targets, err := h.store.ListScopeTargets(r.Context(), targetType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list scope targets")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": targets, "count": len(targets)})
}

func (h *Handler) GetScopeTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := scopeTargetID(w, r)
	if !ok {
		return
	}

	target, err := h.store.GetScopeTarget(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "scope target not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load scope target")
		return
	}
	writeJSON(w, http.StatusOK, target)
}

func (h *Handler) DeleteScopeTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := scopeTargetID(w, r)
	if !ok {
		return
	}

	err := h.store.DeleteScopeTarget(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "scope target not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to delete scope target")
		return
	}

	_ = h.store.RecordAudit(r.Context(), store.AuditEntry{
		Action: "scope_target.delete",
		Detail: map[string]any{"scope_target_id": id.String()},
	})

	w.WriteHeader(http.StatusNoContent)
}

type activateScopeTargetRequest struct {
	AuthConfirmed *bool `json:"auth_confirmed"`
}

func (h *Handler) ActivateScopeTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := scopeTargetID(w, r)
	if !ok {
		return
	}

	var req activateScopeTargetRequest
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}

	target, err := h.store.GetScopeTarget(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "scope target not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load scope target")
		return
	}

	if req.AuthConfirmed != nil && *req.AuthConfirmed && !target.AuthConfirmed {
		target, err = h.store.SetScopeTargetAuthConfirmed(r.Context(), id, true)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to record authorization")
			return
		}
	}

	if !target.AuthConfirmed {
		writeError(w, http.StatusConflict, "authorization_required",
			"this target cannot be activated until you confirm you are authorized to test it")
		return
	}

	target, err = h.store.SetScopeTargetActive(r.Context(), id, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to activate scope target")
		return
	}

	_ = h.store.RecordAudit(r.Context(), store.AuditEntry{
		ScopeTargetID: &target.ID,
		Target:        target.Value,
		Action:        "scope_target.activate",
		Detail:        map[string]any{"auth_confirmed": target.AuthConfirmed},
	})

	writeJSON(w, http.StatusOK, target)
}

type setNotesRequest struct {
	Notes string `json:"notes"`
}

func (h *Handler) SetScopeTargetNotes(w http.ResponseWriter, r *http.Request) {
	id, ok := scopeTargetID(w, r)
	if !ok {
		return
	}

	var req setNotesRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	target, err := h.store.SetScopeTargetNotes(r.Context(), id, req.Notes)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "scope target not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to save notes")
		return
	}

	_ = h.store.RecordAudit(r.Context(), store.AuditEntry{
		ScopeTargetID: &target.ID,
		Target:        target.Value,
		Action:        "scope_target.notes",
		Detail:        map[string]any{"length": len(target.Notes)},
	})

	writeJSON(w, http.StatusOK, target)
}

func scopeTargetID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return uuid.Nil, false
	}
	return id, true
}
