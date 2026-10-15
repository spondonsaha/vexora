package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

var supportedWorkflows = map[string]models.WorkflowType{
	"wildcard": models.WorkflowWildcard,
	"domain":   models.WorkflowDomain,
}

type runWorkflowRequest struct {
	ScopeTargetID string `json:"scope_target_id"`
}

func (h *Handler) RunWildcardWorkflow(w http.ResponseWriter, r *http.Request) {
	h.runWorkflow(w, r, models.WorkflowWildcard)
}

func (h *Handler) RunDomainWorkflow(w http.ResponseWriter, r *http.Request) {
	h.runWorkflow(w, r, models.WorkflowDomain)
}

func (h *Handler) runWorkflow(w http.ResponseWriter, r *http.Request, wfType models.WorkflowType) {
	var req runWorkflowRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	scopeTargetID, err := uuid.Parse(strings.TrimSpace(req.ScopeTargetID))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope_target_id must be a valid UUID")
		return
	}

	target, err := h.store.GetScopeTarget(r.Context(), scopeTargetID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "scope target not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load scope target")
		return
	}

	if !target.AuthConfirmed {
		writeError(w, http.StatusConflict, "authorization_required",
			"cannot start a workflow: authorization is not confirmed for this target")
		return
	}

	wf, err := h.store.CreateWorkflow(r.Context(), store.CreateWorkflowInput{
		ScopeTargetID: scopeTargetID,
		WorkflowType:  wfType,
		Steps:         workflowStepsFor(wfType),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create workflow")
		return
	}

	_ = h.store.RecordAudit(r.Context(), store.AuditEntry{
		ScopeTargetID: &target.ID,
		Target:        target.Value,
		Action:        "workflow.create",
		Detail:        map[string]any{"workflow_type": string(wfType)},
	})

	w.Header().Set("Location", "/api/v1/workflows/"+wf.ID.String())
	writeJSON(w, http.StatusAccepted, wf)
}

func (h *Handler) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "workflow id must be a valid UUID")
		return
	}

	wf, err := h.store.GetWorkflow(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "workflow not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load workflow")
		return
	}
	writeJSON(w, http.StatusOK, wf)
}

func (h *Handler) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	scopeTargetID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("scope_target_id")))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope_target_id query parameter must be a valid UUID")
		return
	}

	workflows, err := h.store.ListWorkflowsByScopeTarget(r.Context(), scopeTargetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list workflows")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": workflows, "count": len(workflows)})
}

func (h *Handler) ListTargetLiveServers(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return
	}

	servers, err := h.store.ListLiveWebServersByScopeTarget(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list live servers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": servers, "count": len(servers)})
}

func (h *Handler) ListTargetEndpoints(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return
	}

	endpoints, err := h.store.ListEndpointsByScopeTarget(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list endpoints")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": endpoints, "count": len(endpoints)})
}

func workflowStepsFor(wfType models.WorkflowType) []store.WorkflowStepSeed {
	if wfType == models.WorkflowDomain {
		return store.DomainWorkflowSteps()
	}
	return store.WildcardWorkflowSteps()
}
