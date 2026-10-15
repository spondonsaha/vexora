package api

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/scanner"
	"github.com/spondonsaha/vexora/api/internal/store"
)

var supportedTools = map[string]bool{
	"subfinder":    true,
	"amass":        true,
	"gau":          true,
	"assetfinder":  true,
	"sublist3r":    true,
	"findomain":    true,
	"ct":           true,
	"waybackurls":  true,
	"katana":       true,
	"takeover":     true,
	"nuclei":       true,
	"netscan":      true,
	"sqli":         true,
	"jsrecon":      true,
	"openredirect": true,
	"screenshot":   true,
}

type createScanRequest struct {
	ScopeTargetID string         `json:"scope_target_id"`
	Options       map[string]any `json:"options"`
}

func (h *Handler) CreateScan(w http.ResponseWriter, r *http.Request) {
	tool := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "id")))
	if !supportedTools[tool] {
		writeError(w, http.StatusUnprocessableEntity, "unsupported_tool", "supported tools: subfinder, amass, assetfinder, sublist3r, findomain, ct, gau, waybackurls, katana, takeover, nuclei, netscan, sqli, jsrecon, openredirect, screenshot")
		return
	}

	var req createScanRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if tool == scanner.NucleiTool {
		category := "all"
		if req.Options != nil {
			if raw, ok := req.Options["category"]; ok {
				if s, ok := raw.(string); ok {
					category = strings.ToLower(strings.TrimSpace(s))
				}
			}
		}
		if _, ok := scanner.NucleiCategories[category]; !ok {
			writeError(w, http.StatusUnprocessableEntity, "invalid_category",
				"nuclei category must be one of: xss, cve, takeover, misconfig, all")
			return
		}
		if req.Options == nil {
			req.Options = map[string]any{}
		}
		req.Options["category"] = category
	}

	if tool == scanner.NetworkTool {
		profile := "top100"
		if req.Options != nil {
			if raw, ok := req.Options["profile"]; ok {
				if s, ok := raw.(string); ok {
					profile = strings.ToLower(strings.TrimSpace(s))
				}
			}
		}
		if _, ok := scanner.NetworkProfiles[profile]; !ok {
			writeError(w, http.StatusUnprocessableEntity, "invalid_profile",
				"port profile must be one of: top100, top1000, full")
			return
		}
		if req.Options == nil {
			req.Options = map[string]any{}
		}
		req.Options["profile"] = profile
	}

	if tool == scanner.SQLiTool {
		technique := scanner.SQLiDefaultTechniques
		if req.Options != nil {
			if raw, ok := req.Options["technique"]; ok {
				if s, ok := raw.(string); ok {
					technique = strings.ToUpper(strings.TrimSpace(s))
				}
			}
		}
		if !scanner.ValidSQLiTechnique(technique) {
			writeError(w, http.StatusUnprocessableEntity, "invalid_technique",
				"technique must be a non-empty subset of BEUSTQ (boolean, error, union, stacked, time, inline)")
			return
		}
		level := optInt(req.Options, "level", 1)
		risk := optInt(req.Options, "risk", 1)
		threads := optInt(req.Options, "threads", 4)
		crawl := optInt(req.Options, "crawl", 0)
		if level < 1 || level > 5 {
			writeError(w, http.StatusUnprocessableEntity, "invalid_level", "level must be between 1 and 5")
			return
		}
		if risk < 1 || risk > 3 {
			writeError(w, http.StatusUnprocessableEntity, "invalid_risk", "risk must be between 1 and 3")
			return
		}
		if threads < 1 || threads > 10 {
			writeError(w, http.StatusUnprocessableEntity, "invalid_threads", "threads must be between 1 and 10")
			return
		}
		if crawl < 0 || crawl > 5 {
			writeError(w, http.StatusUnprocessableEntity, "invalid_crawl", "crawl depth must be between 0 and 5")
			return
		}
		if req.Options == nil {
			req.Options = map[string]any{}
		}
		req.Options["technique"] = technique
		req.Options["level"] = level
		req.Options["risk"] = risk
		req.Options["threads"] = threads
		req.Options["crawl"] = crawl
	}

	if tool == scanner.JSReconTool {
		maxFiles := optInt(req.Options, "max_files", h.cfg.JSReconMaxFiles)
		if maxFiles < 1 || maxFiles > 500 {
			writeError(w, http.StatusUnprocessableEntity, "invalid_max_files", "max_files must be between 1 and 500")
			return
		}
		if req.Options == nil {
			req.Options = map[string]any{}
		}
		req.Options["max_files"] = maxFiles
	}

	if tool == scanner.OpenRedirectTool {
		maxTargets := optInt(req.Options, "max_targets", h.cfg.OpenRedirectMaxTargets)
		if maxTargets < 1 || maxTargets > 500 {
			writeError(w, http.StatusUnprocessableEntity, "invalid_max_targets", "max_targets must be between 1 and 500")
			return
		}
		testAll := false
		if req.Options != nil {
			if raw, ok := req.Options["test_all_params"]; ok {
				if b, ok := raw.(bool); ok {
					testAll = b
				}
			}
		}
		if req.Options == nil {
			req.Options = map[string]any{}
		}
		req.Options["max_targets"] = maxTargets
		req.Options["test_all_params"] = testAll
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
			"cannot start a scan: authorization is not confirmed for this target")
		return
	}

	job, err := h.store.CreateScanJob(r.Context(), store.CreateScanJobInput{
		ScopeTargetID: scopeTargetID,
		Tool:          tool,
		Options:       req.Options,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to queue scan")
		return
	}

	_ = h.store.RecordAudit(r.Context(), store.AuditEntry{
		ScopeTargetID: &target.ID,
		ScanJobID:     &job.ID,
		Target:        target.Value,
		Tool:          tool,
		Action:        "scan.create",
		Detail:        map[string]any{"status": job.Status},
	})

	w.Header().Set("Location", "/api/v1/scans/"+job.ID.String())
	writeJSON(w, http.StatusAccepted, job)
}

func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scan id must be a valid UUID")
		return
	}

	job, err := h.store.GetScanJob(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "scan job not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load scan job")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (h *Handler) ListScans(w http.ResponseWriter, r *http.Request) {
	scopeTargetID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("scope_target_id")))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope_target_id query parameter must be a valid UUID")
		return
	}

	jobs, err := h.store.ListScanJobsByScopeTarget(r.Context(), scopeTargetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list scans")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": jobs, "count": len(jobs)})
}

func (h *Handler) GetScanRawOutput(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scan id must be a valid UUID")
		return
	}

	job, err := h.store.GetScanJob(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "scan job not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load scan job")
		return
	}

	stream := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("stream")))
	if stream == "" {
		stream = "stdout"
	}
	var path *string
	switch stream {
	case "stdout":
		path = job.StdoutPath
	case "stderr":
		path = job.StderrPath
	default:
		writeError(w, http.StatusBadRequest, "invalid_stream", "stream must be stdout or stderr")
		return
	}

	if path == nil {
		writeError(w, http.StatusNotFound, "output_unavailable", "no output recorded for this stream yet")
		return
	}

	content, err := os.ReadFile(*path)
	if err != nil {
		writeError(w, http.StatusNotFound, "output_not_found", "raw output is not available yet")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (h *Handler) ListTargetSubdomains(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return
	}

	subs, err := h.store.ListSubdomainsByScopeTarget(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list subdomains")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": subs, "count": len(subs)})
}

func (h *Handler) ListTargetNucleiFindings(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return
	}

	findings, err := h.store.ListNucleiFindingsByScopeTarget(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list nuclei findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings, "count": len(findings)})
}

func (h *Handler) ListTargetNetworkServices(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return
	}

	services, err := h.store.ListNetworkServicesByScopeTarget(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list network services")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": services, "count": len(services)})
}

func (h *Handler) ListTargetSQLiFindings(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return
	}

	findings, err := h.store.ListSQLiFindingsByScopeTarget(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list sqli findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings, "count": len(findings)})
}

func (h *Handler) ListTargetJSFindings(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return
	}

	findings, err := h.store.ListJSFindingsByScopeTarget(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list javascript findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings, "count": len(findings)})
}

func (h *Handler) ListTargetOpenRedirectFindings(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "scope target id must be a valid UUID")
		return
	}

	findings, err := h.store.ListOpenRedirectFindingsByScopeTarget(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list open redirect findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": findings, "count": len(findings)})
}

// optInt reads an integer option from a decoded JSON object, tolerating the
// float64 representation produced by encoding/json as well as string values.
func optInt(opts map[string]any, key string, fallback int) int {
	if opts == nil {
		return fallback
	}
	raw, ok := opts[key]
	if !ok {
		return fallback
	}
	switch v := raw.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}
