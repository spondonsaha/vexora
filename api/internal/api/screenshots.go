package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/store"
)

// GetLiveWebServerScreenshot streams the stored screenshot for a live web
// server. The stored path is relative to the raw output directory and is
// validated so a crafted value cannot escape it.
func (h *Handler) GetLiveWebServerScreenshot(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "live web server id must be a valid UUID")
		return
	}

	srv, err := h.store.GetLiveWebServer(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "live web server not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load live web server")
		return
	}

	if srv.ScreenshotPath == nil || strings.TrimSpace(*srv.ScreenshotPath) == "" {
		writeError(w, http.StatusNotFound, "screenshot_unavailable", "no screenshot has been captured for this server")
		return
	}

	base, err := filepath.Abs(h.cfg.RawOutputDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to resolve screenshot directory")
		return
	}
	full, err := filepath.Abs(filepath.Join(base, filepath.FromSlash(*srv.ScreenshotPath)))
	if err != nil || (full != base && !strings.HasPrefix(full, base+string(os.PathSeparator))) {
		writeError(w, http.StatusBadRequest, "invalid_path", "screenshot path is invalid")
		return
	}

	f, err := os.Open(full)
	if err != nil {
		writeError(w, http.StatusNotFound, "screenshot_unavailable", "screenshot file is not available")
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		writeError(w, http.StatusNotFound, "screenshot_unavailable", "screenshot file is not available")
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=300")
	http.ServeContent(w, r, filepath.Base(full), info.ModTime(), f)
}
