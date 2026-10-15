package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/spondonsaha/vexora/api/internal/config"
	"github.com/spondonsaha/vexora/api/internal/store"
)

func NewRouter(st store.Store, cfg config.Config) http.Handler {
	h := NewHandler(st, cfg)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(corsMiddleware(cfg.CORSAllowedOrigins))

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", h.Health)

		r.Route("/scope-targets", func(r chi.Router) {
			r.Get("/", h.ListScopeTargets)
			r.Post("/", h.CreateScopeTarget)

			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", h.GetScopeTarget)
				r.Delete("/", h.DeleteScopeTarget)
				r.Patch("/activate", h.ActivateScopeTarget)
				r.Patch("/notes", h.SetScopeTargetNotes)
			})
		})

		r.Route("/scans", func(r chi.Router) {
			r.Get("/", h.ListScans)
			r.Post("/{id}", h.CreateScan)
			r.Get("/{id}", h.GetScan)
			r.Get("/{id}/raw-output", h.GetScanRawOutput)
		})

		r.Route("/workflows", func(r chi.Router) {
			r.Get("/", h.ListWorkflows)
			r.Post("/wildcard/run", h.RunWildcardWorkflow)
			r.Post("/domain/run", h.RunDomainWorkflow)
			r.Get("/{id}", h.GetWorkflow)
		})

		r.Get("/targets/{id}/subdomains", h.ListTargetSubdomains)
		r.Get("/targets/{id}/live-servers", h.ListTargetLiveServers)
		r.Get("/targets/{id}/endpoints", h.ListTargetEndpoints)
		r.Get("/targets/{id}/nuclei-findings", h.ListTargetNucleiFindings)
		r.Get("/targets/{id}/network-services", h.ListTargetNetworkServices)
		r.Get("/targets/{id}/sqli-findings", h.ListTargetSQLiFindings)
		r.Get("/targets/{id}/js-findings", h.ListTargetJSFindings)
		r.Get("/targets/{id}/open-redirect-findings", h.ListTargetOpenRedirectFindings)
		r.Get("/live-servers/{id}/screenshot", h.GetLiveWebServerScreenshot)
	})

	return r
}
