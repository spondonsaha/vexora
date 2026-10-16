package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

// TechnologyTool is the ad-hoc tool name for technology-stack fingerprinting.
// This is the first-pass detector (httpx -tech-detect); WhatWeb, Wappalyzer,
// CMSeeK, WPScan and retire.js are added as additional detectors in a later
// pass and merge into the same `technologies` table by `detected_by`.
const TechnologyTool = "techdetect"

// techOptions are the knobs accepted from the API/UI.
type techOptions struct {
	MaxTargets int `json:"max_targets"`
}

// httpxTechResult is the subset of an httpx JSON line needed for fingerprinting.
type httpxTechResult struct {
	URL   string   `json:"url"`
	Input string   `json:"input"`
	Host  string   `json:"host"`
	Tech  []string `json:"tech"`
}

// runTechnologyAdHoc fingerprints the technologies running on every live web
// server for the target with httpx -tech-detect and normalizes the results into
// the `technologies` table.
func (r *Runner) runTechnologyAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.TechnologyEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("technology fingerprinting is disabled")}
	}

	opts := techOptions{MaxTargets: r.cfg.TechMaxTargets}
	if len(job.Options) > 0 {
		var parsed techOptions
		if err := json.Unmarshal(job.Options, &parsed); err == nil && parsed.MaxTargets > 0 {
			opts.MaxTargets = parsed.MaxTargets
		}
	}
	if opts.MaxTargets < 1 {
		opts.MaxTargets = r.cfg.TechMaxTargets
	}

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")

	servers, err := r.store.ListLiveWebServersByScopeTarget(ctx, target.ID)
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: fmt.Errorf("list live servers: %w", err)}
	}

	byURL := make(map[string]uuid.UUID, len(servers))
	urls := make([]string, 0, len(servers))
	for _, srv := range servers {
		u := strings.TrimSpace(srv.URL)
		if u == "" {
			continue
		}
		key := normalizeURL(u)
		if key == "" {
			continue
		}
		if _, ok := byURL[key]; ok {
			continue
		}
		byURL[key] = srv.ID
		urls = append(urls, u)
	}
	sort.Strings(urls)

	if len(urls) == 0 {
		msg := "no live web servers to fingerprint: run the wildcard workflow (consolidate & probe) first"
		writeRawFile(stdoutPath, msg+"\n")
		writeRawFile(stderrPath, "")
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: errors.New(msg)}
	}
	if len(urls) > opts.MaxTargets {
		log.Printf("techdetect: %d target(s) truncated to %d", len(urls), opts.MaxTargets)
		urls = urls[:opts.MaxTargets]
	}

	args := []string{"-tech-detect", "-json", "-silent", "-no-color", "-timeout", "10"}
	stdout, stderr, exitCode, runErr := r.runContainerInput(ctx, job.ID, r.cfg.HttpxImage, strings.Join(urls, "\n"), args...)
	writeRawFile(stdoutPath, stdout)
	writeRawFile(stderrPath, stderr)

	rows := parseHttpxTechnologies(stdout, byURL)
	stored := 0
	if len(rows) > 0 {
		n, err := r.store.UpsertTechnologies(ctx, target.ID, job.ID, rows)
		if err != nil {
			return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("store technologies: %w", err)}
		}
		stored = n
	}

	log.Printf("job %s: techdetect fingerprinted %d server(s), %d technology row(s) (%d stored)",
		job.ID, len(urls), len(rows), stored)

	if runErr != nil {
		return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("httpx: %w", runErr)}
	}
	return Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// parseHttpxTechnologies maps each httpx JSON line to its live web server and
// normalizes the raw tech strings (e.g. "WordPress:6.4.2") into rows.
func parseHttpxTechnologies(stdout string, byURL map[string]uuid.UUID) []store.TechnologyRow {
	rows := make([]store.TechnologyRow, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var res httpxTechResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		if len(res.Tech) == 0 {
			continue
		}
		key := normalizeURL(res.URL)
		if key == "" {
			key = normalizeURL(res.Input)
		}
		serverID, ok := byURL[key]
		if !ok {
			continue
		}
		for _, raw := range res.Tech {
			name, version := splitTech(raw)
			if name == "" {
				continue
			}
			rows = append(rows, store.TechnologyRow{
				LiveWebServerID: serverID,
				Name:            name,
				Version:         version,
				Category:        categorizeTech(name),
				DetectedBy:      "httpx",
			})
		}
	}
	return rows
}

// splitTech splits an httpx technology string ("WordPress:6.4.2") into its name
// and version components. A technology without a version returns an empty one.
func splitTech(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		name := strings.TrimSpace(raw[:i])
		version := strings.TrimSpace(raw[i+1:])
		return name, version
	}
	return raw, ""
}

// techCategories maps a known technology (lowercased) to its category. Anything
// not listed falls back to "other".
var techCategories = map[string]string{
	// CMS
	"wordpress": "cms", "drupal": "cms", "joomla": "cms", "typo3": "cms",
	"ghost": "cms", "hugo": "cms", "jekyll": "cms", "dnn": "cms",
	"sitecore": "cms", "adobe experience manager": "cms", "aem": "cms",
	"contentful": "cms", "squarespace": "cms", "wix": "cms", "magento": "cms",
	"prestashop": "cms", "opencart": "cms", "woocommerce": "cms", "shopify": "cms",
	// Framework
	"laravel": "framework", "symfony": "framework", "codeigniter": "framework",
	"django": "framework", "flask": "framework", "fastapi": "framework",
	"ruby on rails": "framework", "rails": "framework", "spring": "framework",
	"express": "framework", "next.js": "framework", "nuxt": "framework",
	"gatsby": "framework", "svelte": "framework", "angular": "framework",
	"react": "framework", "vue.js": "framework", "asp.net": "framework",
	"asp.net mvc": "framework", "struts": "framework", "cakephp": "framework",
	"yii": "framework", "node.js": "framework", "gunicorn": "framework",
	// Server
	"nginx": "server", "apache": "server", "apache http server": "server",
	"iis": "server", "microsoft-iis": "server", "litespeed": "server",
	"openresty": "server", "caddy": "server", "tomcat": "server",
	"apache tomcat": "server", "jetty": "server", "gunicorn server": "server",
	"envoy": "server", "traefik": "server", "haproxy": "server",
	// JS library
	"jquery": "js-library", "jquery ui": "js-library", "bootstrap": "js-library",
	"lodash": "js-library", "moment.js": "js-library", "axios": "js-library",
	"modernizr": "js-library", "underscore.js": "js-library", "backbone.js": "js-library",
	"requirejs": "js-library", "core-js": "js-library", "popper": "js-library",
	"swiper": "js-library", "slick": "js-library", "highlight.js": "js-library",
	// Analytics
	"google analytics": "analytics", "gtag": "analytics", "google tag manager": "analytics",
	"hotjar": "analytics", "mixpanel": "analytics", "segment": "analytics",
	"matomo": "analytics", "plausible": "analytics", "new relic": "analytics",
	"facebook pixel": "analytics", "hubspot": "analytics", "clarity": "analytics",
	// CDN
	"cloudflare": "cdn", "amazon cloudfront": "cdn", "cloudfront": "cdn",
	"fastly": "cdn", "akamai": "cdn", "azure cdn": "cdn", "google cloud cdn": "cdn",
	"bunnycdn": "cdn", "stackpath": "cdn", "keycdn": "cdn", "amazon s3": "cdn",
	// WAF
	"aws waf": "waf", "cloudflare waf": "waf", "imperva": "waf", "incapsula": "waf",
	"f5 big-ip": "waf", "fortiweb": "waf", "sucuri": "waf", "barracuda": "waf",
	"modsecurity": "waf", "wordfence": "waf",
	// Language / runtime
	"php": "language", "python": "language", "ruby": "language", "perl": "language",
	"java": "language", "go": "language", "asp": "language",
	// Database
	"mysql": "database", "postgresql": "database", "microsoft sql server": "database",
	"mongodb": "database", "redis": "database", "mariadb": "database", "oracle": "database",
}

// categorizeTech returns the category for a technology name.
func categorizeTech(name string) string {
	if cat, ok := techCategories[strings.ToLower(strings.TrimSpace(name))]; ok {
		return cat
	}
	return "other"
}
