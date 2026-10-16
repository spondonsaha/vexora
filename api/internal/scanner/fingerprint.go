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

// Detector tool names for the additional technology fingerprinting engines.
// Each runs its own container and merges into the `technologies` table tagged
// with `detected_by`, so the UI can present a deduped union of all detectors.
const (
	WhatWebTool = "whatweb"
	WPScanTool  = "wpscan"
	CMSeeKTool  = "cmseek"
)

// liveTarget pairs a live web server URL with its stored row id, so detector
// output can be mapped back to the server it describes.
type liveTarget struct {
	url      string
	serverID uuid.UUID
}

// fingerprintEvent is the JSONL contract the whatweb/wpscan/cmseek adapters
// emit: one "tech" line per detection, plus trailing "done"/"skip"/"error"
// lines that are ignored here.
type fingerprintEvent struct {
	Event    string `json:"event"`
	URL      string `json:"url"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Category string `json:"category"`
	Source   string `json:"source"`
	Message  string `json:"message"`
}

// runWhatWebAdHoc fingerprints every live web server with WhatWeb.
func (r *Runner) runWhatWebAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, _ string) Result {
	if !r.cfg.WhatWebEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("WhatWeb fingerprinting is disabled")}
	}
	targets, err := r.collectLiveTargets(ctx, target, r.techMaxTargets(job))
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: err}
	}
	return r.runFingerprintTool(ctx, job, target, WhatWebTool, r.cfg.WhatWebImage,
		"no live web servers to fingerprint: run the wildcard workflow (consolidate & probe) first", targets)
}

// runWPScanAdHoc runs WPScan against the live servers already identified as
// WordPress (by a prior fingerprinting pass), auto-chaining the WordPress
// deep scan only where it is relevant.
func (r *Runner) runWPScanAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, _ string) Result {
	if !r.cfg.WPScanEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("WPScan fingerprinting is disabled")}
	}
	wpIDs, err := r.wordpressServerIDs(ctx, target)
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: err}
	}
	all, err := r.collectLiveTargets(ctx, target, r.techMaxTargets(job))
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: err}
	}
	targets := make([]liveTarget, 0, len(all))
	for _, t := range all {
		if wpIDs[t.serverID] {
			targets = append(targets, t)
		}
	}
	return r.runFingerprintTool(ctx, job, target, WPScanTool, r.cfg.WPScanImage,
		"no WordPress hosts detected: run fingerprinting (httpx/WhatWeb/CMSeeK) first", targets)
}

// runCMSeeKAdHoc runs the CMSeeK CMS deep scan against every live web server.
func (r *Runner) runCMSeeKAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, _ string) Result {
	if !r.cfg.CMSeeKEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("CMSeeK fingerprinting is disabled")}
	}
	targets, err := r.collectLiveTargets(ctx, target, r.techMaxTargets(job))
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: err}
	}
	return r.runFingerprintTool(ctx, job, target, CMSeeKTool, r.cfg.CMSeeKImage,
		"no live web servers to fingerprint: run the wildcard workflow (consolidate & probe) first", targets)
}

// runFingerprintTool feeds the target URLs to a fingerprinting container on
// stdin, parses its JSONL output and stores the detections as technologies.
func (r *Runner) runFingerprintTool(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, tool, image, noTargets string, targets []liveTarget) Result {
	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")

	if len(targets) == 0 {
		writeRawFile(stdoutPath, noTargets+"\n")
		writeRawFile(stderrPath, "")
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: errors.New(noTargets)}
	}

	byURL := make(map[string]uuid.UUID, len(targets))
	urls := make([]string, 0, len(targets))
	for _, t := range targets {
		key := normalizeURL(t.url)
		if key == "" {
			continue
		}
		if _, ok := byURL[key]; ok {
			continue
		}
		byURL[key] = t.serverID
		urls = append(urls, t.url)
	}

	stdout, stderr, exitCode, runErr := r.runContainerInput(ctx, job.ID, image, strings.Join(urls, "\n"))
	writeRawFile(stdoutPath, stdout)
	writeRawFile(stderrPath, stderr)

	rows := parseFingerprintJSONL(stdout, byURL, tool)
	stored := 0
	if len(rows) > 0 {
		n, err := r.store.UpsertTechnologies(ctx, target.ID, job.ID, rows)
		if err != nil {
			return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("store technologies: %w", err)}
		}
		stored = n
	}

	log.Printf("job %s: %s fingerprinted %d server(s), %d technology row(s) (%d stored)",
		job.ID, tool, len(urls), len(rows), stored)

	if runErr != nil {
		return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("%s: %w", tool, runErr)}
	}
	return Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// parseFingerprintJSONL maps the adapters' JSONL output to technology rows,
// attributing each detection to the live server it belongs to and filling in a
// category when the detector did not supply one.
func parseFingerprintJSONL(stdout string, byURL map[string]uuid.UUID, defaultTool string) []store.TechnologyRow {
	rows := make([]store.TechnologyRow, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ev fingerprintEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Event != "tech" || strings.TrimSpace(ev.Name) == "" {
			continue
		}
		key := normalizeURL(ev.URL)
		serverID, ok := byURL[key]
		if !ok {
			continue
		}
		category := strings.TrimSpace(ev.Category)
		if category == "" {
			category = categorizeTech(ev.Name)
		}
		tool := strings.TrimSpace(ev.Source)
		if tool == "" {
			tool = defaultTool
		}
		rows = append(rows, store.TechnologyRow{
			LiveWebServerID: serverID,
			Name:            ev.Name,
			Version:         ev.Version,
			Category:        category,
			DetectedBy:      tool,
		})
	}
	return rows
}

// collectLiveTargets returns the live web servers for a target, deduplicated by
// normalized URL and capped at maxTargets.
func (r *Runner) collectLiveTargets(ctx context.Context, target *models.ScopeTarget, maxTargets int) ([]liveTarget, error) {
	servers, err := r.store.ListLiveWebServersByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list live servers: %w", err)
	}
	seen := make(map[string]bool, len(servers))
	out := make([]liveTarget, 0, len(servers))
	for _, srv := range servers {
		u := strings.TrimSpace(srv.URL)
		if u == "" {
			continue
		}
		key := normalizeURL(u)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, liveTarget{url: u, serverID: srv.ID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].url < out[j].url })
	if maxTargets > 0 && len(out) > maxTargets {
		log.Printf("fingerprint: %d target(s) truncated to %d", len(out), maxTargets)
		out = out[:maxTargets]
	}
	return out, nil
}

// techMaxTargets resolves the per-run cap from the job options, falling back to
// the configured default.
func (r *Runner) techMaxTargets(job *models.ScanJob) int {
	max := r.cfg.TechMaxTargets
	if len(job.Options) > 0 {
		var parsed techOptions
		if err := json.Unmarshal(job.Options, &parsed); err == nil && parsed.MaxTargets > 0 {
			max = parsed.MaxTargets
		}
	}
	if max < 1 {
		max = r.cfg.TechMaxTargets
	}
	return max
}

// wordpressServerIDs returns the live web servers already known to run
// WordPress, using the merged technologies table first and falling back to the
// raw httpx tech_stack captured during the consolidate & probe step.
func (r *Runner) wordpressServerIDs(ctx context.Context, target *models.ScopeTarget) (map[uuid.UUID]bool, error) {
	ids := make(map[uuid.UUID]bool)
	techs, err := r.store.ListTechnologiesByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list technologies: %w", err)
	}
	for _, t := range techs {
		if strings.Contains(strings.ToLower(t.Name), "wordpress") {
			ids[t.LiveWebServerID] = true
		}
	}
	if len(ids) > 0 {
		return ids, nil
	}

	servers, err := r.store.ListLiveWebServersByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list live servers: %w", err)
	}
	for _, srv := range servers {
		if techStackHasWordPress(srv.TechStack) {
			ids[srv.ID] = true
		}
	}
	return ids, nil
}

// techStackHasWordPress reports whether a raw httpx tech_stack array mentions
// WordPress.
func techStackHasWordPress(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, s := range arr {
			if strings.Contains(strings.ToLower(s), "wordpress") {
				return true
			}
		}
		return false
	}
	return strings.Contains(strings.ToLower(string(raw)), "wordpress")
}
