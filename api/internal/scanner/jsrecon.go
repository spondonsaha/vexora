package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

// JSReconTool is the ad-hoc tool name for the JavaScript reconnaissance pass.
const JSReconTool = "jsrecon"

type jsReconOptions struct {
	MaxFiles int `json:"max_files"`
}

// jsReconEvent is one JSON line emitted by the jsrecon container: either a
// per-file event ("event":"file") or a finding (type/value present).
type jsReconEvent struct {
	Event   string `json:"event"`
	URL     string `json:"url"`
	OK      bool   `json:"ok"`
	Bytes   int    `json:"bytes"`
	Error   string `json:"error"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context"`
}

// runJSReconAdHoc fetches the JavaScript assets discovered during URL discovery
// and extracts secrets, endpoints and other artifacts for an ad-hoc job.
func (r *Runner) runJSReconAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.JSReconEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("javascript recon is disabled")}
	}

	maxFiles := r.cfg.JSReconMaxFiles
	if maxFiles < 1 {
		maxFiles = 100
	}
	var opts jsReconOptions
	if len(job.Options) > 0 {
		if err := json.Unmarshal(job.Options, &opts); err == nil && opts.MaxFiles > 0 {
			maxFiles = opts.MaxFiles
		}
	}
	if maxFiles < 1 {
		maxFiles = 100
	}

	jsURLs, err := r.jsReconTargets(ctx, target, maxFiles)
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: err}
	}

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")

	if len(jsURLs) == 0 {
		msg := "no JavaScript URLs found: run the wildcard workflow (URL discovery) or a katana scan first"
		writeRawFile(stdoutPath, msg+"\n")
		writeRawFile(stderrPath, "")
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: errors.New(msg)}
	}

	args := []string{"--root", root}
	stdout, stderr, exitCode, runErr := r.runContainerInput(ctx, job.ID, r.cfg.JSReconImage, strings.Join(jsURLs, "\n"), args...)
	writeRawFile(stdoutPath, stdout)
	writeRawFile(stderrPath, stderr)

	rows, scanned, failed := parseJSRecon(stdout, root)
	stored := 0
	if len(rows) > 0 {
		n, err := r.store.UpsertJSFindings(ctx, target.ID, job.ID, rows)
		if err != nil {
			return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("store js findings: %w", err)}
		}
		stored = n
	}

	log.Printf("job %s: jsrecon scanned %d file(s) (%d failed), %d finding(s) (%d stored)",
		job.ID, scanned, failed, len(rows), stored)

	if runErr != nil {
		return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("jsrecon: %w", runErr)}
	}
	return Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// jsReconTargets selects the JavaScript files to analyse from the endpoints
// discovered for the target (katana -jc / gau / waybackurls all surface .js URLs).
func (r *Runner) jsReconTargets(ctx context.Context, target *models.ScopeTarget, maxFiles int) ([]string, error) {
	endpoints, err := r.store.ListEndpointsByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.URL == nil {
			continue
		}
		raw := strings.TrimSpace(*ep.URL)
		if raw == "" || !isJavaScriptURL(raw) {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	sort.Strings(out)
	if len(out) > maxFiles {
		out = out[:maxFiles]
	}
	return out, nil
}

// isJavaScriptURL reports whether a URL points at a JavaScript asset.
func isJavaScriptURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	if p == "" {
		return false
	}
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".jsx")
}

// parseJSRecon parses the jsrecon container's JSONL output into finding rows and
// per-file counters.
func parseJSRecon(stdout, root string) (rows []store.JSFindingRow, scanned, failed int) {
	rows = make([]store.JSFindingRow, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ev jsReconEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Event == "file" {
			if ev.OK {
				scanned++
			} else {
				failed++
			}
			continue
		}
		if ev.Type == "" || ev.Value == "" {
			continue
		}
		if ev.Type == "subdomain" && !isSubdomainOf(ev.Value, root) {
			continue
		}
		rows = append(rows, store.JSFindingRow{
			JSURL:       ev.URL,
			Host:        hostOf(ev.URL),
			FindingType: ev.Type,
			Value:       ev.Value,
			Context:     ev.Context,
		})
	}
	return rows, scanned, failed
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return ""
}
