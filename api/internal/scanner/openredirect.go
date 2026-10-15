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

// OpenRedirectTool is the ad-hoc tool name for open-redirect testing.
const OpenRedirectTool = "openredirect"

// openRedirectOptions are the knobs accepted from the API/UI.
type openRedirectOptions struct {
	MaxTargets    int  `json:"max_targets"`
	TestAllParams bool `json:"test_all_params"`
}

// openRedirectEvent is one JSON line emitted by the openredirect container:
// either a finding (URL+Type present) or the trailing summary ("event":"done").
type openRedirectEvent struct {
	Event     string `json:"event"`
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	Status    int    `json:"status"`
	Location  string `json:"location"`
	Evidence  string `json:"evidence"`
}

// redirectParamNames mirrors the parameter set used by the container (and the
// "gf redirect" list) so the worker can pre-filter candidate URLs.
var redirectParamNames = map[string]struct{}{
	"redirect": {}, "redirecturl": {}, "redirect_url": {}, "redirectto": {}, "redirect_to": {},
	"redirect_uri": {}, "redirect-uri": {}, "redirecturi": {}, "redir": {}, "redirurl": {},
	"redir_url": {}, "rurl": {}, "url": {}, "uri": {}, "next": {}, "nexturl": {}, "next_url": {},
	"return": {}, "returnurl": {}, "return_url": {}, "returnto": {}, "return_to": {},
	"returnpath": {}, "return_path": {}, "goto": {}, "go": {}, "dest": {}, "destination": {},
	"destinationurl": {}, "destination_url": {}, "target": {}, "targeturl": {}, "target_url": {},
	"continue": {}, "continueurl": {}, "continue_url": {}, "callback": {}, "callbackurl": {},
	"callback_url": {}, "u": {}, "link": {}, "out": {}, "outurl": {}, "view": {}, "forward": {},
	"forwardurl": {}, "forward_url": {}, "to": {}, "r": {}, "ref": {}, "reference": {}, "image": {},
	"imageurl": {}, "image_url": {}, "file": {}, "fileurl": {}, "file_url": {}, "page": {},
	"pageurl": {}, "page_url": {}, "login": {}, "logout": {}, "signin": {}, "signout": {},
	"checkout": {}, "checkouturl": {}, "checkout_url": {}, "success": {}, "successurl": {},
	"success_url": {}, "cancel": {}, "cancelurl": {}, "cancel_url": {}, "oauth": {},
	"oauthcallback": {}, "oauth_callback": {}, "oauth_redirect": {}, "sso": {}, "service": {},
	"host": {}, "hostname": {}, "domain": {}, "domainurl": {}, "domain_url": {}, "sp": {},
	"action": {}, "back": {}, "backurl": {}, "back_url": {}, "jump": {}, "jumpurl": {},
	"site": {}, "returl": {}, "urlredirect": {}, "uport": {},
}

// runOpenRedirectAdHoc tests discovered parameterised URLs for open redirects.
func (r *Runner) runOpenRedirectAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.OpenRedirectEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("open redirect scanning is disabled")}
	}

	opts := openRedirectOptions{MaxTargets: r.cfg.OpenRedirectMaxTargets}
	if len(job.Options) > 0 {
		var parsed openRedirectOptions
		if err := json.Unmarshal(job.Options, &parsed); err == nil {
			if parsed.MaxTargets > 0 {
				opts.MaxTargets = parsed.MaxTargets
			}
			opts.TestAllParams = parsed.TestAllParams
		}
	}
	if opts.MaxTargets < 1 {
		opts.MaxTargets = r.cfg.OpenRedirectMaxTargets
	}

	targets, err := r.openRedirectTargets(ctx, target, opts)
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: err}
	}

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")

	if len(targets) == 0 {
		msg := "no redirect-style parameters found: run the wildcard workflow (URL discovery) first, or enable 'test all parameters'"
		writeRawFile(stdoutPath, msg+"\n")
		writeRawFile(stderrPath, "")
		return Result{Status: models.ScanFailed, ExitCode: -1, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: errors.New(msg)}
	}

	canary := strings.TrimSpace(r.cfg.OpenRedirectCanary)
	if canary == "" {
		canary = "evil.com"
	}
	args := []string{"--root", root, "--canary", canary}
	if opts.TestAllParams {
		args = append(args, "--test-all-params")
	}

	stdout, stderr, exitCode, runErr := r.runContainerInput(ctx, job.ID, r.cfg.OpenRedirectImage, strings.Join(targets, "\n"), args...)
	writeRawFile(stdoutPath, stdout)
	writeRawFile(stderrPath, stderr)

	rows := parseOpenRedirect(stdout)
	stored := 0
	if len(rows) > 0 {
		n, err := r.store.UpsertOpenRedirectFindings(ctx, target.ID, job.ID, rows)
		if err != nil {
			return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("store open redirect findings: %w", err)}
		}
		stored = n
	}

	log.Printf("job %s: openredirect tested %d target(s), %d finding(s) (%d stored)",
		job.ID, len(targets), len(rows), stored)

	if runErr != nil {
		return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("openredirect: %w", runErr)}
	}
	return Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// openRedirectTargets selects the parameterised URLs to test: with redirect-like
// parameters by default, or every parameterised URL when test-all is enabled.
func (r *Runner) openRedirectTargets(ctx context.Context, target *models.ScopeTarget, opts openRedirectOptions) ([]string, error) {
	endpoints, err := r.store.ListEndpointsByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}

	seen := map[string]struct{}{}
	candidates := make([]string, 0)
	for _, ep := range endpoints {
		if ep.URL == nil {
			continue
		}
		u := strings.TrimSpace(*ep.URL)
		if u == "" || !strings.Contains(u, "?") {
			continue
		}
		if !opts.TestAllParams && !hasRedirectParam(u) {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		candidates = append(candidates, u)
	}
	sort.Strings(candidates)

	if len(candidates) > opts.MaxTargets {
		log.Printf("openredirect: %d target(s) truncated to %d", len(candidates), opts.MaxTargets)
		candidates = candidates[:opts.MaxTargets]
	}
	return candidates, nil
}

// hasRedirectParam reports whether any query parameter name matches the known
// redirect-style set.
func hasRedirectParam(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for name := range u.Query() {
		if _, ok := redirectParamNames[strings.ToLower(name)]; ok {
			return true
		}
	}
	return false
}

// parseOpenRedirect parses the container's JSONL output into finding rows.
func parseOpenRedirect(stdout string) []store.OpenRedirectFindingRow {
	rows := make([]store.OpenRedirectFindingRow, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ev openRedirectEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Event != "" || ev.URL == "" || ev.Type == "" {
			continue
		}
		rows = append(rows, store.OpenRedirectFindingRow{
			URL:         ev.URL,
			Parameter:   ev.Parameter,
			Payload:     ev.Payload,
			FindingType: ev.Type,
			StatusCode:  ev.Status,
			Location:    ev.Location,
			Evidence:    ev.Evidence,
		})
	}
	return rows
}
