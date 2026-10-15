package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

// RunWorkflow executes a claimed workflow one step at a time, updating per-step
// status so the UI stepper can render progress live.
func (r *Runner) RunWorkflow(ctx context.Context, wf *models.Workflow) error {
	target, err := r.store.GetScopeTarget(ctx, wf.ScopeTargetID)
	if err != nil {
		msg := fmt.Sprintf("load target: %v", err)
		_ = r.store.SetWorkflowStatus(ctx, wf.ID, models.WorkflowFailed, wf.CurrentStep, &msg)
		return err
	}

	root := rootDomain(target.Value)
	if root == "" {
		msg := "could not derive a root domain from the target value"
		_ = r.store.SetWorkflowStatus(ctx, wf.ID, models.WorkflowFailed, wf.CurrentStep, &msg)
		return fmt.Errorf("%s", msg)
	}

	for _, step := range wf.Steps {
		_ = r.store.StartWorkflowStep(ctx, step.ID)
		_ = r.store.SetWorkflowStatus(ctx, wf.ID, models.WorkflowRunning, step.StepNumber, nil)

		var (
			summary map[string]any
			stepErr error
		)
		switch step.StepKey {
		case "enum":
			summary, stepErr = r.runDiscoveryStep(ctx, wf, step, target, root, r.enumSources(root))
		case "scrape":
			summary, stepErr = r.runDiscoveryStep(ctx, wf, step, target, root, r.scrapeSources(root))
		case "consolidate_probe":
			summary, stepErr = r.runProbeStep(ctx, wf, step, target, root)
		case "urls":
			summary, stepErr = r.runURLStep(ctx, wf, step, target, root)
		case "takeover":
			summary, stepErr = r.runTakeoverStep(ctx, wf, step, target, root)
		case "dns_config", "email_config", "header_config", "tls_config":
			summary, stepErr = r.runAuditStep(ctx, wf, step, target, root)
		default:
			stepErr = fmt.Errorf("unknown workflow step %q", step.StepKey)
		}

		if stepErr != nil {
			_ = r.store.FinishWorkflowStep(ctx, step.ID, models.StepFailed, summary)
			msg := stepErr.Error()
			_ = r.store.SetWorkflowStatus(ctx, wf.ID, models.WorkflowFailed, step.StepNumber, &msg)
			return stepErr
		}
		_ = r.store.FinishWorkflowStep(ctx, step.ID, models.StepDone, summary)
	}

	_ = r.store.SetWorkflowStatus(ctx, wf.ID, models.WorkflowDone, len(wf.Steps), nil)
	return nil
}

// runDiscoveryStep runs a set of host sources concurrently (one container each)
// and persists every host they return.
func (r *Runner) runDiscoveryStep(ctx context.Context, wf *models.Workflow, step models.WorkflowStep, target *models.ScopeTarget, root string, sources []toolSource) (map[string]any, error) {
	if len(sources) == 0 {
		return map[string]any{"sources": map[string]int{}, "total": 0}, nil
	}

	wildcardID, err := r.store.EnsureWildcardTarget(ctx, target.ID, root)
	if err != nil {
		return nil, fmt.Errorf("ensure wildcard target: %w", err)
	}

	results := r.runSourcesConcurrent(ctx, wf, step, target, root, sources)

	summary := map[string]any{}
	bySource := map[string]int{}
	errs := map[string]string{}
	all := map[string]struct{}{}
	for _, res := range results {
		bySource[res.name] = len(res.hosts)
		for _, h := range res.hosts {
			all[h] = struct{}{}
		}
		if res.err != nil {
			errs[res.name] = res.err.Error()
		}
	}

	unique := make([]string, 0, len(all))
	for h := range all {
		unique = append(unique, h)
	}
	if _, err := r.store.UpsertSubdomains(ctx, wildcardID, "merged", unique); err != nil {
		return summary, fmt.Errorf("store subdomains: %w", err)
	}

	summary["sources"] = bySource
	summary["total"] = len(unique)
	if len(errs) > 0 {
		summary["errors"] = errs
	}
	return summary, nil
}

type sourceResult struct {
	name     string
	hosts    []string
	urls     []string
	exitCode int
	err      error
}

func (r *Runner) runSourcesConcurrent(ctx context.Context, wf *models.Workflow, step models.WorkflowStep, target *models.ScopeTarget, root string, sources []toolSource) []sourceResult {
	limit := r.cfg.WorkflowMaxConcurrency
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	results := make([]sourceResult, len(sources))
	var wg sync.WaitGroup

	for i, src := range sources {
		wg.Add(1)
		go func(i int, src toolSource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = r.runSource(ctx, wf, step, target, root, src)
		}(i, src)
	}
	wg.Wait()
	return results
}

func (r *Runner) runSource(ctx context.Context, wf *models.Workflow, step models.WorkflowStep, target *models.ScopeTarget, root string, src toolSource) sourceResult {
	res := sourceResult{name: src.Name}
	args := src.Args(root)

	job, err := r.store.CreateRunningScanJob(ctx, target.ID, wf.ID, step.ID, src.Name, map[string]any{"args": args})
	if err != nil {
		res.err = fmt.Errorf("create job: %w", err)
		return res
	}

	stdout, stderr, exitCode, runErr := r.runContainer(ctx, job.ID, src.Image, args...)
	r.persistAndComplete(ctx, job, stdout, stderr, exitCode, runErr)

	res.exitCode = exitCode
	// Parse whatever the tool managed to emit even when it errored or was
	// killed at the deadline: URL-discovery tools stream results and a timeout
	// still leaves a useful partial set. Dropping it here is what made long
	// runs report 0.
	res.hosts = dedupe(src.Parse(stdout, root))
	if src.ParseURLs != nil {
		res.urls = dedupe(src.ParseURLs(stdout, root))
	}
	if runErr != nil {
		res.err = fmt.Errorf("%s: %w", src.Name, runErr)
	}
	log.Printf("workflow %s: %s returned %d host(s) and %d url(s) for %s", wf.ID, src.Name, len(res.hosts), len(res.urls), root)
	return res
}

// runProbeStep consolidates all known subdomains and probes them with httpx.
func (r *Runner) runProbeStep(ctx context.Context, wf *models.Workflow, step models.WorkflowStep, target *models.ScopeTarget, root string) (map[string]any, error) {
	if _, err := r.store.EnsureWildcardTarget(ctx, target.ID, root); err != nil {
		return nil, fmt.Errorf("ensure wildcard target: %w", err)
	}

	subs, err := r.store.ListSubdomainsByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list subdomains: %w", err)
	}

	input := make([]string, 0, len(subs))
	idByHost := make(map[string]uuid.UUID, len(subs))
	seen := map[string]struct{}{}
	for _, s := range subs {
		host := strings.ToLower(s.Subdomain)
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		input = append(input, host)
		idByHost[host] = s.ID
	}

	summary := map[string]any{"probed": 0, "live": 0}
	if len(input) == 0 {
		return summary, nil
	}

	// -ss captures a screenshot of every live server (spec §8/§9); -esb keeps the
	// base64 image bytes out of stdout. The container shares the raw output volume
	// so the images persist for the worker/api.
	args := []string{"-silent", "-json", "-sc", "-title", "-tech-detect", "-follow-redirects", "-timeout", "10", "-ss", "-esb", "-screenshot-timeout", "15"}
	pruneScreenshotDirs(r.cfg.RawOutputDir, input)
	job, err := r.store.CreateRunningScanJob(ctx, target.ID, wf.ID, step.ID, "httpx", map[string]any{"args": args})
	if err != nil {
		return summary, fmt.Errorf("create httpx job: %w", err)
	}

	stdout, stderr, exitCode, runErr := r.runContainerSharedInput(ctx, job.ID, r.cfg.HttpxImage, strings.Join(input, "\n"), args...)
	relaxDirPerms(filepath.Join(r.cfg.RawOutputDir, "output", "screenshot"))
	r.persistAndComplete(ctx, job, stdout, stderr, exitCode, runErr)
	if runErr != nil {
		return summary, fmt.Errorf("httpx: %w", runErr)
	}

	rows, err := parseHttpx(stdout, idByHost)
	if err != nil {
		return summary, err
	}
	affected, err := r.store.UpsertLiveWebServers(ctx, rows)
	if err != nil {
		return summary, fmt.Errorf("store live servers: %w", err)
	}

	summary["probed"] = len(input)
	summary["live"] = len(rows)
	log.Printf("workflow %s: probed %d subdomain(s), %d live (%d upserted)", wf.ID, len(input), len(rows), affected)
	return summary, nil
}

// runURLStep discovers historical and crawled URLs (§8) with several tools in
// parallel, stores them as endpoints (linking to a live server when the host is
// serving), and flags the "interesting" ones for manual review.
func (r *Runner) runURLStep(ctx context.Context, wf *models.Workflow, step models.WorkflowStep, target *models.ScopeTarget, root string) (map[string]any, error) {
	wildcardID, err := r.store.EnsureWildcardTarget(ctx, target.ID, root)
	if err != nil {
		return nil, fmt.Errorf("ensure wildcard target: %w", err)
	}

	sources := r.urlSources(root)
	summary := map[string]any{"sources": map[string]int{}, "hosts": 0, "urls": 0, "interesting": 0}
	if len(sources) == 0 {
		return summary, nil
	}

	results := r.runSourcesConcurrent(ctx, wf, step, target, root, sources)

	bySource := map[string]int{}
	hostSet := map[string]struct{}{}
	urlList := make([]string, 0)
	urlTool := map[string]string{}
	errs := map[string]string{}
	for _, res := range results {
		bySource[res.name] = len(res.urls)
		for _, h := range res.hosts {
			hostSet[h] = struct{}{}
		}
		for _, u := range res.urls {
			if _, ok := urlTool[u]; ok {
				continue
			}
			urlTool[u] = res.name
			urlList = append(urlList, u)
		}
		if res.err != nil {
			errs[res.name] = res.err.Error()
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	if _, err := r.store.UpsertSubdomains(ctx, wildcardID, "urls", hosts); err != nil {
		return summary, fmt.Errorf("store subdomains: %w", err)
	}
	summary["sources"] = bySource
	summary["hosts"] = len(hosts)

	servers, err := r.store.ListLiveWebServersByScopeTarget(ctx, target.ID)
	if err != nil {
		return summary, fmt.Errorf("list live servers: %w", err)
	}
	lwsByHost := map[string]uuid.UUID{}
	for _, srv := range servers {
		if u, err := url.Parse(srv.URL); err == nil && u.Hostname() != "" {
			lwsByHost[strings.ToLower(u.Hostname())] = srv.ID
		}
	}

	rows := make([]store.EndpointRow, 0, len(urlList))
	interesting := 0
	for _, raw := range urlList {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		isInteresting := store.InterestingURL(raw)
		if isInteresting {
			interesting++
		}
		var lwsID *uuid.UUID
		if id, ok := lwsByHost[host]; ok {
			idCopy := id
			lwsID = &idCopy
		}
		wtID := wildcardID
		tool := urlTool[raw]
		rows = append(rows, store.EndpointRow{
			LiveWebServerID:  lwsID,
			WildcardTargetID: &wtID,
			Host:             host,
			URL:              raw,
			Path:             path,
			SourceTool:       tool,
			Interesting:      isInteresting,
		})
	}

	if _, err := r.store.UpsertEndpoints(ctx, rows); err != nil {
		return summary, fmt.Errorf("store endpoints: %w", err)
	}

	summary["urls"] = len(rows)
	summary["interesting"] = interesting
	if len(errs) > 0 {
		summary["errors"] = errs
	}
	log.Printf("workflow %s: url discovery found %d host(s), %d url(s) (%d interesting)", wf.ID, len(hosts), len(rows), interesting)
	return summary, nil
}

// auditSections maps a domain-audit workflow step key to the audit.py section.
var auditSections = map[string]string{
	"dns_config":    "dns",
	"email_config":  "email",
	"header_config": "headers",
	"tls_config":    "tls",
}

// runAuditStep runs one domain/DNS security audit section and stores the JSON
// report as the step summary so the UI can render the checks and score.
func (r *Runner) runAuditStep(ctx context.Context, wf *models.Workflow, step models.WorkflowStep, target *models.ScopeTarget, root string) (map[string]any, error) {
	section, ok := auditSections[step.StepKey]
	if !ok {
		return nil, fmt.Errorf("unknown audit step %q", step.StepKey)
	}

	args := []string{section, root}
	job, err := r.store.CreateRunningScanJob(ctx, target.ID, wf.ID, step.ID, "domainaudit-"+section, map[string]any{"args": args})
	if err != nil {
		return nil, fmt.Errorf("create job: %w", err)
	}

	stdout, stderr, exitCode, runErr := r.runContainer(ctx, job.ID, r.cfg.DomainAuditImage, args...)
	r.persistAndComplete(ctx, job, stdout, stderr, exitCode, runErr)
	if runErr != nil {
		return map[string]any{"error": runErr.Error()}, fmt.Errorf("domain audit %s: %w", section, runErr)
	}

	summary, err := parseAuditReport(stdout)
	if err != nil {
		return map[string]any{"error": "unparseable audit output"}, fmt.Errorf("parse domain audit %s: %w", section, err)
	}
	score, _ := summary["score"]
	log.Printf("workflow %s: domain audit %s score=%v", wf.ID, section, score)
	return summary, nil
}

func parseAuditReport(stdout string) (map[string]any, error) {
	start := strings.IndexByte(stdout, '{')
	end := strings.LastIndexByte(stdout, '}')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON object in audit output")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout[start:end+1]), &report); err != nil {
		return nil, err
	}
	return report, nil
}

type httpxResult struct {
	URL               string   `json:"url"`
	Input             string   `json:"input"`
	Host              string   `json:"host"`
	HostIP            string   `json:"host_ip"`
	StatusCode        int      `json:"status_code"`
	Title             string   `json:"title"`
	Tech              []string `json:"tech"`
	ContentLength     int64    `json:"content_length"`
	A                 []string `json:"a"`
	ScreenshotPathRel string   `json:"screenshot_path_rel"`
}

func parseHttpx(stdout string, idByHost map[string]uuid.UUID) ([]store.LiveWebServerRow, error) {
	rows := make([]store.LiveWebServerRow, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var res httpxResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		host := strings.ToLower(res.Input)
		if host == "" {
			host = strings.ToLower(res.Host)
		}

		var subID *uuid.UUID
		if id, ok := idByHost[host]; ok {
			idCopy := id
			subID = &idCopy
		}

		status := res.StatusCode
		length := res.ContentLength
		tech, _ := json.Marshal(res.Tech)
		var ip *string
		if res.HostIP != "" {
			ipCopy := res.HostIP
			ip = &ipCopy
		}
		var title *string
		if res.Title != "" {
			tCopy := res.Title
			title = &tCopy
		}
		var shot *string
		if rel := strings.TrimSpace(res.ScreenshotPathRel); rel != "" {
			p := "output/screenshot/" + strings.TrimPrefix(rel, "/")
			shot = &p
		}

		rows = append(rows, store.LiveWebServerRow{
			SubdomainID:    subID,
			IP:             ip,
			URL:            res.URL,
			StatusCode:     &status,
			Title:          title,
			ContentLength:  &length,
			TechStack:      tech,
			Headers:        json.RawMessage("{}"),
			TLS:            json.RawMessage("{}"),
			ScreenshotPath: shot,
		})
	}
	return rows, scanner.Err()
}

func (r *Runner) persistAndComplete(ctx context.Context, job *models.ScanJob, stdout, stderr string, exitCode int, runErr error) {
	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		log.Printf("job %s: write stdout: %v", job.ID, err)
	}
	if err := os.WriteFile(stderrPath, []byte(stderr), 0o644); err != nil {
		log.Printf("job %s: write stderr: %v", job.ID, err)
	}

	status := models.ScanDone
	if runErr != nil {
		status = models.ScanFailed
	}
	if err := r.store.CompleteScanJob(ctx, job.ID, status, exitCode, stdoutPath, stderrPath); err != nil {
		log.Printf("complete job %s: %v", job.ID, err)
	}
}

func dedupe(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
