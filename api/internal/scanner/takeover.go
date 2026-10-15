package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

// TakeoverTool is the ad-hoc tool name accepted by the scan endpoint. It is not
// a host-discovery source: it reads the already-discovered subdomains, resolves
// their CNAME chains / reverse DNS and matches them against a fingerprint DB.
const TakeoverTool = "takeover"

// runTakeoverAdHoc executes a standalone takeover scan for an ad-hoc job.
func (r *Runner) runTakeoverAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.TakeoverEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("takeover scanning is disabled")}
	}

	summary, stdout, stderr, exitCode, runErr := r.runTakeover(ctx, target, root, job.ID)

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")
	writeRawFile(stdoutPath, stdout)
	writeRawFile(stderrPath, stderr)

	result := Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}
	if runErr != nil {
		result.Status = models.ScanFailed
		result.Err = runErr
		return result
	}
	log.Printf("job %s: takeover checked %d subdomain(s): %d vulnerable, %d dangling, %d edge",
		job.ID, summary["checked"], summary["vulnerable"], summary["dangling"], summary["edge"])
	return result
}

// runTakeoverStep runs the takeover check as a workflow step (legacy workflows
// may still carry a "takeover" step). It creates a workflow-linked scan job so
// the raw output shows up in the UI just like an ad-hoc run.
func (r *Runner) runTakeoverStep(ctx context.Context, wf *models.Workflow, step models.WorkflowStep, target *models.ScopeTarget, root string) (map[string]any, error) {
	if !r.cfg.TakeoverEnabled {
		return map[string]any{"skipped": true, "reason": "takeover scanning disabled"}, nil
	}

	job, err := r.store.CreateRunningScanJob(ctx, target.ID, wf.ID, step.ID, TakeoverTool, nil)
	if err != nil {
		return nil, fmt.Errorf("create takeover job: %w", err)
	}

	summary, stdout, stderr, exitCode, runErr := r.runTakeover(ctx, target, root, job.ID)
	r.persistAndComplete(ctx, job, stdout, stderr, exitCode, runErr)
	if runErr != nil {
		return summary, fmt.Errorf("takeover: %w", runErr)
	}

	log.Printf("workflow %s: takeover checked %v subdomain(s): %v vulnerable, %v dangling, %v edge",
		wf.ID, summary["checked"], summary["vulnerable"], summary["dangling"], summary["edge"])
	return summary, nil
}

// runTakeover resolves the CNAME chain + reverse DNS for every subdomain already
// discovered for the target, stores the enrichment and returns a summary. Raw
// stdout/stderr are always written to disk so the UI can show them.
func (r *Runner) runTakeover(ctx context.Context, target *models.ScopeTarget, root string, jobID uuid.UUID) (map[string]any, string, string, int, error) {
	summary := map[string]any{
		"checked": 0, "vulnerable": 0, "dangling": 0, "edge": 0, "safe": 0, "unknown": 0, "cname": 0,
	}

	wildcardID, err := r.store.EnsureWildcardTarget(ctx, target.ID, root)
	if err != nil {
		return summary, "", "", -1, fmt.Errorf("ensure wildcard target: %w", err)
	}

	subs, err := r.store.ListSubdomainsByScopeTarget(ctx, target.ID)
	if err != nil {
		return summary, "", "", -1, fmt.Errorf("list subdomains: %w", err)
	}

	input := make([]string, 0, len(subs))
	seen := map[string]struct{}{}
	for _, s := range subs {
		host := strings.ToLower(strings.TrimSpace(s.Subdomain))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		input = append(input, host)
	}

	if len(input) == 0 {
		return summary, "", "", 0, nil
	}

	stdout, stderr, exitCode, runErr := r.runContainerInput(ctx, jobID, r.cfg.TakeoverImage, strings.Join(input, "\n"))
	if runErr != nil {
		return summary, stdout, stderr, exitCode, fmt.Errorf("takeover: %w", runErr)
	}

	rows, err := parseTakeover(stdout)
	if err != nil {
		return summary, stdout, stderr, exitCode, fmt.Errorf("parse takeover output: %w", err)
	}
	if _, err := r.store.UpdateSubdomainRecon(ctx, wildcardID, rows); err != nil {
		return summary, stdout, stderr, exitCode, fmt.Errorf("store takeover results: %w", err)
	}

	for _, row := range rows {
		summary["checked"] = summary["checked"].(int) + 1
		if row.CNAME != "" {
			summary["cname"] = summary["cname"].(int) + 1
		}
		if _, ok := summary[row.TakeoverStatus]; ok {
			summary[row.TakeoverStatus] = summary[row.TakeoverStatus].(int) + 1
		}
	}

	return summary, stdout, stderr, exitCode, nil
}

type takeoverResult struct {
	Subdomain  string   `json:"subdomain"`
	CNAME      string   `json:"cname"`
	CNAMEChain []string `json:"cname_chain"`
	ARecords   []string `json:"a_records"`
	ReverseDNS []string `json:"reverse_dns"`
	Status     string   `json:"status"`
	Service    string   `json:"service"`
	Detail     string   `json:"detail"`
}

func parseTakeover(stdout string) ([]store.SubdomainReconRow, error) {
	rows := make([]store.SubdomainReconRow, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var res takeoverResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		if res.Subdomain == "" {
			continue
		}
		rows = append(rows, store.SubdomainReconRow{
			Subdomain:       strings.ToLower(res.Subdomain),
			CNAME:           strings.ToLower(res.CNAME),
			CNAMEChain:      res.CNAMEChain,
			ARecords:        res.ARecords,
			ReverseDNS:      res.ReverseDNS,
			TakeoverStatus:  res.Status,
			TakeoverService: res.Service,
			TakeoverDetail:  res.Detail,
		})
	}
	return rows, scanner.Err()
}

func writeRawFile(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		log.Printf("write raw output %s: %v", path, err)
	}
}
