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

// NucleiTool is the ad-hoc tool name for the nuclei vulnerability scanner.
const NucleiTool = "nuclei"

// nucleiTemplatesDir is where templates are baked into the recon/nuclei image.
const nucleiTemplatesDir = "/opt/nuclei-templates"

// nucleiMaxTargets caps how many hosts a single run will scan so a huge target
// cannot run away with the tool timeout.
const nucleiMaxTargets = 500

// NucleiCategories maps a UI category to the nuclei template tags it runs.
var NucleiCategories = map[string]string{
	"xss":       "xss",
	"cve":       "cve",
	"takeover":  "takeover",
	"misconfig": "misconfig",
	"all":       "xss,cve,takeover,misconfig",
}

type nucleiOptions struct {
	Category string `json:"category"`
}

// runNucleiAdHoc executes a standalone nuclei scan for an ad-hoc job.
func (r *Runner) runNucleiAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.NucleiEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("nuclei scanning is disabled")}
	}

	category := "all"
	var opts nucleiOptions
	if len(job.Options) > 0 {
		if err := json.Unmarshal(job.Options, &opts); err == nil && opts.Category != "" {
			category = strings.ToLower(strings.TrimSpace(opts.Category))
		}
	}
	if _, ok := NucleiCategories[category]; !ok {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: fmt.Errorf("unsupported nuclei category %q", category)}
	}

	summary, stdout, stderr, exitCode, runErr := r.runNuclei(ctx, target, root, category, job.ID)

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")
	writeRawFile(stdoutPath, stdout)
	writeRawFile(stderrPath, stderr)

	if runErr != nil {
		return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: runErr}
	}

	log.Printf("job %s: nuclei [%s] found %v finding(s) across %v host(s)",
		job.ID, category, summary["findings"], summary["hosts"])
	return Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// runNuclei gathers the target hosts for the category, runs nuclei and stores
// the parsed findings. Findings are stored even when nuclei exits non-zero
// (e.g. partial output before the tool timeout) so results are never lost.
func (r *Runner) runNuclei(ctx context.Context, target *models.ScopeTarget, root, category string, jobID uuid.UUID) (map[string]any, string, string, int, error) {
	summary := map[string]any{"category": category, "hosts": 0, "findings": 0, "stored": 0}

	targets, err := r.nucleiTargets(ctx, target, category)
	if err != nil {
		return summary, "", "", -1, err
	}
	if len(targets) == 0 {
		return summary, "", "", 0, errors.New("no targets to scan: run the wildcard workflow (or an ad-hoc subdomain tool) first")
	}
	summary["hosts"] = len(targets)

	args := []string{
		"-jsonl", "-silent", "-no-color", "-nc",
		"-t", nucleiTemplatesDir,
		"-tags", NucleiCategories[category],
		"-timeout", "5", "-retries", "1",
		"-rate-limit", "150", "-concurrency", "25",
		"-disable-update-check", "-no-interactsh",
	}

	stdout, stderr, exitCode, runErr := r.runContainerInput(ctx, jobID, r.cfg.NucleiImage, strings.Join(targets, "\n"), args...)

	rows := parseNuclei(stdout, category)
	summary["findings"] = len(rows)

	if len(rows) > 0 {
		stored, err := r.store.UpsertNucleiFindings(ctx, target.ID, jobID, rows)
		if err != nil {
			return summary, stdout, stderr, exitCode, fmt.Errorf("store nuclei findings: %w", err)
		}
		summary["stored"] = stored
	}

	if runErr != nil {
		return summary, stdout, stderr, exitCode, fmt.Errorf("nuclei: %w", runErr)
	}
	return summary, stdout, stderr, exitCode, nil
}

// nucleiTargets selects what nuclei should scan. Takeover templates operate on
// hostnames regardless of liveness, so that category uses the discovered
// subdomains; every other category scans the live web servers, falling back to
// subdomains when nothing has been probed yet.
func (r *Runner) nucleiTargets(ctx context.Context, target *models.ScopeTarget, category string) ([]string, error) {
	subs, err := r.store.ListSubdomainsByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list subdomains: %w", err)
	}
	servers, err := r.store.ListLiveWebServersByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list live servers: %w", err)
	}

	set := map[string]struct{}{}
	if category == "takeover" {
		for _, s := range subs {
			if host := strings.TrimSpace(strings.ToLower(s.Subdomain)); host != "" {
				set["https://"+host] = struct{}{}
			}
		}
	}
	for _, srv := range servers {
		if url := strings.TrimSpace(srv.URL); url != "" {
			set[url] = struct{}{}
		}
	}
	if len(set) == 0 {
		for _, s := range subs {
			if host := strings.TrimSpace(strings.ToLower(s.Subdomain)); host != "" {
				set["https://"+host] = struct{}{}
			}
		}
	}

	targets := make([]string, 0, len(set))
	for t := range set {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	if len(targets) > nucleiMaxTargets {
		log.Printf("nuclei: %d targets truncated to %d", len(targets), nucleiMaxTargets)
		targets = targets[:nucleiMaxTargets]
	}
	return targets, nil
}

type nucleiEvent struct {
	TemplateID  string   `json:"template-id"`
	Type        string   `json:"type"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched-at"`
	MatcherName string   `json:"matcher-name"`
	CurlCommand string   `json:"curl-command"`
	Extracted   []string `json:"extracted-results"`
	Info        struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Tags           []string `json:"tags"`
		Reference      []string `json:"reference"`
		Classification struct {
			CVSSScore *float64 `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
}

func parseNuclei(stdout, category string) []store.NucleiFindingRow {
	rows := make([]store.NucleiFindingRow, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ev nucleiEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.TemplateID == "" {
			continue
		}
		matchedAt := ev.MatchedAt
		if matchedAt == "" {
			matchedAt = ev.Host
		}
		if matchedAt == "" {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(ev.Info.Severity))
		if severity == "" {
			severity = "unknown"
		}
		name := ev.Info.Name
		if name == "" {
			name = ev.TemplateID
		}
		// Some templates (e.g. http-missing-security-headers) put the concrete
		// match detail in matcher-name rather than extracted-results. Fold it in
		// so it survives de-duplication and surfaces in the UI.
		extracted := emptyStrings(ev.Extracted)
		if mn := strings.TrimSpace(ev.MatcherName); mn != "" && mn != "true" && mn != "false" {
			extracted = append(extracted, mn)
		}
		rows = append(rows, store.NucleiFindingRow{
			Category:    category,
			TemplateID:  ev.TemplateID,
			Name:        name,
			Severity:    severity,
			Type:        ev.Type,
			Host:        ev.Host,
			MatchedAt:   matchedAt,
			Description: ev.Info.Description,
			Reference:   emptyStrings(ev.Info.Reference),
			Tags:        emptyStrings(ev.Info.Tags),
			Extracted:   extracted,
			CVSSScore:   ev.Info.Classification.CVSSScore,
			CurlCommand: ev.CurlCommand,
		})
	}
	return rows
}

func emptyStrings(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}
