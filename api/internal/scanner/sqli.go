package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

// SQLiTool is the ad-hoc tool name for automated SQL-injection testing with
// sqlmap. It targets discovered parameterised URLs (query strings) for a scope
// target and can optionally crawl forms / links on live servers.
const SQLiTool = "sqli"

// SQLiDefaultTechniques is the full sqlmap technique set:
// B boolean-based blind, E error-based, U union-based (UNION query),
// S stacked queries, T time-based blind, Q inline queries.
const SQLiDefaultTechniques = "BEUSTQ"

// sqlmapTechniqueLetters are the characters allowed in a technique selection.
const sqlmapTechniqueLetters = SQLiDefaultTechniques

// sqliOptions are the advanced sqlmap knobs accepted from the API/UI.
type sqliOptions struct {
	Technique string `json:"technique"`
	Level     int    `json:"level"`
	Risk      int    `json:"risk"`
	Threads   int    `json:"threads"`
	Tamper    string `json:"tamper"`
	DBMS      string `json:"dbms"`
	Forms     bool   `json:"forms"`
	Crawl     int    `json:"crawl"`
}

// ValidSQLiTechnique reports whether t is a non-empty subset of the sqlmap
// technique letters BEUSTQ.
func ValidSQLiTechnique(t string) bool {
	if t == "" {
		return false
	}
	for _, c := range t {
		if !strings.ContainsRune(sqlmapTechniqueLetters, c) {
			return false
		}
	}
	return true
}

// runSQLiAdHoc executes a standalone sqlmap run for an ad-hoc job.
func (r *Runner) runSQLiAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
	if !r.cfg.SQLiEnabled {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("sql injection scanning is disabled")}
	}

	opts := normalizeSQLiOptions(job.Options)

	targets, err := r.sqlmapTargets(ctx, target, opts)
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: err}
	}

	var out, errOut strings.Builder
	out.WriteString("=== sqlmap (SQL injection) ===\n")
	fmt.Fprintf(&out, "technique=%s level=%d risk=%d threads=%d forms=%t crawl=%d",
		opts.Technique, opts.Level, opts.Risk, opts.Threads, opts.Forms, opts.Crawl)
	if opts.Tamper != "" {
		fmt.Fprintf(&out, " tamper=%s", opts.Tamper)
	}
	if opts.DBMS != "" {
		fmt.Fprintf(&out, " dbms=%s", opts.DBMS)
	}
	fmt.Fprintf(&out, "\nscanning %d target URL(s)\n", len(targets))

	rows := make([]store.SQLiFindingRow, 0)
	exitCode := 0
	scanned := 0
	var lastErr error
	for _, url := range targets {
		out.WriteString("\n=== sqlmap: " + url + " ===\n")
		args := buildSQLMapArgs(opts, url)
		stdout, stderr, code, runErr := r.runContainerInput(ctx, job.ID, r.cfg.SQLMapImage, "", args...)
		out.WriteString(stdout)
		if stderr != "" {
			errOut.WriteString(stderr)
		}
		if runErr != nil {
			exitCode = code
			lastErr = runErr
			fmt.Fprintf(&out, "\n[sqlmap failed: %v]\n", runErr)
			continue
		}
		scanned++
		rows = append(rows, parseSQLMap(url, stdout)...)
	}

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")
	writeRawFile(stdoutPath, out.String())
	writeRawFile(stderrPath, errOut.String())

	if scanned == 0 && lastErr != nil {
		return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: lastErr}
	}

	stored := 0
	if len(rows) > 0 {
		stored, err = r.store.UpsertSQLiFindings(ctx, target.ID, job.ID, rows)
		if err != nil {
			return Result{Status: models.ScanFailed, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath, Err: fmt.Errorf("store sqli findings: %w", err)}
		}
	}

	log.Printf("job %s: sqli scanned %d/%d target(s), %d finding(s) persisted", job.ID, scanned, len(targets), stored)
	return Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}
}

// normalizeSQLiOptions applies safe defaults and clamps values into sqlmap's
// accepted ranges. The API validates the same ranges, but the worker re-checks
// so a malformed job can never run sqlmap with an out-of-range option.
func normalizeSQLiOptions(raw json.RawMessage) sqliOptions {
	opts := sqliOptions{Technique: SQLiDefaultTechniques, Level: 1, Risk: 1, Threads: 4}
	if len(raw) == 0 {
		return opts
	}
	var parsed sqliOptions
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return opts
	}
	if t := strings.ToUpper(strings.TrimSpace(parsed.Technique)); ValidSQLiTechnique(t) {
		opts.Technique = t
	}
	if parsed.Level >= 1 && parsed.Level <= 5 {
		opts.Level = parsed.Level
	}
	if parsed.Risk >= 1 && parsed.Risk <= 3 {
		opts.Risk = parsed.Risk
	}
	if parsed.Threads >= 1 && parsed.Threads <= 10 {
		opts.Threads = parsed.Threads
	}
	opts.Tamper = strings.TrimSpace(parsed.Tamper)
	opts.DBMS = strings.TrimSpace(parsed.DBMS)
	opts.Forms = parsed.Forms
	if parsed.Crawl >= 0 && parsed.Crawl <= 5 {
		opts.Crawl = parsed.Crawl
	}
	return opts
}

// buildSQLMapArgs assembles a batch, non-interactive sqlmap invocation for one
// target URL.
func buildSQLMapArgs(opts sqliOptions, url string) []string {
	args := []string{
		"-u", url,
		"--batch",
		"--disable-coloring",
		"--flush-session",
		"--output-dir", "/tmp/sqlmap",
		"--technique", opts.Technique,
		"--level", strconv.Itoa(opts.Level),
		"--risk", strconv.Itoa(opts.Risk),
		"--threads", strconv.Itoa(opts.Threads),
		"--random-agent",
		"--timeout", "10",
		"--retries", "1",
	}
	if opts.Tamper != "" {
		args = append(args, "--tamper", opts.Tamper)
	}
	if opts.DBMS != "" {
		args = append(args, "--dbms", opts.DBMS)
	}
	if opts.Forms {
		args = append(args, "--forms")
	}
	if opts.Crawl > 0 {
		args = append(args, "--crawl", strconv.Itoa(opts.Crawl))
	}
	return args
}

// sqlmapTargets selects the URLs to test. Parameterised (query-string)
// endpoints discovered by the wildcard workflow are preferred; when none exist
// and form crawling / link crawling is enabled it falls back to live web
// servers.
func (r *Runner) sqlmapTargets(ctx context.Context, target *models.ScopeTarget, opts sqliOptions) ([]string, error) {
	endpoints, err := r.store.ListEndpointsByScopeTarget(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}

	seen := map[string]struct{}{}
	parameterised := make([]string, 0)
	for _, ep := range endpoints {
		if ep.URL == nil {
			continue
		}
		u := strings.TrimSpace(*ep.URL)
		if u == "" || !strings.Contains(u, "?") {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		parameterised = append(parameterised, u)
	}
	sort.Strings(parameterised)

	candidates := parameterised
	if len(candidates) == 0 && (opts.Forms || opts.Crawl > 0) {
		servers, err := r.store.ListLiveWebServersByScopeTarget(ctx, target.ID)
		if err != nil {
			return nil, fmt.Errorf("list live servers: %w", err)
		}
		for _, s := range servers {
			u := strings.TrimSpace(s.URL)
			if u == "" {
				continue
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			candidates = append(candidates, u)
		}
		sort.Strings(candidates)
	}

	if len(candidates) == 0 {
		return nil, errors.New("no parameterised URLs to test: run the wildcard workflow to discover endpoints, or enable form crawling")
	}
	if len(candidates) > r.cfg.SQLiMaxTargets {
		log.Printf("sqli: %d target(s) truncated to %d", len(candidates), r.cfg.SQLiMaxTargets)
		candidates = candidates[:r.cfg.SQLiMaxTargets]
	}
	return candidates, nil
}

// parseSQLMap extracts injection points from a single sqlmap stdout. sqlmap
// prints one summary block per injectable parameter, and a single parameter may
// carry several techniques:
//
//	Parameter: id (GET)
//	    Type: boolean-based blind
//	    Title: AND boolean-based blind - WHERE or HAVING clause
//	    Payload: id=1 AND 1234=1234
//
//	    Type: time-based blind
//	    Title: MySQL >= 5.0.12 AND time-based blind
//	    Payload: id=1 AND SLEEP(5)
//
//	back-end DBMS: MySQL >= 5.0.12
//
// Each "Type:" begins a new injection point; Title/Payload attach to the most
// recent one.
func parseSQLMap(url, stdout string) []store.SQLiFindingRow {
	rows := make([]store.SQLiFindingRow, 0)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var (
		curParam  string
		curMethod string
		cur       *store.SQLiFindingRow
		dbms      string
	)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "back-end dbms:"):
			dbms = strings.TrimSpace(line[len("back-end DBMS:"):])
		case strings.HasPrefix(lower, "parameter:"):
			curParam, curMethod = parseSQLMapParameter(line)
			cur = nil
		case strings.HasPrefix(lower, "type:"):
			rows = append(rows, store.SQLiFindingRow{
				URL:       url,
				Parameter: curParam,
				Method:    curMethod,
				Technique: strings.TrimSpace(line[len("Type:"):]),
			})
			cur = &rows[len(rows)-1]
		case cur != nil && strings.HasPrefix(lower, "title:"):
			cur.Title = strings.TrimSpace(line[len("Title:"):])
		case cur != nil && strings.HasPrefix(lower, "payload:"):
			cur.Payload = strings.TrimSpace(line[len("Payload:"):])
		}
	}
	for i := range rows {
		rows[i].DBMS = dbms
	}
	return rows
}

// parseSQLMapParameter splits "Parameter: id (GET)" into its parameter name and
// the injection context (e.g. GET, POST, URI, Cookie).
func parseSQLMapParameter(line string) (string, string) {
	v := strings.TrimSpace(line[len("Parameter:"):])
	method := ""
	if i := strings.LastIndexByte(v, '('); i >= 0 {
		method = strings.TrimSpace(strings.Trim(v[i+1:], "() "))
		v = strings.TrimSpace(v[:i])
	}
	return v, method
}
