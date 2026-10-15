package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

// ScreenshotTool is the ad-hoc tool name for capturing screenshots of the live
// web servers discovered for a scope target.
const ScreenshotTool = "screenshot"

// screenshotMaxTargets caps how many live servers a single run will capture so a
// huge target cannot run away with the tool timeout.
const screenshotMaxTargets = 500

type screenshotEvent struct {
	URL               string `json:"url"`
	Input             string `json:"input"`
	Host              string `json:"host"`
	StatusCode        int    `json:"status_code"`
	ScreenshotPathRel string `json:"screenshot_path_rel"`
	ScreenshotBytes   int    `json:"screenshot_bytes"`
}

// runScreenshotAdHoc captures a headless-browser screenshot of every live web
// server for the target and stores the resulting image path on each row.
func (r *Runner) runScreenshotAdHoc(ctx context.Context, job *models.ScanJob, target *models.ScopeTarget, root string) Result {
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
		if _, ok := byURL[key]; ok {
			continue
		}
		byURL[key] = srv.ID
		urls = append(urls, u)
	}
	sort.Strings(urls)

	if len(urls) == 0 {
		return Result{Status: models.ScanFailed, ExitCode: -1,
			Err: errors.New("no live web servers to screenshot: run the wildcard workflow (or a probe) first")}
	}
	if len(urls) > screenshotMaxTargets {
		log.Printf("screenshot: %d targets truncated to %d", len(urls), screenshotMaxTargets)
		urls = urls[:screenshotMaxTargets]
	}

	hosts := make([]string, 0, len(urls))
	for _, u := range urls {
		if pu, err := url.Parse(u); err == nil && pu.Host != "" {
			hosts = append(hosts, pu.Hostname())
		}
	}
	pruneScreenshotDirs(r.cfg.RawOutputDir, hosts)

	// -esb keeps the base64 image bytes out of stdout; only the saved file path
	// is needed, and embedding the images would bloat the streamed output.
	args := []string{
		"-ss", "-json", "-silent", "-no-color", "-esb",
		"-screenshot-timeout", "15", "-timeout", "10",
	}
	stdout, stderr, exitCode, runErr := r.runContainerSharedInput(ctx, job.ID, r.cfg.HttpxImage, strings.Join(urls, "\n"), args...)

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")
	writeRawFile(stdoutPath, stdout)
	writeRawFile(stderrPath, stderr)

	// httpx creates per-host screenshot directories with mode 0700 owned by
	// root, which the non-root api container cannot traverse. Relax permissions
	// so the captured images can be served by the API.
	relaxDirPerms(filepath.Join(r.cfg.RawOutputDir, "output", "screenshot"))

	result := Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}

	shots := parseHttpxScreenshots(stdout, byURL)
	if len(shots) > 0 {
		updated, err := r.store.UpdateLiveWebServerScreenshots(ctx, shots)
		if err != nil {
			result.Status = models.ScanFailed
			result.Err = fmt.Errorf("store screenshots: %w", err)
			return result
		}
		log.Printf("job %s: screenshot captured %d live server(s) (%d stored) for %s", job.ID, len(shots), updated, root)
	}

	if runErr != nil {
		result.Status = models.ScanFailed
		result.Err = runErr
	}
	return result
}

// parseHttpxScreenshots maps each httpx JSON line to the live web server it
// belongs to, returning the screenshot path (relative to the raw output dir).
func parseHttpxScreenshots(stdout string, byURL map[string]uuid.UUID) map[uuid.UUID]string {
	shots := map[uuid.UUID]string{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ev screenshotEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		rel := strings.TrimSpace(ev.ScreenshotPathRel)
		if rel == "" {
			continue
		}
		key := normalizeURL(ev.URL)
		if key == "" {
			key = normalizeURL(ev.Input)
		}
		id, ok := byURL[key]
		if !ok {
			continue
		}
		// httpx writes to <cwd>/output/screenshot/<rel>; the container's cwd is
		// the raw output dir, so the same path is readable by the worker/api.
		shots[id] = "output/screenshot/" + strings.TrimPrefix(rel, "/")
	}
	return shots
}

// relaxDirPerms makes a directory tree readable by other users. httpx writes
// screenshot output under a root-owned 0700 directory tree, but the images must
// be readable by the non-root api container that serves them.
func relaxDirPerms(root string) {
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(path, 0o755)
			return nil
		}
		_ = os.Chmod(path, 0o644)
		return nil
	})
	if err != nil {
		log.Printf("screenshot: relax permissions under %s: %v", root, err)
	}
}

// pruneScreenshotDirs removes the per-host screenshot directories for the given
// hosts before a fresh capture. httpx appends _1, _2, ... when a screenshot hash
// already exists, so without pruning repeated runs would accumulate files.
func pruneScreenshotDirs(rawDir string, hosts []string) {
	base := filepath.Join(rawDir, "output", "screenshot")
	for _, h := range hosts {
		host := strings.TrimSpace(strings.ToLower(h))
		if host == "" {
			continue
		}
		// Guard against traversal: only ever remove a single directory name.
		name := filepath.Base(filepath.Clean(host))
		if name == "." || name == string(filepath.Separator) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(base, name))
	}
}

// normalizeURL produces a comparable form of a URL, tolerating scheme/host
// casing and a trailing slash so httpx output can be matched to stored URLs.
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimSuffix(strings.ToLower(raw), "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	if u.Path != "" {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	return u.String()
}
