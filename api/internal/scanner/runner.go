package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/config"
	"github.com/spondonsaha/vexora/api/internal/models"
	"github.com/spondonsaha/vexora/api/internal/store"
)

type Runner struct {
	cfg   config.Config
	store store.Store
}

func New(cfg config.Config, st store.Store) *Runner {
	return &Runner{cfg: cfg, store: st}
}

type Result struct {
	Status     models.ScanJobStatus
	ExitCode   int
	StdoutPath string
	StderrPath string
	Err        error
}

func (r *Runner) Execute(ctx context.Context, job *models.ScanJob) Result {
	target, err := r.store.GetScopeTarget(ctx, job.ScopeTargetID)
	if err != nil {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: fmt.Errorf("load target: %w", err)}
	}

	root := rootDomain(target.Value)
	if root == "" {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: errors.New("could not derive root domain from target value")}
	}

	if job.Tool == TakeoverTool {
		return r.runTakeoverAdHoc(ctx, job, target, root)
	}

	if job.Tool == ScreenshotTool {
		return r.runScreenshotAdHoc(ctx, job, target, root)
	}

	if job.Tool == NucleiTool {
		return r.runNucleiAdHoc(ctx, job, target, root)
	}

	if job.Tool == NetworkTool {
		return r.runNetworkAdHoc(ctx, job, target, root)
	}

	if job.Tool == SQLiTool {
		return r.runSQLiAdHoc(ctx, job, target, root)
	}

	if job.Tool == JSReconTool {
		return r.runJSReconAdHoc(ctx, job, target, root)
	}

	if job.Tool == OpenRedirectTool {
		return r.runOpenRedirectAdHoc(ctx, job, target, root)
	}

	if job.Tool == SSRFTool {
		return r.runSSRFAdHoc(ctx, job, target, root)
	}

	if job.Tool == TechnologyTool {
		return r.runTechnologyAdHoc(ctx, job, target, root)
	}

	if job.Tool == WhatWebTool {
		return r.runWhatWebAdHoc(ctx, job, target, root)
	}

	if job.Tool == WPScanTool {
		return r.runWPScanAdHoc(ctx, job, target, root)
	}

	if job.Tool == CMSeeKTool {
		return r.runCMSeeKAdHoc(ctx, job, target, root)
	}

	if job.Tool == WhoisTool {
		return r.runWhoisAdHoc(ctx, job, target, root)
	}

	src, ok := r.sourceByName(job.Tool, root)
	if !ok {
		return Result{Status: models.ScanFailed, ExitCode: -1, Err: fmt.Errorf("unsupported tool %q", job.Tool)}
	}

	return r.runHostTool(ctx, job, root, src)
}

// sourceByName resolves a single ad-hoc host-discovery tool (subfinder, amass,
// assetfinder, sublist3r, findomain, ct, gau, waybackurls, katana) from the same
// registries the wildcard workflow uses.
func (r *Runner) sourceByName(name, root string) (toolSource, bool) {
	all := append(r.enumSources(root), r.scrapeSources(root)...)
	all = append(all, r.urlSources(root)...)
	for _, src := range all {
		if src.Name == name {
			return src, true
		}
	}
	return toolSource{}, false
}

func (r *Runner) runHostTool(ctx context.Context, job *models.ScanJob, root string, src toolSource) Result {
	args := src.Args(root)
	stdout, stderr, exitCode, runErr := r.runContainer(ctx, job.ID, src.Image, args...)

	stdoutPath := r.rawPath(job.ID, "out")
	stderrPath := r.rawPath(job.ID, "err")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		log.Printf("job %s: write stdout: %v", job.ID, err)
	}
	if err := os.WriteFile(stderrPath, []byte(stderr), 0o644); err != nil {
		log.Printf("job %s: write stderr: %v", job.ID, err)
	}

	result := Result{Status: models.ScanDone, ExitCode: exitCode, StdoutPath: stdoutPath, StderrPath: stderrPath}

	// Persist partial output even if the tool errored or timed out, so a streamed
	// run that hit the deadline still contributes the hosts it found.
	hosts := dedupe(src.Parse(stdout, root))
	wildcardID, err := r.store.EnsureWildcardTarget(ctx, job.ScopeTargetID, root)
	if err != nil {
		result.Status = models.ScanFailed
		result.Err = fmt.Errorf("ensure wildcard target: %w", err)
		return result
	}

	added, err := r.store.UpsertSubdomains(ctx, wildcardID, job.Tool, hosts)
	if err != nil {
		result.Status = models.ScanFailed
		result.Err = fmt.Errorf("store subdomains: %w", err)
		return result
	}
	log.Printf("job %s: %s found %d subdomains (%d upserted) for %s", job.ID, job.Tool, len(hosts), added, root)

	if runErr != nil {
		result.Status = models.ScanFailed
		result.Err = runErr
	}
	return result
}

func (r *Runner) runContainer(ctx context.Context, jobID uuid.UUID, image string, args ...string) (string, string, int, error) {
	return r.runContainerInput(ctx, jobID, image, "", args...)
}

func (r *Runner) runContainerInput(ctx context.Context, jobID uuid.UUID, image, stdin string, args ...string) (string, string, int, error) {
	return r.runContainerExtra(ctx, jobID, image, stdin, nil, args...)
}

// runContainerSharedInput runs a tool container that shares the worker's raw
// output volume (via --volumes-from) and uses it as the working directory, so
// files written by the tool (e.g. screenshots) persist for the worker and API.
func (r *Runner) runContainerSharedInput(ctx context.Context, jobID uuid.UUID, image, stdin string, args ...string) (string, string, int, error) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "", "", -1, fmt.Errorf("resolve worker hostname for volume share: %w", err)
	}
	extra := []string{"--volumes-from", host, "-w", r.cfg.RawOutputDir}
	return r.runContainerExtra(ctx, jobID, image, stdin, extra, args...)
}

func (r *Runner) runContainerExtra(ctx context.Context, jobID uuid.UUID, image, stdin string, extra []string, args ...string) (string, string, int, error) {
	runCtx, cancel := context.WithTimeout(ctx, r.cfg.ToolTimeout)
	defer cancel()

	dockerArgs := []string{"run", "--rm"}
	if stdin != "" {
		dockerArgs = append(dockerArgs, "-i")
	}
	dockerArgs = append(dockerArgs, extra...)
	dockerArgs = append(dockerArgs, image)
	dockerArgs = append(dockerArgs, args...)
	cmd := exec.CommandContext(runCtx, r.cfg.DockerBin, dockerArgs...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	log.Printf("job %s: running %s %s", jobID, r.cfg.DockerBin, strings.Join(dockerArgs, " "))

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
		if runCtx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("tool timed out after %s", r.cfg.ToolTimeout)
		}
	}
	return stdout.String(), stderr.String(), exitCode, err
}

func (r *Runner) rawPath(jobID uuid.UUID, ext string) string {
	if err := os.MkdirAll(r.cfg.RawOutputDir, 0o750); err != nil {
		log.Printf("create raw dir: %v", err)
	}
	return filepath.Join(r.cfg.RawOutputDir, fmt.Sprintf("%s.%s", jobID, ext))
}

func rootDomain(value string) string {
	v := strings.TrimSpace(strings.ToLower(value))
	v = strings.TrimPrefix(v, "*.")
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/:?#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
