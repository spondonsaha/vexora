package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spondonsaha/vexora/api/internal/config"
	"github.com/spondonsaha/vexora/api/internal/db"
	"github.com/spondonsaha/vexora/api/internal/scanner"
	"github.com/spondonsaha/vexora/api/internal/store"
)

func main() {
	cfg := config.Load()

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(rootCtx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	st := store.NewPGStore(pool)
	runner := scanner.New(cfg, st)

	log.Printf("worker started (poll=%s, tool_timeout=%s, workflow_concurrency=%d, raw_dir=%s)",
		cfg.WorkerPollInterval, cfg.ToolTimeout, cfg.WorkflowMaxConcurrency, cfg.RawOutputDir)

	// Ad-hoc single-tool scans (e.g. the "Run Subfinder" button) run alongside
	// workflow execution so a queued workflow never blocks a quick manual scan.
	go jobLoop(rootCtx, cfg, st, runner)
	workflowLoop(rootCtx, cfg, st, runner)
}

func jobLoop(ctx context.Context, cfg config.Config, st store.Store, runner *scanner.Runner) {
	for {
		if ctx.Err() != nil {
			return
		}

		job, err := st.ClaimNextQueuedJob(ctx)
		if errors.Is(err, store.ErrNotFound) {
			sleepCtx(ctx, cfg.WorkerPollInterval)
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("claim job: %v", err)
			sleepCtx(ctx, cfg.WorkerPollInterval)
			continue
		}

		log.Printf("claimed job %s (tool=%s)", job.ID, job.Tool)
		result := runner.Execute(ctx, job)
		if err := st.CompleteScanJob(ctx, job.ID, result.Status, result.ExitCode, result.StdoutPath, result.StderrPath); err != nil {
			log.Printf("complete job %s: %v", job.ID, err)
		}
		if result.Err != nil {
			log.Printf("job %s %s: %v", job.ID, result.Status, result.Err)
		} else {
			log.Printf("job %s done", job.ID)
		}
	}
}

func workflowLoop(ctx context.Context, cfg config.Config, st store.Store, runner *scanner.Runner) {
	for {
		if ctx.Err() != nil {
			return
		}

		wf, err := st.ClaimNextQueuedWorkflow(ctx)
		if errors.Is(err, store.ErrNotFound) {
			sleepCtx(ctx, cfg.WorkerPollInterval)
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("claim workflow: %v", err)
			sleepCtx(ctx, cfg.WorkerPollInterval)
			continue
		}

		log.Printf("claimed workflow %s (%s)", wf.ID, wf.WorkflowType)
		if err := runner.RunWorkflow(ctx, wf); err != nil {
			log.Printf("workflow %s failed: %v", wf.ID, err)
		} else {
			log.Printf("workflow %s done", wf.ID)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
