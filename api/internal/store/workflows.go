package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/spondonsaha/vexora/api/internal/models"
)

const workflowCols = `id, scope_target_id, workflow_type, status, current_step, error, created_at, updated_at, finished_at`

const workflowStepCols = `id, workflow_id, step_number, step_key, title, description, status, summary, started_at, finished_at, created_at`

type WorkflowStepSeed struct {
	StepNumber  int
	StepKey     string
	Title       string
	Description string
}

// WildcardWorkflowSteps defines the §7 steps 1-3 for the wildcard workflow.
// The descriptions back the UI's "Help Me Learn!" panel.
func WildcardWorkflowSteps() []WorkflowStepSeed {
	return []WorkflowStepSeed{
		{
			StepNumber: 1,
			StepKey:    "enum",
			Title:      "Enumeration (Amass)",
			Description: "Amass maps the target's DNS footprint using passive (and optionally active) sources. " +
				"Passive enumeration mines public datasets — Certificate Transparency logs, WHOIS, public DNS — " +
				"without sending traffic to the target. Everything downstream builds on this initial surface.",
		},
		{
			StepNumber: 2,
			StepKey:    "scrape",
			Title:      "Subdomain scraping (parallel)",
			Description: "Several independent tools query public data at the same time: Subfinder (passive DNS + CT), " +
				"Assetfinder, Sublist3r, Findomain and crt.sh. Each source covers different datasets, so running them " +
				"concurrently is faster and cross-checks coverage — results are merged and deduplicated.",
		},
		{
			StepNumber: 3,
			StepKey:    "consolidate_probe",
			Title:      "Consolidate + live-server probe",
			Description: "Every discovered subdomain is deduplicated, then probed with httpx to find which actually " +
				"resolve and serve HTTP(S). Live servers get their status code, title, tech stack and headers recorded " +
				"into a single list — this is the prioritized surface you start manual testing against.",
		},
		{
			StepNumber: 4,
			StepKey:    "urls",
			Title:      "URL discovery (parallel)",
			Description: "GAU, waybackurls and Katana pull historical, archived and crawled URLs in parallel. URLs are " +
				"stored as endpoints and linked to live servers where possible. Endpoints with parameters or interesting " +
				"extensions (.json, .env, .sql, .bak, .git, ...) are flagged for manual review.",
		},
	}
}

// DomainWorkflowSteps defines the domain security audit checklist
// (DNSSEC, SPF/DKIM/DMARC, HTTP security headers/CSP, TLS).
func DomainWorkflowSteps() []WorkflowStepSeed {
	return []WorkflowStepSeed{
		{
			StepNumber: 1,
			StepKey:    "dns_config",
			Title:      "DNS records & DNSSEC",
			Description: "Records the zone's nameservers, MX, SOA, CAA and TXT configuration, verifies whether " +
				"the zone is DNSSEC-signed (DNSKEY + DS), looks for a wildcard, and attempts a full zone " +
				"transfer (AXFR) against each authoritative nameserver.",
		},
		{
			StepNumber: 2,
			StepKey:    "email_config",
			Title:      "Email security (SPF/DKIM/DMARC)",
			Description: "Checks that SPF is present and enforces a hard fail, that DMARC is published with a " +
				"restrictive policy (quarantine/reject), and looks for DKIM keys on common selectors. Also " +
				"reports MTA-STS and TLS-RPT.",
		},
		{
			StepNumber: 3,
			StepKey:    "header_config",
			Title:      "HTTP security headers & CSP",
			Description: "Fetches the site over HTTP(S) and inspects the response headers: HSTS, Content-Security-" +
				"Policy (flagging unsafe-inline / unsafe-eval / wildcards), X-Frame-Options, X-Content-Type-" +
				"Options, Referrer-Policy and Permissions-Policy, plus clickjacking protection and cookie flags.",
		},
		{
			StepNumber: 4,
			StepKey:    "tls_config",
			Title:      "TLS / SSL configuration",
			Description: "Performs a TLS handshake on port 443 and reports the negotiated protocol/cipher, " +
				"certificate issuer and expiry, whether legacy TLS 1.0/1.1 are still enabled, and whether " +
				"modern TLS 1.2/1.3 is available.",
		},
	}
}

type CreateWorkflowInput struct {
	ScopeTargetID uuid.UUID
	WorkflowType  models.WorkflowType
	Steps         []WorkflowStepSeed
}

func (s *PGStore) CreateWorkflow(ctx context.Context, in CreateWorkflowInput) (*models.Workflow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx,
		`INSERT INTO workflows (scope_target_id, workflow_type, status)
		 VALUES ($1, $2, 'queued')
		 RETURNING `+workflowCols,
		in.ScopeTargetID, string(in.WorkflowType))
	workflow, err := scanWorkflow(row)
	if err != nil {
		return nil, err
	}

	for _, step := range in.Steps {
		if _, err := tx.Exec(ctx,
			`INSERT INTO workflow_steps (workflow_id, step_number, step_key, title, description, status)
			 VALUES ($1, $2, $3, $4, $5, 'queued')`,
			workflow.ID, step.StepNumber, step.StepKey, step.Title, step.Description); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetWorkflow(ctx, workflow.ID)
}

func (s *PGStore) GetWorkflow(ctx context.Context, id uuid.UUID) (*models.Workflow, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+workflowCols+` FROM workflows WHERE id = $1`, id)
	workflow, err := scanWorkflow(row)
	if err != nil {
		return nil, err
	}
	if err := s.loadWorkflowSteps(ctx, workflow); err != nil {
		return nil, err
	}
	return workflow, nil
}

func (s *PGStore) ListWorkflowsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.Workflow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+workflowCols+` FROM workflows WHERE scope_target_id = $1 ORDER BY created_at DESC`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	workflows := make([]models.Workflow, 0)
	for rows.Next() {
		wf, err := scanWorkflow(rows)
		if err != nil {
			return nil, err
		}
		workflows = append(workflows, *wf)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range workflows {
		if err := s.loadWorkflowSteps(ctx, &workflows[i]); err != nil {
			return nil, err
		}
	}
	return workflows, nil
}

func (s *PGStore) ClaimNextQueuedWorkflow(ctx context.Context) (*models.Workflow, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE workflows SET status = 'running', updated_at = now()
		 WHERE id = (
			SELECT id FROM workflows
			WHERE status = 'queued'
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		 )
		 RETURNING `+workflowCols)
	workflow, err := scanWorkflow(row)
	if err != nil {
		return nil, err
	}
	if err := s.loadWorkflowSteps(ctx, workflow); err != nil {
		return nil, err
	}
	return workflow, nil
}

func (s *PGStore) SetWorkflowStatus(ctx context.Context, id uuid.UUID, status models.WorkflowStatus, currentStep int, errMsg *string) error {
	terminal := status == models.WorkflowDone || status == models.WorkflowFailed || status == models.WorkflowCancelled
	_, err := s.pool.Exec(ctx,
		`UPDATE workflows
		 SET status = $2, current_step = $3, error = $4, updated_at = now(),
		     finished_at = CASE WHEN $5 THEN now() ELSE finished_at END
		 WHERE id = $1`,
		id, string(status), currentStep, errMsg, terminal)
	return err
}

func (s *PGStore) StartWorkflowStep(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE workflow_steps SET status = 'running', started_at = now() WHERE id = $1`, id)
	return err
}

func (s *PGStore) FinishWorkflowStep(ctx context.Context, id uuid.UUID, status models.StepStatus, summary map[string]any) error {
	encoded := []byte("{}")
	if summary != nil {
		b, err := json.Marshal(summary)
		if err != nil {
			return err
		}
		encoded = b
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE workflow_steps SET status = $2, summary = $3, finished_at = now() WHERE id = $1`,
		id, string(status), encoded)
	return err
}

// CreateRunningScanJob records a tool invocation already owned by a running
// workflow step, so it is never picked up by the ad-hoc job queue.
func (s *PGStore) CreateRunningScanJob(ctx context.Context, scopeTargetID, workflowID, workflowStepID uuid.UUID, tool string, options map[string]any) (*models.ScanJob, error) {
	opts := "{}"
	if options != nil {
		encoded, err := json.Marshal(options)
		if err != nil {
			return nil, err
		}
		opts = string(encoded)
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO scan_jobs (scope_target_id, workflow_id, workflow_step_id, tool, status, options, started_at)
		 VALUES ($1, $2, $3, $4, 'running', $5, now())
		 RETURNING `+scanJobCols,
		scopeTargetID, workflowID, workflowStepID, tool, opts)
	return scanScanJob(row)
}

func (s *PGStore) loadWorkflowSteps(ctx context.Context, workflow *models.Workflow) error {
	rows, err := s.pool.Query(ctx,
		`SELECT `+workflowStepCols+` FROM workflow_steps WHERE workflow_id = $1 ORDER BY step_number`,
		workflow.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	steps := make([]models.WorkflowStep, 0)
	index := map[uuid.UUID]int{}
	for rows.Next() {
		step, err := scanWorkflowStep(rows)
		if err != nil {
			return err
		}
		index[step.ID] = len(steps)
		steps = append(steps, *step)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	jobRows, err := s.pool.Query(ctx,
		`SELECT `+scanJobCols+` FROM scan_jobs WHERE workflow_id = $1 ORDER BY created_at`,
		workflow.ID)
	if err != nil {
		return err
	}
	defer jobRows.Close()
	for jobRows.Next() {
		job, err := scanScanJob(jobRows)
		if err != nil {
			return err
		}
		if job.WorkflowStepID == nil {
			continue
		}
		if i, ok := index[*job.WorkflowStepID]; ok {
			steps[i].Jobs = append(steps[i].Jobs, *job)
		}
	}
	if err := jobRows.Err(); err != nil {
		return err
	}

	workflow.Steps = steps
	return nil
}

func scanWorkflow(row pgx.Row) (*models.Workflow, error) {
	var (
		wf     models.Workflow
		wtype  string
		status string
	)
	err := row.Scan(&wf.ID, &wf.ScopeTargetID, &wtype, &status, &wf.CurrentStep,
		&wf.Error, &wf.CreatedAt, &wf.UpdatedAt, &wf.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	wf.WorkflowType = models.WorkflowType(wtype)
	wf.Status = models.WorkflowStatus(status)
	return &wf, nil
}

func scanWorkflowStep(row pgx.Row) (*models.WorkflowStep, error) {
	var (
		step   models.WorkflowStep
		status string
		summ   []byte
	)
	err := row.Scan(&step.ID, &step.WorkflowID, &step.StepNumber, &step.StepKey,
		&step.Title, &step.Description, &status, &summ, &step.StartedAt,
		&step.FinishedAt, &step.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	step.Status = models.StepStatus(status)
	if len(summ) > 0 {
		step.Summary = json.RawMessage(summ)
	} else {
		step.Summary = json.RawMessage("{}")
	}
	return &step, nil
}
