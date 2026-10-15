package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/spondonsaha/vexora/api/internal/models"
)

const scanJobCols = `id, scope_target_id, workflow_id, workflow_step_id, tool, status, options, started_at, finished_at, stdout_path, stderr_path, exit_code, created_at`

func (s *PGStore) CreateScanJob(ctx context.Context, in CreateScanJobInput) (*models.ScanJob, error) {
	options := "{}"
	if in.Options != nil {
		encoded, err := json.Marshal(in.Options)
		if err != nil {
			return nil, err
		}
		options = string(encoded)
	}

	row := s.pool.QueryRow(ctx,
		`INSERT INTO scan_jobs (scope_target_id, tool, status, options)
		 VALUES ($1, $2, 'queued', $3)
		 RETURNING `+scanJobCols,
		in.ScopeTargetID, in.Tool, options)
	return scanScanJob(row)
}

func (s *PGStore) GetScanJob(ctx context.Context, id uuid.UUID) (*models.ScanJob, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scanJobCols+` FROM scan_jobs WHERE id = $1`, id)
	return scanScanJob(row)
}

func (s *PGStore) ListScanJobsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.ScanJob, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scanJobCols+` FROM scan_jobs WHERE scope_target_id = $1 ORDER BY created_at DESC`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	jobs := make([]models.ScanJob, 0)
	for rows.Next() {
		job, err := scanScanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, *job)
	}
	return jobs, rows.Err()
}

func (s *PGStore) ClaimNextQueuedJob(ctx context.Context) (*models.ScanJob, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE scan_jobs SET status = 'running', started_at = now()
		 WHERE id = (
			SELECT id FROM scan_jobs
			WHERE status = 'queued' AND workflow_id IS NULL
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		 )
		 RETURNING `+scanJobCols)
	return scanScanJob(row)
}

func (s *PGStore) CompleteScanJob(ctx context.Context, id uuid.UUID, status models.ScanJobStatus, exitCode int, stdoutPath, stderrPath string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scan_jobs
		 SET status = $2, exit_code = $3, stdout_path = $4, stderr_path = $5, finished_at = now()
		 WHERE id = $1`,
		id, string(status), exitCode, stdoutPath, stderrPath)
	return err
}

func (s *PGStore) EnsureWildcardTarget(ctx context.Context, scopeTargetID uuid.UUID, rootDomain string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`INSERT INTO wildcard_targets (scope_target_id, root_domain)
		 VALUES ($1, $2)
		 ON CONFLICT (scope_target_id, root_domain)
		 DO UPDATE SET root_domain = EXCLUDED.root_domain
		 RETURNING id`,
		scopeTargetID, rootDomain).Scan(&id)
	return id, err
}

func (s *PGStore) UpsertSubdomains(ctx context.Context, wildcardTargetID uuid.UUID, sourceTool string, subdomains []string) (int, error) {
	if len(subdomains) == 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO subdomains (wildcard_target_id, subdomain, source_tool)
		 SELECT $1, unnest($2::text[]), $3
		 ON CONFLICT (wildcard_target_id, subdomain)
		 DO UPDATE SET last_seen = now(), source_tool = EXCLUDED.source_tool`,
		wildcardTargetID, subdomains, sourceTool)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PGStore) ListSubdomainsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.Subdomain, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT s.id, s.wildcard_target_id, s.subdomain, COALESCE(s.source_tool, ''),
		        s.cname, COALESCE(s.cname_chain, '{}'), COALESCE(s.a_records, '{}'),
		        COALESCE(s.reverse_dns, '{}'), s.takeover_status, s.takeover_service,
		        s.takeover_detail, s.dns_checked_at, s.first_seen, s.last_seen
		 FROM subdomains s
		 JOIN wildcard_targets w ON w.id = s.wildcard_target_id
		 WHERE w.scope_target_id = $1
		 ORDER BY s.subdomain`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	subs := make([]models.Subdomain, 0)
	for rows.Next() {
		var sub models.Subdomain
		if err := rows.Scan(
			&sub.ID, &sub.WildcardTargetID, &sub.Subdomain, &sub.SourceTool,
			&sub.CNAME, &sub.CNAMEChain, &sub.ARecords, &sub.ReverseDNS,
			&sub.TakeoverStatus, &sub.TakeoverService, &sub.TakeoverDetail,
			&sub.DNSCheckedAt, &sub.FirstSeen, &sub.LastSeen,
		); err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

// UpdateSubdomainRecon writes the CNAME/reverse-DNS/takeover enrichment produced
// by the takeover tool back onto the matching subdomains.
func (s *PGStore) UpdateSubdomainRecon(ctx context.Context, wildcardTargetID uuid.UUID, rows []SubdomainReconRow) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	payload := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		var cname any
		if r.CNAME != "" {
			cname = r.CNAME
		}
		payload = append(payload, map[string]any{
			"subdomain":        r.Subdomain,
			"cname":            cname,
			"cname_chain":      emptyIfNil(r.CNAMEChain),
			"a_records":        emptyIfNil(r.ARecords),
			"reverse_dns":      emptyIfNil(r.ReverseDNS),
			"takeover_status":  r.TakeoverStatus,
			"takeover_service": r.TakeoverService,
			"takeover_detail":  r.TakeoverDetail,
		})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tag, err := s.pool.Exec(ctx,
		`UPDATE subdomains s SET
		     cname = v.cname,
		     cname_chain = v.cname_chain,
		     a_records = v.a_records,
		     reverse_dns = v.reverse_dns,
		     takeover_status = v.takeover_status,
		     takeover_service = v.takeover_service,
		     takeover_detail = v.takeover_detail,
		     dns_checked_at = now()
		 FROM jsonb_to_recordset($1::jsonb) AS v(
		     subdomain text, cname text, cname_chain text[], a_records text[],
		     reverse_dns text[], takeover_status text, takeover_service text, takeover_detail text
		 )
		 WHERE s.wildcard_target_id = $2 AND s.subdomain = v.subdomain`,
		string(encoded), wildcardTargetID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func emptyIfNil(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

func scanScanJob(row pgx.Row) (*models.ScanJob, error) {
	var (
		job    models.ScanJob
		status string
		opts   []byte
	)
	err := row.Scan(
		&job.ID, &job.ScopeTargetID, &job.WorkflowID, &job.WorkflowStepID,
		&job.Tool, &status, &opts,
		&job.StartedAt, &job.FinishedAt, &job.StdoutPath, &job.StderrPath,
		&job.ExitCode, &job.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	job.Status = models.ScanJobStatus(status)
	job.Options = json.RawMessage(opts)
	return &job, nil
}
