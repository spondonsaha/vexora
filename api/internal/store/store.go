package store

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/spondonsaha/vexora/api/internal/models"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type CreateScopeTargetInput struct {
	Type          models.ScopeTargetType
	Value         string
	Description   string
	AuthConfirmed bool
}

type AuditEntry struct {
	ScopeTargetID *uuid.UUID
	ScanJobID     *uuid.UUID
	Target        string
	Tool          string
	Action        string
	Detail        map[string]any
}

type CreateScanJobInput struct {
	ScopeTargetID uuid.UUID
	Tool          string
	Options       map[string]any
}

// SubdomainReconRow carries DNS/takeover enrichment for one already-discovered
// subdomain (keyed by its name within a wildcard target).
type SubdomainReconRow struct {
	Subdomain       string
	CNAME           string
	CNAMEChain      []string
	ARecords        []string
	ReverseDNS      []string
	TakeoverStatus  string
	TakeoverService string
	TakeoverDetail  string
}

type Store interface {
	Ping(ctx context.Context) error

	CreateScopeTarget(ctx context.Context, in CreateScopeTargetInput) (*models.ScopeTarget, error)
	ListScopeTargets(ctx context.Context, targetType string) ([]models.ScopeTarget, error)
	GetScopeTarget(ctx context.Context, id uuid.UUID) (*models.ScopeTarget, error)
	DeleteScopeTarget(ctx context.Context, id uuid.UUID) error
	SetScopeTargetActive(ctx context.Context, id uuid.UUID, active bool) (*models.ScopeTarget, error)
	SetScopeTargetAuthConfirmed(ctx context.Context, id uuid.UUID, confirmed bool) (*models.ScopeTarget, error)
	SetScopeTargetNotes(ctx context.Context, id uuid.UUID, notes string) (*models.ScopeTarget, error)

	CreateScanJob(ctx context.Context, in CreateScanJobInput) (*models.ScanJob, error)
	GetScanJob(ctx context.Context, id uuid.UUID) (*models.ScanJob, error)
	ListScanJobsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.ScanJob, error)
	ClaimNextQueuedJob(ctx context.Context) (*models.ScanJob, error)
	CompleteScanJob(ctx context.Context, id uuid.UUID, status models.ScanJobStatus, exitCode int, stdoutPath, stderrPath string) error

	EnsureWildcardTarget(ctx context.Context, scopeTargetID uuid.UUID, rootDomain string) (uuid.UUID, error)
	UpsertSubdomains(ctx context.Context, wildcardTargetID uuid.UUID, sourceTool string, subdomains []string) (int, error)
	ListSubdomainsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.Subdomain, error)
	UpdateSubdomainRecon(ctx context.Context, wildcardTargetID uuid.UUID, rows []SubdomainReconRow) (int, error)
	UpdateSubdomainDNS(ctx context.Context, wildcardTargetID uuid.UUID, rows []SubdomainDNSRow) (int, error)

	UpsertNetworkServices(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []NetworkServiceRow) (int, error)
	ListNetworkServicesByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.NetworkService, error)

	CreateWorkflow(ctx context.Context, in CreateWorkflowInput) (*models.Workflow, error)
	GetWorkflow(ctx context.Context, id uuid.UUID) (*models.Workflow, error)
	ListWorkflowsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.Workflow, error)
	ClaimNextQueuedWorkflow(ctx context.Context) (*models.Workflow, error)
	SetWorkflowStatus(ctx context.Context, id uuid.UUID, status models.WorkflowStatus, currentStep int, errMsg *string) error
	StartWorkflowStep(ctx context.Context, id uuid.UUID) error
	FinishWorkflowStep(ctx context.Context, id uuid.UUID, status models.StepStatus, summary map[string]any) error
	CreateRunningScanJob(ctx context.Context, scopeTargetID, workflowID, workflowStepID uuid.UUID, tool string, options map[string]any) (*models.ScanJob, error)

	UpsertLiveWebServers(ctx context.Context, rows []LiveWebServerRow) (int, error)
	GetLiveWebServer(ctx context.Context, id uuid.UUID) (*models.LiveWebServer, error)
	ListLiveWebServersByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.LiveWebServer, error)
	UpdateLiveWebServerScreenshots(ctx context.Context, shots map[uuid.UUID]string) (int, error)

	UpsertEndpoints(ctx context.Context, rows []EndpointRow) (int, error)
	ListEndpointsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.Endpoint, error)

	UpsertNucleiFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []NucleiFindingRow) (int, error)
	ListNucleiFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.NucleiFinding, error)

	UpsertSQLiFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []SQLiFindingRow) (int, error)
	ListSQLiFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.SQLiFinding, error)

	UpsertJSFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []JSFindingRow) (int, error)
	ListJSFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.JSFinding, error)

	UpsertOpenRedirectFindings(ctx context.Context, scopeTargetID, scanJobID uuid.UUID, rows []OpenRedirectFindingRow) (int, error)
	ListOpenRedirectFindingsByScopeTarget(ctx context.Context, scopeTargetID uuid.UUID) ([]models.OpenRedirectFinding, error)

	RecordAudit(ctx context.Context, e AuditEntry) error
}
