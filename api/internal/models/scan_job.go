package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type ScanJobStatus string

const (
	ScanQueued    ScanJobStatus = "queued"
	ScanRunning   ScanJobStatus = "running"
	ScanDone      ScanJobStatus = "done"
	ScanFailed    ScanJobStatus = "failed"
	ScanCancelled ScanJobStatus = "cancelled"
)

type ScanJob struct {
	ID             uuid.UUID       `json:"id"`
	ScopeTargetID  uuid.UUID       `json:"scope_target_id"`
	WorkflowID     *uuid.UUID      `json:"workflow_id"`
	WorkflowStepID *uuid.UUID      `json:"workflow_step_id"`
	Tool           string          `json:"tool"`
	Status         ScanJobStatus   `json:"status"`
	Options        json.RawMessage `json:"options"`
	StartedAt      *time.Time      `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at"`
	StdoutPath     *string         `json:"stdout_path"`
	StderrPath     *string         `json:"stderr_path"`
	ExitCode       *int            `json:"exit_code"`
	CreatedAt      time.Time       `json:"created_at"`
}

type Subdomain struct {
	ID               uuid.UUID  `json:"id"`
	WildcardTargetID uuid.UUID  `json:"wildcard_target_id"`
	Subdomain        string     `json:"subdomain"`
	SourceTool       string     `json:"source_tool"`
	CNAME            *string    `json:"cname"`
	CNAMEChain       []string   `json:"cname_chain"`
	ARecords         []string   `json:"a_records"`
	ReverseDNS       []string   `json:"reverse_dns"`
	TakeoverStatus   *string    `json:"takeover_status"`
	TakeoverService  *string    `json:"takeover_service"`
	TakeoverDetail   *string    `json:"takeover_detail"`
	DNSCheckedAt     *time.Time `json:"dns_checked_at"`
	FirstSeen        time.Time  `json:"first_seen"`
	LastSeen         time.Time  `json:"last_seen"`
}
