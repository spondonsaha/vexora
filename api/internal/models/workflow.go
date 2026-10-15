package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type WorkflowType string

const (
	WorkflowCompany  WorkflowType = "company"
	WorkflowWildcard WorkflowType = "wildcard"
	WorkflowURL      WorkflowType = "url"
	WorkflowDomain   WorkflowType = "domain"
)

type WorkflowStatus string

const (
	WorkflowQueued    WorkflowStatus = "queued"
	WorkflowRunning   WorkflowStatus = "running"
	WorkflowDone      WorkflowStatus = "done"
	WorkflowFailed    WorkflowStatus = "failed"
	WorkflowCancelled WorkflowStatus = "cancelled"
)

// StepStatus shares the same lifecycle vocabulary as ScanJobStatus.
type StepStatus string

const (
	StepQueued    StepStatus = "queued"
	StepRunning   StepStatus = "running"
	StepDone      StepStatus = "done"
	StepFailed    StepStatus = "failed"
	StepCancelled StepStatus = "cancelled"
)

type Workflow struct {
	ID            uuid.UUID      `json:"id"`
	ScopeTargetID uuid.UUID      `json:"scope_target_id"`
	WorkflowType  WorkflowType   `json:"workflow_type"`
	Status        WorkflowStatus `json:"status"`
	CurrentStep   int            `json:"current_step"`
	Error         *string        `json:"error"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	FinishedAt    *time.Time     `json:"finished_at"`
	Steps         []WorkflowStep `json:"steps,omitempty"`
}

type WorkflowStep struct {
	ID          uuid.UUID       `json:"id"`
	WorkflowID  uuid.UUID       `json:"workflow_id"`
	StepNumber  int             `json:"step_number"`
	StepKey     string          `json:"step_key"`
	Title       string          `json:"title"`
	Description *string         `json:"description"`
	Status      StepStatus      `json:"status"`
	Summary     json.RawMessage `json:"summary"`
	StartedAt   *time.Time      `json:"started_at"`
	FinishedAt  *time.Time      `json:"finished_at"`
	CreatedAt   time.Time       `json:"created_at"`
	Jobs        []ScanJob       `json:"jobs,omitempty"`
}
