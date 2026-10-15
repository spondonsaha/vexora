package models

import (
	"time"

	"github.com/google/uuid"
)

// JSFinding is a single artifact extracted from a JavaScript asset (secret,
// endpoint, host, ...) by the jsrecon tool for a scope target.
type JSFinding struct {
	ID            int64      `json:"id"`
	ScopeTargetID uuid.UUID  `json:"scope_target_id"`
	ScanJobID     *uuid.UUID `json:"scan_job_id"`
	JSURL         string     `json:"js_url"`
	Host          string     `json:"host"`
	FindingType   string     `json:"finding_type"`
	Value         string     `json:"value"`
	Context       string     `json:"context"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
