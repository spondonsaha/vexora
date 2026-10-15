package models

import (
	"time"

	"github.com/google/uuid"
)

// SQLiFinding is a single injectable parameter reported by the sqli (sqlmap)
// tool for a scope target.
type SQLiFinding struct {
	ID            int64      `json:"id"`
	ScopeTargetID uuid.UUID  `json:"scope_target_id"`
	ScanJobID     *uuid.UUID `json:"scan_job_id"`
	URL           string     `json:"url"`
	Parameter     string     `json:"parameter"`
	Method        string     `json:"method"`
	Technique     string     `json:"technique"`
	Title         string     `json:"title"`
	Payload       string     `json:"payload"`
	DBMS          string     `json:"dbms"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
