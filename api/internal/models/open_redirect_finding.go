package models

import (
	"time"

	"github.com/google/uuid"
)

// OpenRedirectFinding is a single redirect issue reported by the openredirect
// tool for a scope target: a parameter/payload combination that made the server
// redirect to the scanner's canary host (open_redirect), that reached a
// client-side redirect sink (dom_redirect), that injected a response header
// (header_injection), that accepted a javascript:/data: URI (javascript_uri) or
// that simply reflected the payload (reflection).
type OpenRedirectFinding struct {
	ID            int64      `json:"id"`
	ScopeTargetID uuid.UUID  `json:"scope_target_id"`
	ScanJobID     *uuid.UUID `json:"scan_job_id"`
	URL           string     `json:"url"`
	Parameter     string     `json:"parameter"`
	Payload       string     `json:"payload"`
	FindingType   string     `json:"finding_type"`
	StatusCode    *int       `json:"status_code"`
	Location      string     `json:"location"`
	Evidence      string     `json:"evidence"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
