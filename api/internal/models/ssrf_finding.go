package models

import (
	"time"

	"github.com/google/uuid"
)

// SSRFFinding is a single server-side request forgery result for a scope
// target. Findings are one of:
//
//   - candidate     — a parameter that looks SSRF-prone (pre-filtered, not yet
//     confirmed),
//   - ssrf_oob      — a parameter confirmed exploitable because the target
//     issued an out-of-band DNS/HTTP/SMTP callback to the
//     framework's OOB host,
//   - metadata_read — an in-band cloud-instance metadata response was returned
//     for a parameter (auto-flagged critical).
type SSRFFinding struct {
	ID            int64      `json:"id"`
	ScopeTargetID uuid.UUID  `json:"scope_target_id"`
	ScanJobID     *uuid.UUID `json:"scan_job_id"`
	URL           string     `json:"url"`
	Parameter     string     `json:"parameter"`
	Payload       string     `json:"payload"`
	Method        string     `json:"method"`
	FindingType   string     `json:"finding_type"`
	Severity      string     `json:"severity"`
	Confirmed     bool       `json:"confirmed"`
	Protocol      string     `json:"protocol"`
	RemoteAddress string     `json:"remote_address"`
	Evidence      string     `json:"evidence"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
