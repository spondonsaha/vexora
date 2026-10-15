package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// NucleiFinding is a single template match produced by the nuclei tool.
type NucleiFinding struct {
	ID            int64           `json:"id"`
	ScopeTargetID uuid.UUID       `json:"scope_target_id"`
	ScanJobID     *uuid.UUID      `json:"scan_job_id"`
	Category      string          `json:"category"`
	TemplateID    string          `json:"template_id"`
	Name          string          `json:"name"`
	Severity      string          `json:"severity"`
	Type          *string         `json:"type"`
	Host          *string         `json:"host"`
	MatchedAt     string          `json:"matched_at"`
	Description   *string         `json:"description"`
	Reference     json.RawMessage `json:"reference"`
	Tags          json.RawMessage `json:"tags"`
	Extracted     json.RawMessage `json:"extracted"`
	CVSSScore     *float64        `json:"cvss_score"`
	CurlCommand   *string         `json:"curl_command"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}
