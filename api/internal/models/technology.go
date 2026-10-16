package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Technology is one fingerprinted technology (CMS, framework, server, JS
// library, analytics, CDN or WAF) detected on a live web server. Rows are keyed
// by (scope target, live web server, name, version, detecting tool) so results
// from several tools can be stored side by side and presented as a deduped
// union in the UI.
type Technology struct {
	ID              int64           `json:"id"`
	ScopeTargetID   uuid.UUID       `json:"scope_target_id"`
	LiveWebServerID uuid.UUID       `json:"live_web_server_id"`
	ScanJobID       *uuid.UUID      `json:"scan_job_id"`
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Category        string          `json:"category"`
	DetectedBy      string          `json:"detected_by"`
	CVERefs         json.RawMessage `json:"cve_refs"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}
