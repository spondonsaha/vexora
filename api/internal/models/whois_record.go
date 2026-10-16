package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// WhoisRecord is registration/ownership data for a target's root domain,
// collected from an RDAP (preferred) or WHOIS source. registrant_org may be
// empty when the registry redacts it (common under GDPR); registrar and the
// nameserver list usually remain available.
type WhoisRecord struct {
	ID            int64           `json:"id"`
	ScopeTargetID uuid.UUID       `json:"scope_target_id"`
	RootDomainID  *uuid.UUID      `json:"root_domain_id"`
	ScanJobID     *uuid.UUID      `json:"scan_job_id"`
	Domain        string          `json:"domain"`
	RegistrantOrg string          `json:"registrant_org"`
	Registrar     string          `json:"registrar"`
	RegisteredAt  *time.Time      `json:"registered_at"`
	ExpiresAt     *time.Time      `json:"expires_at"`
	Nameservers   json.RawMessage `json:"nameservers"`
	Statuses      json.RawMessage `json:"statuses"`
	Source        string          `json:"source"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}
