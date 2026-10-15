package models

import (
	"time"

	"github.com/google/uuid"
)

// NetworkService is a single open port + detected service discovered by the
// netscan tool. Hosts lists the subdomains that currently resolve to this IP.
type NetworkService struct {
	ID            int64      `json:"id"`
	ScopeTargetID uuid.UUID  `json:"scope_target_id"`
	ScanJobID     *uuid.UUID `json:"scan_job_id"`
	IP            string     `json:"ip"`
	Port          int        `json:"port"`
	Protocol      string     `json:"protocol"`
	State         string     `json:"state"`
	TLS           bool       `json:"tls"`
	Service       *string    `json:"service"`
	Product       *string    `json:"product"`
	Version       *string    `json:"version"`
	Banner        *string    `json:"banner"`
	Hosts         []string   `json:"hosts"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
