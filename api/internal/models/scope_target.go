package models

import (
	"time"

	"github.com/google/uuid"
)

type ScopeTargetType string

const (
	ScopeCompany  ScopeTargetType = "company"
	ScopeWildcard ScopeTargetType = "wildcard"
	ScopeURL      ScopeTargetType = "url"
)

func (t ScopeTargetType) Valid() bool {
	switch t {
	case ScopeCompany, ScopeWildcard, ScopeURL:
		return true
	default:
		return false
	}
}

type ScopeTarget struct {
	ID            uuid.UUID       `json:"id"`
	Type          ScopeTargetType `json:"type"`
	Value         string          `json:"value"`
	Description   string          `json:"description"`
	Notes         string          `json:"notes"`
	AuthConfirmed bool            `json:"auth_confirmed"`
	Active        bool            `json:"active"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}
