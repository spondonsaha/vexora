package models

import (
	"time"

	"github.com/google/uuid"
)

// Endpoint is a historical or crawled URL associated with a wildcard target.
// It links to a live web server when the URL's host is currently serving HTTP.
type Endpoint struct {
	ID               uuid.UUID  `json:"id"`
	LiveWebServerID  *uuid.UUID `json:"live_web_server_id"`
	WildcardTargetID *uuid.UUID `json:"wildcard_target_id"`
	Host             *string    `json:"host"`
	URL              *string    `json:"url"`
	Path             string     `json:"path"`
	StatusCode       *int       `json:"status_code"`
	ContentLength    *int64     `json:"content_length"`
	SourceTool       *string    `json:"source_tool"`
	Interesting      bool       `json:"interesting"`
	CreatedAt        time.Time  `json:"created_at"`
}
