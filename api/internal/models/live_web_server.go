package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type LiveWebServer struct {
	ID             uuid.UUID       `json:"id"`
	SubdomainID    *uuid.UUID      `json:"subdomain_id"`
	IP             *string         `json:"ip"`
	URL            string          `json:"url"`
	StatusCode     *int            `json:"status_code"`
	Title          *string         `json:"title"`
	ContentLength  *int64          `json:"content_length"`
	TechStack      json.RawMessage `json:"tech_stack"`
	Headers        json.RawMessage `json:"headers"`
	TLS            json.RawMessage `json:"tls"`
	ScreenshotPath *string         `json:"screenshot_path"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}
