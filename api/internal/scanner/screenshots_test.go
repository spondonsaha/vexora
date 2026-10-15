package scanner

import (
	"testing"

	"github.com/google/uuid"
)

const sampleHttpxScreenshotLine = `{"url":"https://example.com/","input":"example.com","host":"example.com","host_ip":"93.184.216.34","status_code":200,"title":"Example Domain","tech":["Nginx"],"content_length":1256,"screenshot_path":"/output/screenshot/example.com/cea8d4cbc5e3b39fcbcf053e0e0244fe14c835ae.png","screenshot_path_rel":"example.com/cea8d4cbc5e3b39fcbcf053e0e0244fe14c835ae.png","screenshot_bytes":75625}`

func TestParseHttpxScreenshotPath(t *testing.T) {
	subID := uuid.New()
	rows, err := parseHttpx(sampleHttpxScreenshotLine, map[string]uuid.UUID{"example.com": subID})
	if err != nil {
		t.Fatalf("parseHttpx: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].ScreenshotPath == nil {
		t.Fatal("screenshot path is nil, want set")
	}
	want := "output/screenshot/example.com/cea8d4cbc5e3b39fcbcf053e0e0244fe14c835ae.png"
	if *rows[0].ScreenshotPath != want {
		t.Errorf("screenshot path = %q, want %q", *rows[0].ScreenshotPath, want)
	}
	if rows[0].SubdomainID == nil || *rows[0].SubdomainID != subID {
		t.Errorf("subdomain id not linked")
	}
}

func TestParseHttpxNoScreenshot(t *testing.T) {
	subID := uuid.New()
	rows, err := parseHttpx(`{"url":"https://example.com/","input":"example.com","status_code":200}`,
		map[string]uuid.UUID{"example.com": subID})
	if err != nil {
		t.Fatalf("parseHttpx: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].ScreenshotPath != nil {
		t.Errorf("screenshot path = %q, want nil", *rows[0].ScreenshotPath)
	}
}

func TestParseHttpxScreenshotsAdHoc(t *testing.T) {
	subID := uuid.New()
	byURL := map[string]uuid.UUID{"https://example.com": subID}
	shots := parseHttpxScreenshots(sampleHttpxScreenshotLine, byURL)
	got, ok := shots[subID]
	if !ok {
		t.Fatalf("no screenshot captured for subdomain, shots=%v", shots)
	}
	want := "output/screenshot/example.com/cea8d4cbc5e3b39fcbcf053e0e0244fe14c835ae.png"
	if got != want {
		t.Errorf("ad-hoc screenshot path = %q, want %q", got, want)
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/":      "https://example.com",
		"https://example.com":       "https://example.com",
		"HTTPS://EXAMPLE.COM/path/": "https://example.com/path",
		"":                          "",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}
