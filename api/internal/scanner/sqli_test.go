package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleSQLMapOutput = `        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.10.10.2#dev}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 50 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=1 AND SLEEP(5)
---
[INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
`

func TestParseSQLMap(t *testing.T) {
	rows := parseSQLMap("http://example.com/item?id=1", sampleSQLMapOutput)
	if len(rows) != 2 {
		t.Fatalf("expected 2 injection points, got %d", len(rows))
	}
	if rows[0].Parameter != "id" || rows[0].Method != "GET" {
		t.Errorf("row 0 param/method = %q/%q, want id/GET", rows[0].Parameter, rows[0].Method)
	}
	if rows[0].Technique != "boolean-based blind" {
		t.Errorf("row 0 technique = %q", rows[0].Technique)
	}
	if rows[0].Payload != "id=1 AND 1234=1234" {
		t.Errorf("row 0 payload = %q", rows[0].Payload)
	}
	if rows[1].Technique != "time-based blind" {
		t.Errorf("row 1 technique = %q", rows[1].Technique)
	}
	if rows[1].Payload != "id=1 AND SLEEP(5)" {
		t.Errorf("row 1 payload = %q", rows[1].Payload)
	}
	for i, r := range rows {
		if r.DBMS != "MySQL >= 5.0.12" {
			t.Errorf("row %d dbms = %q", i, r.DBMS)
		}
		if r.URL != "http://example.com/item?id=1" {
			t.Errorf("row %d url = %q", i, r.URL)
		}
	}
}

func TestParseSQLMapNoFindings(t *testing.T) {
	rows := parseSQLMap("http://example.com/", "[INFO] testing connection to the target URL\n[WARNING] parameter 'id' does not seem to be injectable\n")
	if len(rows) != 0 {
		t.Fatalf("expected 0 injection points, got %d", len(rows))
	}
}

func TestValidSQLiTechnique(t *testing.T) {
	valid := []string{"B", "BEUSTQ", "BEQ"}
	for _, v := range valid {
		if !ValidSQLiTechnique(v) {
			t.Errorf("ValidSQLiTechnique(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "X", "BX", "beustq"}
	for _, v := range invalid {
		if ValidSQLiTechnique(v) {
			t.Errorf("ValidSQLiTechnique(%q) = true, want false", v)
		}
	}
}

func TestNormalizeSQLiOptions(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"technique": "beq",
		"level":     9,
		"risk":      0,
		"threads":   4,
		"crawl":     3,
		"forms":     true,
		"tamper":    " space2comment ",
	})
	opts := normalizeSQLiOptions(raw)
	if opts.Technique != "BEQ" {
		t.Errorf("technique = %q, want BEQ", opts.Technique)
	}
	if opts.Level != 1 {
		t.Errorf("level = %d, want clamped default 1", opts.Level)
	}
	if opts.Risk != 1 {
		t.Errorf("risk = %d, want clamped default 1", opts.Risk)
	}
	if opts.Threads != 4 {
		t.Errorf("threads = %d, want 4", opts.Threads)
	}
	if opts.Crawl != 3 {
		t.Errorf("crawl = %d, want 3", opts.Crawl)
	}
	if !opts.Forms {
		t.Error("forms = false, want true")
	}
	if opts.Tamper != "space2comment" {
		t.Errorf("tamper = %q, want trimmed", opts.Tamper)
	}
}

func TestNormalizeSQLiOptionsDefaults(t *testing.T) {
	opts := normalizeSQLiOptions(nil)
	if opts.Technique != SQLiDefaultTechniques || opts.Level != 1 || opts.Risk != 1 || opts.Threads != 4 {
		t.Errorf("unexpected defaults: %+v", opts)
	}
}

func TestBuildSQLMapArgs(t *testing.T) {
	opts := sqliOptions{Technique: "BEUSTQ", Level: 2, Risk: 1, Threads: 4, Tamper: "space2comment", Forms: true, Crawl: 2, DBMS: "MySQL"}
	args := buildSQLMapArgs(opts, "http://example.com/item?id=1")
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-u http://example.com/item?id=1",
		"--batch",
		"--technique BEUSTQ",
		"--level 2",
		"--risk 1",
		"--threads 4",
		"--tamper space2comment",
		"--dbms MySQL",
		"--forms",
		"--crawl 2",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
}
