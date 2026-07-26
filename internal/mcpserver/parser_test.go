package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestReport(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.html")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("writing test report: %v", err)
	}
	return path
}

const v2Body = `<html><body>
<script type="application/json" id="morok-data">{"v":2,"generated_at":"2026-07-26 10:00:00","domain":"corp.local","version":"1.3.0","score":{"grade":"C","value":53},"counts":{"critical":1,"high":2,"medium":3},"findings":{"acl":[{"summary":"tyrion|WriteDACL|Small Council","severity":"Critical","cvss":9.1}]}}</script>
</body></html>`

func TestParseReport_ValidV2(t *testing.T) {
	path := writeTestReport(t, v2Body)

	snap, err := ParseReport(path)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if snap.V != 2 {
		t.Errorf("V = %d, want 2", snap.V)
	}
	if snap.Domain != "corp.local" {
		t.Errorf("Domain = %q, want corp.local", snap.Domain)
	}
	acl := snap.Findings["acl"]
	if len(acl) != 1 || acl[0].Severity != "Critical" {
		t.Errorf("Findings[acl] = %+v", acl)
	}
}

func TestParseReport_RejectsV1(t *testing.T) {
	v1Body := `<html><body>
<script type="application/json" id="morok-data">{"v":1,"generated_at":"2026-06-01 10:00:00","domain":"corp.local","findings":{"acl":["tyrion|WriteDACL|Small Council"]}}</script>
</body></html>`
	path := writeTestReport(t, v1Body)

	_, err := ParseReport(path)
	if err == nil {
		t.Fatal("expected error for v1 report, got nil")
	}
	if !strings.Contains(err.Error(), "older morok version") {
		t.Errorf("error = %q, want it to mention 'older morok version'", err.Error())
	}
}

func TestParseReport_MissingScriptBlock(t *testing.T) {
	path := writeTestReport(t, `<html><body><p>not a morok report</p></body></html>`)

	_, err := ParseReport(path)
	if err == nil {
		t.Fatal("expected error for missing morok-data block, got nil")
	}
	if !strings.Contains(err.Error(), "no embedded morok-data") {
		t.Errorf("error = %q, want it to mention 'no embedded morok-data'", err.Error())
	}
}

func TestParseReport_MalformedJSON(t *testing.T) {
	path := writeTestReport(t, `<html><body>
<script type="application/json" id="morok-data">{not valid json</script>
</body></html>`)

	_, err := ParseReport(path)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestParseReport_FileNotFound(t *testing.T) {
	_, err := ParseReport(filepath.Join(t.TempDir(), "does-not-exist.html"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
