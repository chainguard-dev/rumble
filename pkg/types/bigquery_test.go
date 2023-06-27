package types

import (
	"os"
	"testing"
)

const (
	testGrypeScan = "testdata/grype-scan.json"

	testTime   = "2023-06-22T02:38:46Z"
	testScanID = "testing123"

	expectedVulnCount = 37
)

var (
	expectedVulnCountsByType = map[string]int{
		"apk":          14,
		"dotnet":       3,
		"go-module":    8,
		"java-archive": 11,
		"python":       1,
	}
)

func TestVulnExtraction(t *testing.T) {
	b, err := os.ReadFile(testGrypeScan)
	if err != nil {
		t.Errorf("expected no error on os.ReadFile(), got %v", err)
	}
	summary := ImageScanSummary{
		Time:         testTime,
		ID:           testScanID,
		RawGrypeJSON: string(b),
	}
	vulns, err := summary.ExtractVulns()
	if err != nil {
		t.Errorf("expected no error on summary.ExtractVulns(), got %v", err)
	}
	actualVulnCount := len(vulns)
	if actualVulnCount != expectedVulnCount {
		t.Errorf("got %d vulns, wanted %d vulns", actualVulnCount, expectedVulnCount)
	}
	actualVulnCountsByType := map[string]int{}
	for _, vuln := range vulns {
		// Make sure the summary ID and time gets passed down
		if vuln.ScanID != testScanID {
			t.Errorf("vuln.ScanID is %s, wanted %s", vuln.ScanID, testScanID)
		}
		if vuln.Time != testTime {
			t.Errorf("vuln.Time is %s, wanted %s", vuln.Time, testTime)
		}
		// Make sure that all fields are non-empty (besides FixedIn which might be missing)
		for _, v := range []string{vuln.ID, vuln.Name, vuln.Installed, vuln.Type, vuln.Vulnerability, vuln.Severity} {
			if v == "" {
				t.Errorf("got empty value for required field %s", vuln.id())
			}
		}
		if _, ok := actualVulnCountsByType[vuln.Type]; !ok {
			actualVulnCountsByType[vuln.Type] = 0
		}
		actualVulnCountsByType[vuln.Type]++
	}
	for k, expected := range expectedVulnCountsByType {
		actual, ok := actualVulnCountsByType[k]
		if !ok {
			t.Errorf("could not find key %s in actualVulnCountsByType", k)
		}
		if actual != expected {
			t.Errorf("got %d %s vulns, wanted %d %s vulns", actual, k, expected, k)
		}
	}
}
