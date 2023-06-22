package types

import (
	"os"
	"testing"
)

const (
	testGrypeScan = "testdata/grype-scan.json"

	expectedVulnCount = 37

	vulnTypeApk    = "apk"
	vulnTypeDotnet = "dotnet"
	vulnTypeGo     = "go-module"
	vulnTypeJava   = "java-archive"
	vulnTypePython = "python"
)

var (
	expectedVulnCountsByType = map[string]int{
		vulnTypeApk:    14,
		vulnTypeDotnet: 3,
		vulnTypeGo:     8,
		vulnTypeJava:   11,
		vulnTypePython: 1,
	}
)

func TestVulnExtraction(t *testing.T) {
	b, err := os.ReadFile(testGrypeScan)
	if err != nil {
		t.Errorf("expected no error on os.ReadFile(), got %v", err)
	}
	summary := ImageScanSummary{
		ID:           "testing-123",
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
