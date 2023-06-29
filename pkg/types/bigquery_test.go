package types

import (
	"os"
	"testing"
)

const (
	testGrypeScan = "testdata/grype-scan.json"
	testSyftScan  = "testdata/syft-scan.json"

	testTime   = "2023-06-22T02:38:46Z"
	testScanID = "testing123"

	expectedVulnCount = 20
)

var (
	expectedVulnCountsByType = map[string]int{
		"apk":          1,
		"dotnet":       5,
		"java-archive": 12,
		"python":       1,
	}
)

func TestVulnExtraction(t *testing.T) {
	grypeBytes, err := os.ReadFile(testGrypeScan)
	if err != nil {
		t.Errorf("expected no error on os.ReadFile(), got %v", err)
	}
	syftBytes, err := os.ReadFile(testSyftScan)
	if err != nil {
		t.Errorf("expected no error on os.ReadFile(), got %v", err)
	}
	summary := ImageScanSummary{
		Time:         testTime,
		ID:           testScanID,
		RawGrypeJSON: string(grypeBytes),
		RawSyftJSON:  string(syftBytes),
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

		// spot check a python vuln package extract
		if vuln.Type == "python" {
			if vuln.PackageName != "py3.11-pip" {
				t.Errorf("expcted package name to be pip but got %s", vuln.PackageName)
			}
			if vuln.PackageVersion != "23.1.2-r0" {
				t.Errorf("expcted package version to be 23.1.2 but got %s", vuln.PackageVersion)
			}
		}

		// TODO: spot check apk vuln

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
