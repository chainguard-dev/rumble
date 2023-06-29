package types

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type ImageScanSummary struct {
	ID string `bigquery:"id"` // This is faux primary key, the shas256sum of (image + "--" + scanner + "--" + time)

	Image            string `bigquery:"image"`
	Digest           string `bigquery:"digest"`
	Scanner          string `bigquery:"scanner"`
	ScannerVersion   string `bigquery:"scanner_version"`
	ScannerDbVersion string `bigquery:"scanner_db_version"`
	Time             string `bigquery:"time"`
	Created          string `bigquery:"created"`
	LowCveCount      int    `bigquery:"low_cve_count"`
	MedCveCount      int    `bigquery:"med_cve_count"`
	HighCveCount     int    `bigquery:"high_cve_count"`
	CritCveCount     int    `bigquery:"crit_cve_count"`

	// NegligibleCveCount is a grype specific field
	NegligibleCveCount int `bigquery:"negligible_cve_count"`

	UnknownCveCount int  `bigquery:"unknown_cve_count"`
	TotCveCount     int  `bigquery:"tot_cve_count"`
	Success         bool `bigquery:"success"`

	RawGrypeJSON string `bigquery:"raw_grype_json"`
	RawSyftJSON  string `bigquery:"-"`
}

func (row *ImageScanSummary) SetID() {
	row.ID = sha256Sum(row.id())
}

func (row *ImageScanSummary) id() string {
	return strings.Join([]string{row.Image, row.Scanner, row.Time}, "--")
}

func (row *ImageScanSummary) ExtractVulns() ([]*Vuln, error) {
	// No Grype data present which we rely on for this info
	if row.RawGrypeJSON == "" {
		return []*Vuln{}, nil
	}
	if row.ID == "" {
		row.SetID()
	}
	var grypeOutput GrypeScanOutput
	if err := json.Unmarshal([]byte(row.RawGrypeJSON), &grypeOutput); err != nil {
		return nil, err
	}
	var syftOutput SyftScanOutput
	if row.RawSyftJSON != "" {
		if err := json.Unmarshal([]byte(row.RawSyftJSON), &syftOutput); err != nil {
			return nil, err
		}
	}
	uniqueVulns := map[string]*Vuln{}
	for _, match := range grypeOutput.Matches {
		packageName, packageVersion := determineDistroPackage(&match, &grypeOutput, &syftOutput)
		v := Vuln{
			ScanID:               row.ID,
			Name:                 match.Artifact.Name,
			Installed:            match.Artifact.Version,
			FixedIn:              strings.Join(match.Vulnerability.Fix.Versions, ","),
			Type:                 match.Artifact.Type,
			Vulnerability:        match.Vulnerability.ID,
			Severity:             match.Vulnerability.Severity,
			Time:                 row.Time,
			DistroPackageName:    packageName,
			DistroPackageVersion: packageVersion,
		}
		v.SetID()
		uniqueVulns[v.ID] = &v
	}
	vulns := []*Vuln{}
	for _, vuln := range uniqueVulns {
		vulns = append(vulns, vuln)
	}
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].id() < vulns[j].id()
	})
	return vulns, nil
}

type Vuln struct {
	ID                   string `bigquery:"id"`      // This is faux primary key, the shas256sum of (name + "--" + installed + "--" + vulnerability + "--" + type + "--" + time)
	ScanID               string `bigquery:"scan_id"` // This is faux foreign key to the table above
	Name                 string `bigquery:"name"`
	Installed            string `bigquery:"installed"`
	FixedIn              string `bigquery:"fixed_in"`
	Type                 string `bigquery:"type"`
	Vulnerability        string `bigquery:"vulnerability"`
	Severity             string `bigquery:"severity"`
	Time                 string `bigquery:"time"`
	DistroPackageName    string `bigquery:"distro_package_name"`
	DistroPackageVersion string `bigquery:"distro_package_version"`
}

func (row *Vuln) SetID() {
	row.ID = sha256Sum(row.id())
}

func (row *Vuln) id() string {
	return strings.Join([]string{row.Name, row.Installed, row.Vulnerability, row.Type, row.Time}, "--")
}

func sha256Sum(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

const (
	defaultDistroPackageName    = "unknown"
	defaultDistroPackageVersion = "unknown"
)

func determineDistroPackage(match *GrypeScanOutputMatches, grypeOutput *GrypeScanOutput, syftOutput *SyftScanOutput) (string, string) {
	if grypeOutput == nil || syftOutput == nil || match == nil {
		return defaultDistroPackageName, defaultDistroPackageVersion
	}

	if match.Artifact.Type == "apk" {
		return match.Artifact.Name, match.Artifact.Version
	}

	grypeArtifactID := match.Artifact.ID

	var syftArtifact SyftScanOutputArtifact
	foundSyftArtifact := false
	for _, artifact := range syftOutput.Artifacts {
		if artifact.ID == grypeArtifactID {
			syftArtifact = artifact
			foundSyftArtifact = true
			break
		}
	}
	if !foundSyftArtifact {
		return defaultDistroPackageName, defaultDistroPackageVersion
	}

	syftChildID := syftArtifact.ID
	var syftArtifactRelationship SyftScanOutputArtifactRelationship
	foundSyftArtifactRelationship := false
	for _, relationship := range syftOutput.ArtifactRelationships {
		// TODO: what if it is to self? (e.g. apk)
		if relationship.Child == syftChildID && relationship.Type == "ownership-by-file-overlap" {
			syftArtifactRelationship = relationship
			foundSyftArtifactRelationship = true
			break
		}
	}
	if !foundSyftArtifactRelationship {
		return defaultDistroPackageName, defaultDistroPackageVersion
	}

	syftParentID := syftArtifactRelationship.Parent
	var syftArtifactParent SyftScanOutputArtifact
	foundSyftArtifactParent := false
	for _, artifact := range syftOutput.Artifacts {
		if artifact.ID == syftParentID {
			syftArtifactParent = artifact
			foundSyftArtifactParent = true
			break
		}
	}
	if !foundSyftArtifactParent {
		return defaultDistroPackageName, defaultDistroPackageVersion
	}

	return syftArtifactParent.Name, syftArtifactParent.Version
}
