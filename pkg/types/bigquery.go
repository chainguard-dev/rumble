package types

import (
	"crypto/sha256"
	"fmt"
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
}

func (row *ImageScanSummary) SetPrimaryKey() {
	h := sha256.New()
	s := row.Image + "--" + row.Scanner + row.Time
	h.Write([]byte(s))
	bs := h.Sum(nil)
	row.ID = fmt.Sprintf("%x", bs)
}

type Vuln struct {
	ID            string `bigquery:"id"`      // This is faux primary key, the shas256sum of (name + "--" + installed + "--" + vulnerability + "--" + type + "--" + time)
	ScanID        string `bigquery:"scan_id"` // This is faux foreign key to the table above
	Name          string `bigquery:"name"`
	Installed     string `bigquery:"installed"`
	FixedIn       string `bigquery:"fixed_in"`
	Type          string `bigquery:"type"`
	Vulnerability string `bigquery:"vulnerability"`
	Severity      string `bigquery:"severity"`
	Time          string `bigquery:"time"`
}

func (row *Vuln) SetPrimaryKey() {
	h := sha256.New()
	s := row.Name + "--" + row.Installed + "--" + row.Vulnerability + "--" + row.Type + "--" + row.Time
	h.Write([]byte(s))
	bs := h.Sum(nil)
	row.ID = fmt.Sprintf("%x", bs)
}
