package types

type ImageScanSummary struct {
	Image            string `bigquery:"image"`
	Digest           string `bigquery:"digest"`
	Scanner          string `bigquery:"scanner"`
	ScannerVersion   string `bigquery:"scanner_version"`
	ScannerDbVersion string `bigquery:"scanner_db_version"`
	Time             string `bigquery:"time"`
	LowCveCount      int    `bigquery:"low_cve_count"`
	MedCveCount      int    `bigquery:"med_cve_count"`
	HighCveCount     int    `bigquery:"high_cve_count"`
	CritCveCount     int    `bigquery:"crit_cve_count"`

	// NegligibleCveCount is a grype specific field
	NegligibleCveCount int `bigquery:"negligible_cve_count"`

	UnknownCveCount int  `bigquery:"unknown_cve_count"`
	TotCveCount     int  `bigquery:"tot_cve_count"`
	Success         bool `bigquery:"success"`
}
