package types

type ImageScanSummary struct {
	Image            string
	Digest           string
	Scanner          string
	ScannerVersion   string
	ScannerDbVersion string
	Time             string
	LowCveCount      int
	MedCveCount      int
	HighCveCount     int
	CritCveCount     int

	// NegligibleCveCount is a grype specific field
	NegligibleCveCount int

	UnknownCveCount int
	TotCveCount     int
	Success         bool
}
