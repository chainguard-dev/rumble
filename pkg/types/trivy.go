package types

type TrivyScanOutput struct {
	Metadata TrivyScanOutputMetadata `json:"Metadata"`
	Results  []TrivyScanOutputResult `json:"Results"`
}

type TrivyScanOutputMetadata struct {
	RepoDigests []string `json:"RepoDigests"`
}

type TrivyScanOutputResult struct {
	Vulnerabilities []TrivyScanOutputResultVulnerability `json:"Vulnerabilities"`
}

type TrivyScanOutputResultVulnerability struct {
	Severity string `json:"Severity"`
}

type TrivyVersionOutput struct {
	Version         string `json:"Version"`
	VulnerabilityDB TrivyVersionOutputVulnerabilityDB
}

type TrivyVersionOutputVulnerabilityDB struct {
	// TODO: re-enable this - its an integer, but could potentially be a string.
	// We are not using it anyway
	// Version      int    `json:"Version"`
	NextUpdate   string `json:"NextUpdate"`
	UpdatedAt    string `json:"UpdatedAt"`
	DownloadedAt string `json:"DownloadedAt"`
}
