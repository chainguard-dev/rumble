package types

type GrypeScanOutput struct {
	Matches    []GrypeScanOutputMatches  `json:"matches"`
	Source     GrypeScanOutputSource     `json:"source"`
	Descriptor GrypeScanOutputDescriptor `json:"descriptor"`
}

type GrypeScanOutputSource struct {
	Target GrypeScanOutputSourceTarget `json:"target"`
}

type GrypeScanOutputSourceTarget struct {
	RepoDigests []string `json:"repoDigests"`
}

type GrypeScanOutputDescriptor struct {
	Version string                      `json:"version"`
	Db      GrypeScanOutputDescriptorDb `json:"db"`
}

type GrypeScanOutputDescriptorDb struct {
	Checksum string `json:"checksum"`
}

type GrypeScanOutputMatches struct {
	Vulnerability GrypeScanOutputMatchesVulnerability `json:"vulnerability"`
}

type GrypeScanOutputMatchesVulnerability struct {
	Severity string `json:"severity"`
}

type SarifOutput struct {
	Runs []SarifOutputRun `json:"runs"`
}

type SarifOutputRun struct {
	Tool SarifOutputRunTool `json:"tool"`
}

type SarifOutputRunTool struct {
	Driver SarifOutputRunToolDriver `json:"driver"`
}

type SarifOutputRunToolDriver struct {
	InformationURI string `json:"informationUri"`
	Version        string `json:"version"`
}
