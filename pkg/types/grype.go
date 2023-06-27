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
	Vulnerability GrypeScanOutputMatchesVulnerability  `json:"vulnerability"`
	Artifact      GrypeScanOutputMatchesArtifact       `json:"artifact"`
}

type GrypeScanOutputMatchesArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

type GrypeScanOutputMatchesVulnerability struct {
	ID       string                                 `json:"id"`
	Severity string                                 `json:"severity"`
	Fix      GrypeScanOutputMatchesVulnerabilityFix `json:"fix"`
}

type GrypeScanOutputMatchesVulnerabilityFix struct {
	Versions []string `json:"versions"`
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
