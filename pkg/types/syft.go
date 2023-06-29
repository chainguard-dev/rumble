package types

type SyftScanOutput struct {
	Artifacts             []SyftScanOutputArtifact
	ArtifactRelationships []SyftScanOutputArtifactRelationship
}

type SyftScanOutputArtifact struct {
	ID      string
	Name    string
	Version string
	Type    string
}

type SyftScanOutputArtifactRelationship struct {
	Parent string
	Child  string
	Type   string
}
