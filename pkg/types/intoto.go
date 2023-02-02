package types

type InTotoStatement struct {
	Invocation InTotoStatementInvocation `json:"invocation"`
	Scanner    InTotoStatementScanner    `json:"scanner"`
	Metadata   InTotoStatementMetadata   `json:"metadata"`
}

type InTotoStatementInvocation struct {
	Parameters *struct{} `json:"parameters"`
	URI        string    `json:"uri"`
	EventID    string    `json:"event_id"`
	BuilderID  string    `json:"builder.id"`
}

type InTotoStatementScanner struct {
	URI     string                 `json:"uri"`
	Version string                 `json:"version"`
	Result  map[string]interface{} `json:"result"`
}

type InTotoStatementMetadata struct {
	ScanStartedOn  string `json:"scanStartedOn"`
	ScanFinishedOn string `json:"scanFinishedOn"`
}
