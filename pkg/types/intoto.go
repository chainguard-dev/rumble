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

/*
From existing github action:

        export SCANNER_URI=$(cat ${{ steps.grype-scan.outputs.sarif }} | jq -r .runs[0].tool.driver.informationUri)
        export SCANNER_VERSION=$(cat ${{ steps.grype-scan.outputs.sarif }} | jq -r .runs[0].tool.driver.version)
        echo "grype SCANNER_URI: $SCANNER_URI"
        echo "grype SCANNER_VERSION: $SCANNER_VERSION"

        cat > "${ATTESTATION}" <<EOF
        {
            "invocation": {
              "parameters": null,
              "uri": "https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}",
              "event_id": "${{ github.run_id }}",
              "builder.id": "${{ github.workflow }}"
            },
            "scanner": {
              "uri": "$SCANNER_URI",
              "version": "$SCANNER_VERSION",
              "result": $(cat ${{ steps.grype-scan.outputs.sarif }} | jq .)
            },
            "metadata": {
              "scanStartedOn": "${{ steps.scan-start.outputs.date }}",
              "scanFinishedOn": "$(TZ=Zulu date "+%Y-%m-%dT%H:%M:%SZ")"
            }
        }
        EOF
}
*/
