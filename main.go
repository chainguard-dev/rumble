package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/chainguard-dev/rumble/pkg/types"
	rumbletypes "github.com/chainguard-dev/rumble/pkg/types"
)

var (
	GcloudProject = os.Getenv("GCLOUD_PROJECT")
	GcloudDataset = os.Getenv("GCLOUD_DATASET")
	GcloudTable   = os.Getenv("GCLOUD_TABLE")
)

func main() {
	image := flag.String("image", "cgr.dev/chainguard/static:latest", "OCI image")
	scanner := flag.String("scanner", "grype", "Which scanner to use, (\"trivy\" or \"grype\")")
	attest := flag.Bool("attest", false, "If enabled, attempt to attest vuln results using cosign")
	bigqueryUpload := flag.Bool("bigquery", true, "If enabled, attempt to upload results to BigQuery")
	invocationURI := flag.String("invocation-uri", "unknown", "in-toto value for invocation uri")
	invocationEventID := flag.String("invocation-event-id", "unknown", "in-toto value for invocation event_id")
	invocationBuilderID := flag.String("invocation-builder-id", "unknown", "in-toto value for invocation builder.id")
	flag.Parse()

	// If the user is attesting, always use sarif format
	format := "json"
	if *attest {
		format = "sarif"
	}

	filename, startTime, endTime, summary, err := scanImage(*image, *scanner, format)
	defer os.Remove(filename)
	if err != nil {
		panic(err)
	}

	if *attest {
		fmt.Println("Attempting to attest scan results using cosign...")
		if err := attestImage(*image, startTime, endTime, *scanner, *invocationURI, *invocationEventID, *invocationBuilderID, filename); err != nil {
			panic(err)
		}
	} else {
		// Print the summary
		b, err := json.MarshalIndent(summary, "", "    ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(b))

		if *bigqueryUpload {
			// Upload to BigQuery
			ctx := context.Background()
			client, err := bigquery.NewClient(ctx, GcloudProject)
			if err != nil {
				panic(err)
			}
			dataset := client.Dataset(GcloudDataset)
			table := dataset.Table(GcloudTable)
			u := table.Inserter()
			if err := u.Put(ctx, summary); err != nil {
				panic(err)
			}
		}

	}
}

func scanImage(image string, scanner string, format string) (string, *time.Time, *time.Time, *rumbletypes.ImageScanSummary, error) {
	var filename string
	var startTime, endTime *time.Time
	var summary *rumbletypes.ImageScanSummary
	var err error
	switch scanner {
	case "trivy":
		filename, startTime, endTime, summary, err = scanImageTrivy(image, format)
	case "grype":
		filename, startTime, endTime, summary, err = scanImageGrype(image, format)
	default:
		err = fmt.Errorf("invalid scanner: %s", scanner)
	}
	if err != nil {
		return "", nil, nil, nil, err
	}
	return filename, startTime, endTime, summary, nil
}

func attestImage(image string, startTime *time.Time, endTime *time.Time, scanner string, invocationURI string, invocationEventID string, invocationBuilderID string, filename string) error {
	env := append(os.Environ(), "COSIGN_EXPERIMENTAL=1")

	// Convert the sarif document to InToto statement
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var sarifObj types.SarifOutput
	if err := json.Unmarshal(b, &sarifObj); err != nil {
		return err
	}

	if len(sarifObj.Runs) == 0 {
		return fmt.Errorf("issue with grype sarif output")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		return err
	}

	statement := rumbletypes.InTotoStatement{
		Invocation: rumbletypes.InTotoStatementInvocation{
			URI:       invocationURI,
			EventID:   invocationEventID,
			BuilderID: invocationBuilderID,
		},
		Scanner: rumbletypes.InTotoStatementScanner{
			URI:     sarifObj.Runs[0].Tool.Driver.InformationURI,
			Version: sarifObj.Runs[0].Tool.Driver.Version,
			Result:  result,
		},
		Metadata: rumbletypes.InTotoStatementMetadata{
			ScanStartedOn:  startTime.UTC().Format("2006-01-02T15:04:05Z"),
			ScanFinishedOn: endTime.UTC().Format("2006-01-02T15:04:05Z"),
		},
	}

	b, err = json.MarshalIndent(statement, "", "    ")
	if err != nil {
		return err
	}

	// Overwrite the sarif file with the intoto envelope file
	if err := os.WriteFile(filename, b, 0644); err != nil {
		return err
	}
	fmt.Println(string(b))

	// Attest
	args := []string{"attest", "--type", "vuln", "--predicate", filename, image}
	cmd := exec.Command("cosign", args...)
	fmt.Printf("Running attestation command \"cosign %s\"...\n", strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return err
	}

	// Verify
	args = []string{"verify-attestation", "--type", "vuln", image}
	cmd = exec.Command("cosign", args...)
	fmt.Printf("Running verify command \"cosign %s\"...\n", strings.Join(args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	return cmd.Run()
}

func scanImageTrivy(image string, format string) (string, *time.Time, *time.Time, *rumbletypes.ImageScanSummary, error) {
	log.Printf("scanning %s with trivy\n", image)
	file, err := os.CreateTemp("", "trivy-scan-")
	if err != nil {
		return "", nil, nil, nil, err
	}
	args := []string{"--debug", "image", "--offline-scan", "-f", format, "-o", file.Name(), image}
	cmd := exec.Command("trivy", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	startTime := time.Now()
	if err := cmd.Run(); err != nil {
		return "", nil, nil, nil, err
	}
	endTime := time.Now()
	b, err := os.ReadFile(file.Name())
	if err != nil {
		return "", nil, nil, nil, err
	}
	fmt.Println(string(b))

	// Get the trivy version
	var out bytes.Buffer
	cmd = exec.Command("trivy", "--version", "-f", "json")
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", nil, nil, nil, err
	}
	var trivyVersion types.TrivyVersionOutput
	if err := json.Unmarshal(out.Bytes(), &trivyVersion); err != nil {
		return "", nil, nil, nil, err
	}
	if format == "json" {
		var output rumbletypes.TrivyScanOutput
		if err := json.Unmarshal(b, &output); err != nil {
			return "", nil, nil, nil, err
		}
		summary := trivyOutputToSummary(image, startTime, &output, &trivyVersion)
		return file.Name(), &startTime, &endTime, summary, err
	}
	return file.Name(), &startTime, &endTime, nil, nil
}

func scanImageGrype(image string, format string) (string, *time.Time, *time.Time, *rumbletypes.ImageScanSummary, error) {
	log.Printf("scanning %s with grype\n", image)
	file, err := os.CreateTemp("", "grype-scan-")
	if err != nil {
		return "", nil, nil, nil, err
	}
	args := []string{"-v", "-o", format, "--file", file.Name(), image}
	cmd := exec.Command("grype", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	startTime := time.Now()
	if err := cmd.Run(); err != nil {
		return "", nil, nil, nil, err
	}
	endTime := time.Now()
	b, err := os.ReadFile(file.Name())
	if err != nil {
		return "", nil, nil, nil, err
	}
	fmt.Println(string(b))
	// Only attempt summary if the format is JSON
	if format == "json" {
		var output rumbletypes.GrypeScanOutput
		if err := json.Unmarshal(b, &output); err != nil {
			return "", nil, nil, nil, err
		}
		summary := grypeOutputToSummary(image, startTime, &output)
		return file.Name(), &startTime, &endTime, summary, err
	}
	return file.Name(), &startTime, &endTime, nil, nil
}

func grypeOutputToSummary(image string, scanTime time.Time, output *rumbletypes.GrypeScanOutput) *rumbletypes.ImageScanSummary {
	summary := &rumbletypes.ImageScanSummary{
		Image:   image,
		Scanner: "grype",
		Time:    scanTime.UTC().Format("2006-01-02T15:04:05Z"),
	}

	summary.Success = true
	summary.ScannerVersion = output.Descriptor.Version
	summary.ScannerDbVersion = output.Descriptor.Db.Checksum

	// TODO: get the digest beforehand
	summary.Digest = strings.Split(output.Source.Target.RepoDigests[0], "@")[1]

	// CVE counts by severity
	summary.TotCveCount = len(output.Matches)
	for _, match := range output.Matches {
		switch match.Vulnerability.Severity {
		case "Low":
			summary.LowCveCount++
		case "Medium":
			summary.MedCveCount++
		case "High":
			summary.HighCveCount++
		case "Critical":
			summary.CritCveCount++
		case "Negligible":
			summary.NegligibleCveCount++
		case "Unknown":
			summary.UnknownCveCount++
		default:
			fmt.Printf("WARNING: unknown severity: %s\n", match.Vulnerability.Severity)
		}
	}
	return summary
}

func trivyOutputToSummary(image string, scanTime time.Time, output *rumbletypes.TrivyScanOutput, trivyVersion *rumbletypes.TrivyVersionOutput) *rumbletypes.ImageScanSummary {
	summary := &rumbletypes.ImageScanSummary{
		Image:              image,
		Scanner:            "trivy",
		Time:               scanTime.UTC().Format("2006-01-02T15:04:05Z"),
		NegligibleCveCount: 0, // This is only available in Grype output
	}

	summary.Success = true
	summary.ScannerVersion = trivyVersion.Version
	summary.ScannerDbVersion = trivyVersion.VulnerabilityDB.UpdatedAt

	// TODO: get the digest beforehand
	summary.Digest = strings.Split(output.Metadata.RepoDigests[0], "@")[1]

	// CVE counts by severity
	totalCveCount := 0
	for _, result := range output.Results {
		for _, vuln := range result.Vulnerabilities {
			totalCveCount++
			switch vuln.Severity {
			case "LOW":
				summary.LowCveCount++
			case "MEDIUM":
				summary.MedCveCount++
			case "HIGH":
				summary.HighCveCount++
			case "CRITICAL":
				summary.CritCveCount++
			case "UNKNOWN":
				summary.UnknownCveCount++
			default:
				fmt.Printf("WARNING: unknown severity: %s\n", vuln.Severity)
			}
		}
	}
	summary.TotCveCount = totalCveCount
	return summary
}
