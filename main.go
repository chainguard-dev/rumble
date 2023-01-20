package main

import (
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

func main() {
	image := flag.String("image", "cgr.dev/chainguard/static:latest", "OCI image")
	scanner := flag.String("scanner", "grype", "Which scanner to use, (\"trivy\" or \"grype\")")
	attest := flag.Bool("attest", false, "If enabled, attempt to attest vuln results using cosign")
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
		if err := attestImage(*image, startTime, endTime, *scanner, filename); err != nil {
			panic(err)
		}
	} else {
		// TODO: upload this to BigQuery if certain flags set etc.
		b, err := json.MarshalIndent(summary, "", "    ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(b))
		fmt.Println("im here")

		ctx := context.Background()
		client, err := bigquery.NewClient(ctx, "MY_GCLOUD_PROJECT") // TODO: make option
		if err != nil {
			panic(err)
		}

		dataset := client.Dataset("MY_GCLOUD_DATASET") // TODO: make option

		table := dataset.Table("MY_GCLOUD_TABLE") // TODO: make option

		u := table.Inserter()
		if err := u.Put(ctx, summary); err != nil {
			panic(err)
		}

		/*
			TODO: put the table schema creation elsewhere?
			schema, err := bigquery.InferSchema(rumbletypes.ImageScanSummary{})
			if err != nil {
				panic(err)
			}

			if err := table.Create(ctx, &bigquery.TableMetadata{Schema: schema}); err != nil {
				panic(err)
			}
		*/

		/*
					if err := table.Create(ctx, &bigquery.TableMetadata{Schema: schema1}); err != nil {
			    // TODO: Handle error.
			}
		*/
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

func attestImage(image string, startTime *time.Time, endTime *time.Time, scanner string, filename string) error {
	env := append(os.Environ(), "COSIGN_EXPERIMENTAL=1")

	// Convert the sarif document to InToto statement
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var sarifObj types.GrypeScanSarifOutput
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
			URI:       "TODO: pass this in",
			EventID:   "TODO: pass this in",
			BuilderID: "TODO: pass this in",
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
	return "", nil, nil, nil, nil
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
	// TODO:Create dat summary!
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
