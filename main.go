package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	rumbletypes "github.com/chainguard-dev/rumble/pkg/types"
)

func main() {
	image := flag.String("image", "cgr.dev/chainguard/static:latest", "OCI image")
	scanner := flag.String("scanner", "grype", "Which scanner to use, (\"trivy\" or \"grype\")")
	flag.Parse()
	if err := scanImage(*image, *scanner); err != nil {
		panic(err)
	}
}

func scanImage(image string, scanner string) error {
	var err error
	var summary *rumbletypes.ImageScanSummary
	switch scanner {
	case "trivy":
		summary, err = scanImageTrivy(image)
	case "grype":
		summary, err = scanImageGrype(image)
	default:
		err = fmt.Errorf("invalid scanner: %s", scanner)
	}
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(summary, "", "    ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func scanImageTrivy(image string) (*rumbletypes.ImageScanSummary, error) {
	return nil, nil
}

func scanImageGrype(image string) (*rumbletypes.ImageScanSummary, error) {
	summary := &rumbletypes.ImageScanSummary{
		Image:   image,
		Digest:  "todo",
		Scanner: "grype",
		Time:    time.Now().UTC().Format("2006-01-02T15:04:05"),
	}
	log.Printf("scanning %s with grype\n", image)
	file, err := os.CreateTemp("", "grype-scan-")
	if err != nil {
		return summary, err
	}
	defer os.Remove(file.Name())
	args := []string{"-v", "-o", "json", "--file", file.Name(), image}
	cmd := exec.Command("grype", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return summary, err
	}
	b, err := os.ReadFile(file.Name())
	if err != nil {
		return summary, err
	}
	fmt.Println(string(b))
	var output rumbletypes.GrypeScanOutput
	if err := json.Unmarshal(b, &output); err != nil {
		return summary, err
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

	return summary, nil
}
