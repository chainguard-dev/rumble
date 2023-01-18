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
	attest := flag.Bool("attest", false, "If enabled, attempt to attest vuln results using cosign")
	flag.Parse()
	filename, err := scanImage(*image, *scanner)
	defer os.Remove(filename)
	if err != nil {
		panic(err)
	}
	if *attest {
		fmt.Println("Attempting to attest scan results using cosign...")
		if err := attestImage(*image, *scanner, filename); err != nil {
			panic(err)
		}
	}
}

func scanImage(image string, scanner string) (string, error) {
	var filename string
	var summary *rumbletypes.ImageScanSummary
	var err error
	switch scanner {
	case "trivy":
		filename, summary, err = scanImageTrivy(image)
	case "grype":
		filename, summary, err = scanImageGrype(image)
	default:
		err = fmt.Errorf("invalid scanner: %s", scanner)
	}
	if err != nil {
		return "", err
	}

	// TODO: upload this to BigQuery if certain flags set etc.
	b, err := json.MarshalIndent(summary, "", "    ")
	if err != nil {
		return "", err
	}
	fmt.Println(string(b))

	return filename, nil
}

func attestImage(image string, scanner string, filename string) error {
	env := append(os.Environ(), "COSIGN_EXPERIMENTAL=1")

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

func scanImageTrivy(image string) (string, *rumbletypes.ImageScanSummary, error) {
	return "", nil, nil
}

func scanImageGrype(image string) (string, *rumbletypes.ImageScanSummary, error) {
	summary := &rumbletypes.ImageScanSummary{
		Image:   image,
		Digest:  "todo",
		Scanner: "grype",
		Time:    time.Now().UTC().Format("2006-01-02T15:04:05"),
	}
	log.Printf("scanning %s with grype\n", image)
	file, err := os.CreateTemp("", "grype-scan-")
	if err != nil {
		return "", summary, err
	}
	args := []string{"-v", "-o", "json", "--file", file.Name(), image}
	cmd := exec.Command("grype", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", summary, err
	}
	b, err := os.ReadFile(file.Name())
	if err != nil {
		return "", summary, err
	}
	fmt.Println(string(b))
	var output rumbletypes.GrypeScanOutput
	if err := json.Unmarshal(b, &output); err != nil {
		return "", summary, err
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

	return file.Name(), summary, nil
}
