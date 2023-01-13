package main

import (
	//"bufio"
	///"bytes"

	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
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
	switch scanner {
	case "trivy":
		return scanImageTrivy(image)
	case "grype":
		return scanImageGrype(image)
	}
	return fmt.Errorf("invalid scanner: %s", scanner)
}

func scanImageTrivy(image string) error {
	return nil
}

type grypeScanOutput struct {
	Matches []grypeScanOutputMatches `json:"matches"`
}

type grypeScanOutputMatches struct {
	Vulnerability grypeScanOutputMatchesVulnerability `json:"vulnerability"`
}

type grypeScanOutputMatchesVulnerability struct {
	Severity string `json:"severity"`
}

func scanImageGrype(image string) error {
	log.Printf("scanning %s with grype\n", image)
	app := "grype"

	file, err := os.CreateTemp("", "grype-scan-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name())

	fmt.Println(file.Name())

	args := []string{"-v", "-o", "json", "--file", file.Name(), image}

	// with open(report_name, encoding="utf-8") as file:
	//     scan_results = json.load(file)

	//     # collect all cves and convert to counter
	//     cve_list = []
	//     for field in scan_results["matches"]:
	//         # lowercase the vulnerability severity to avoid inconsistent naming
	//         # across tools
	//         cve_list.append(field["vulnerability"]["severity"].lower())

	//     cve_counter = Counter(cve_list)

	cmd := exec.Command(app, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	b, err := os.ReadFile(file.Name())
	if err != nil {
		return err
	}
	// fmt.Println(string(b))
	var output grypeScanOutput
	if err := json.Unmarshal(b, &output); err != nil {
		return err
	}

	fmt.Println(output)

	return nil
}
