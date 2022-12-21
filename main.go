package main

import (
	//"bufio"
	///"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	trivyartifact "github.com/aquasecurity/trivy/pkg/commands/artifact"
	trivyflag "github.com/aquasecurity/trivy/pkg/flag"
)

func main() {
	image := flag.String("image", "cgr.dev/chainguard/static:latest", "OCI image")
	scanner := flag.String("scanner", "trivy", "Which scanner to use, (\"trivy\" or \"grype\")")
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
	log.Printf("scanning %s with trivy\n", image)
	reportFlagGroup := trivyflag.NewReportFlagGroup()
	reportFlagGroup.DependencyTree = nil
	reportFlagGroup.ReportFormat = nil
	imageFlags := &trivyflag.Flags{
		CacheFlagGroup:         trivyflag.NewCacheFlagGroup(),
		DBFlagGroup:            trivyflag.NewDBFlagGroup(),
		ImageFlagGroup:         trivyflag.NewImageFlagGroup(),
		LicenseFlagGroup:       trivyflag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       trivyflag.NewMisconfFlagGroup(),
		RemoteFlagGroup:        trivyflag.NewClientFlags(),
		RegoFlagGroup:          trivyflag.NewRegoFlagGroup(),
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          trivyflag.NewScanFlagGroup(),
		SecretFlagGroup:        trivyflag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: trivyflag.NewVulnerabilityFlagGroup(),
	}
	globalFlags := trivyflag.NewGlobalFlagGroup()
	options, err := imageFlags.ToOptions("rumble-dev", []string{image}, globalFlags, os.Stderr)
	if err != nil {
		return err
	}
	options.GlobalOptions.Debug = true
	options.Timeout = time.Minute * 5
	options.ReportOptions.Format = "json"
	//options.ReportOptions.ReportFormat = "json"
	ctx := context.Background()
	return trivyartifact.Run(ctx, options, trivyartifact.TargetContainerImage)
}

func scanImageGrype(image string) error {
	log.Printf("scanning %s with grype\n", image)
	return nil
}
