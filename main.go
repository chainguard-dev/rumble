package main

import (
	//"bufio"
	///"bytes"

	"flag"
	"fmt"
	"log"
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

func scanImageGrype(image string) error {
	log.Printf("scanning %s with grype\n", image)
	return nil
}
