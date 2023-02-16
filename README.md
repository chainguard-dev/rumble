# rumble

Collect data on the number of CVEs in a set of container images, including both [Chainguard Images](https://www.chainguard.dev/chainguard-images) and other images. 

This repository serves two purposes:
- Provides a GitHub Action that scans and attests a container image.
- Logs daily CVE information on Chainguard Images and set of other images.

## Background

Known vulnerabilities ([CVEs](https://www.cve.org/)) in 3rd party container images are an important software supply chain security problem. 
First, many popular container images, often pulled from Docker Hub, have [hundreds of CVEs](https://assets.website-files.com/6228fdbc6c97145dad2a9c2b/624e2337f70386ed568d7e7e_chainguard-all-about-that-base-image.pdf), even when a user pulls the latest version.
Second, these vulnerabilities can be a source of compromise, offering attackers a way to gain access to container-based applications.
Third, because many reported vulnerabilities are either false positives or otherwise do not represent an actual vulnerability, these high CVE counts are a source of wasted staff time since one or more teams must triage the sometimes high number of CVEs.

## How the `action.yaml` GitHub Action Works

This GitHub Action scans and attests a container image.

## How Daily Logging of CVEs Works

A GitHub Action ([`scan.yml`](https://github.com/chainguard-dev/rumble/blob/main/.github/workflows/scan.yml)) operates on a daily cron job, scanning all Chainguard Images and also images listed in [`images.txt`](https://github.com/chainguard-dev/rumble/blob/main/images.txt). This data is then stored in Google BigQuery.

## Initialize a BigQuery table with schema

```
GCLOUD_PROJECT=*** GCLOUD_DATASET=*** GCLOUD_TABLE=***  go run cmd/tableinit/main.go
```

## FAQ

*Is the daily logged CVE data available?*

Not currently. It might be in the future. If you are interested in the data, please open an issue.

*What scanners does `rumble` currently support?*

`trivy` and `grype`.

*How do I learn more about Chainguard images?*

You can request a demo [here](https://www.chainguard.dev/get-demo). You can also check out documentation on the Chainguard [website](https://www.chainguard.dev/chainguard-images) or [GitHub](https://github.com/chainguard-images/).
