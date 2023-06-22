package main

import (
	"context"
	"os"

	"cloud.google.com/go/bigquery"
	"github.com/chainguard-dev/rumble/pkg/types"
)

var (
	GcloudProject = os.Getenv("GCLOUD_PROJECT")
	GcloudDataset = os.Getenv("GCLOUD_DATASET")

	// This is the table that stores a row for each rumble run/scan
	GcloudTable = os.Getenv("GCLOUD_TABLE")

	// This is a table that holds individual vulns found in a single rumble run/scan
	// The scan_id field on this table refers to the rumble run id (acting as a foreign key)
	GcloudTableVulns = os.Getenv("GCLOUD_TABLE_VULNS")
)

func main() {
	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, GcloudProject)
	if err != nil {
		panic(err)
	}
	dataset := client.Dataset(GcloudDataset)

	// 1. Image scan summary
	schema, err := bigquery.InferSchema(types.ImageScanSummary{})
	if err != nil {
		panic(err)
	}
	table := dataset.Table(GcloudTable)
	if err := table.Create(ctx, &bigquery.TableMetadata{Schema: schema}); err != nil {
		panic(err)
	}

	// 2. Individual vulnerabilties
	schema, err = bigquery.InferSchema(types.Vuln{})
	if err != nil {
		panic(err)
	}
	table = dataset.Table(GcloudTableVulns)
	if err := table.Create(ctx, &bigquery.TableMetadata{Schema: schema}); err != nil {
		panic(err)
	}
}
