package main

import (
	"context"
	"os"

	"cloud.google.com/go/bigquery"
	"github.com/chainguard-dev/rumble/pkg/types"
)

var (
	GcloudProject    = os.Getenv("GCLOUD_PROJECT")
	GcloudDataset    = os.Getenv("GCLOUD_DATASET")
	GcloudTable      = os.Getenv("GCLOUD_TABLE")
	GcloudTableVulns = os.Getenv("GCLOUD_TABLE_VULNS")

	DoMigrate = os.Getenv("RUMBLE_MIGRATE")
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
