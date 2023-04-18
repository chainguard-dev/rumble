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
	GcloudTable   = os.Getenv("GCLOUD_TABLE")

	DoMigrate = os.Getenv("RUMBLE_MIGRATE")
)

func main() {
	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, GcloudProject)
	if err != nil {
		panic(err)
	}
	schema, err := bigquery.InferSchema(types.ImageScanSummary{})
	if err != nil {
		panic(err)
	}
	dataset := client.Dataset(GcloudDataset)
	table := dataset.Table(GcloudTable)

	if err := table.Create(ctx, &bigquery.TableMetadata{Schema: schema}); err != nil {
		panic(err)
	}
}
