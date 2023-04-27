package oci

import (
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func ImageBuildTime(imageRef string) (*time.Time, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %w", imageRef, err)
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("remote.Image() %q: %w", imageRef, err)
	}
	config, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("img.ConfigFile() %q: %w", imageRef, err)
	}
	return &config.Created.Time, nil
}
