#!/usr/bin/env bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/../

ARCH="${ARCH:-x86_64}"
REF="${REF:-"rumble:dev"}"

MELANGE_IMAGE_REPO="cgr.dev/chainguard/melange"
MELANGE_IMAGE_IDENTIFIER=":latest"
MELANGE_IMAGE_REF="${MELANGE_IMAGE_REF:-${MELANGE_IMAGE_REPO}${MELANGE_IMAGE_IDENTIFIER}}"

APKO_IMAGE_REPO="cgr.dev/chainguard/apko"
APKO_IMAGE_IDENTIFIER=":latest"
APKO_IMAGE_REF="${APKO_IMAGE_REF:-${APKO_IMAGE_REPO}${APKO_IMAGE_IDENTIFIER}}"

rm -rf ./packages/

rm -f melange.rsa melange.rsa.pub

docker run --rm -v "${PWD}":/work "${MELANGE_IMAGE_REF}" keygen

docker run --rm --privileged -v "${PWD}":/work\
    "${MELANGE_IMAGE_REF}" build melange.yaml \
    --arch "${ARCH}" \
    --repository-append packages \
    --signing-key melange.rsa

docker run --rm -v "${PWD}":/work \
    "${APKO_IMAGE_REF}" build --debug apko.yaml \
    "${REF}" output.tar -k melange.rsa.pub \
    --build-arch "${ARCH}"

docker load < output.tar
