#!/usr/bin/env bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/../

ARCH="${ARCH:-x86_64}"
REF="${REF:-"ghcr.io/chainguard-dev/rumble"}"

REGISTRY_USERNAME="${REGISTRY_USERNAME:-"missing"}"
REGISTRY_PASSWORD="${REGISTRY_PASSWORD:-"missing"}"

MELANGE_IMAGE_REPO="cgr.dev/chainguard/melange"
MELANGE_IMAGE_IDENTIFIER=":latest"
MELANGE_IMAGE_REF="${MELANGE_IMAGE_REF:-${MELANGE_IMAGE_REPO}${MELANGE_IMAGE_IDENTIFIER}}"

APKO_IMAGE_REPO="cgr.dev/chainguard/apko"
APKO_IMAGE_IDENTIFIER=":latest"
APKO_IMAGE_REF="${APKO_IMAGE_REF:-${APKO_IMAGE_REPO}${APKO_IMAGE_IDENTIFIER}}"

if [[ "${REGISTRY_USERNAME}" == "missing" || "${REGISTRY_PASSWORD}" == "missing" ]]; then
    echo "Must set REGISTRY_USERNAME and REGISTRY_PASSWORD. Exiting."
    exit 1
fi

rm -rf ./packages/

rm -f melange.rsa melange.rsa.pub

docker run --rm -v "${PWD}":/work "${MELANGE_IMAGE_REF}" keygen

docker run --rm --privileged -v "${PWD}":/work\
    "${MELANGE_IMAGE_REF}" build melange.yaml \
    --arch "${ARCH}" \
    --repository-append packages \
    --signing-key melange.rsa

export DOCKER_CONFIG="$(mktemp -d)"
trap "rm -rf ${DOCKER_CONFIG}" EXIT
echo "{}" > "${DOCKER_CONFIG}/config.json"
docker login "$(echo "${REF}" | cut -d: -f1 | cut -d/ -f1)" \
    -u "${REGISTRY_USERNAME}" -p "${REGISTRY_PASSWORD}"

APKOREFS="${REF}"
echo "GITHUB_EVENT_NAME: ${GITHUB_EVENT_NAME}"
echo "CHAINGUARD_GITHUB_EVENT_NAME: ${CHAINGUARD_GITHUB_EVENT_NAME}"
if [[ "${CHAINGUARD_GITHUB_EVENT_NAME}" == "schedule" ]]; then
  APKOREFS="${APKOREFS} $(echo "${REF}" | cut -d: -f1):$(date +'%Y-%m-%d')"
fi

docker run --rm -v "${PWD}":/work -v "${DOCKER_CONFIG}":/dockerconfig -e DOCKER_CONFIG=/dockerconfig \
    "${APKO_IMAGE_REF}" publish --debug apko.yaml --image-refs apko.images \
        -k melange.rsa.pub --arch "${ARCH}" ${APKOREFS}

cosign sign $(cat apko.images)
