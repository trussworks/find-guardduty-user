#! /usr/bin/env bash

VERSION=0.0.1
ARTIFACTS="/root/artifacts"

mkdir -p "${ARTIFACTS}"
tar -czvf "${ARTIFACTS}/find-guardduty-user-${VERSION}.tar.gz" main.go go.mod go.sum Dockerfile LICENSE README.md
zip "${ARTIFACTS}/find-guardduty-user-${VERSION}.zip" main.go go.mod go.sum Dockerfile LICENSE README.md
GOOS=darwin GOARCH=amd64 go build -ldflags "LDFLAGS=-linkmode external -extldflags -static" -o "${ARTIFACTS}/find-guardduty-user_${VERSION}_Darwin_x86_64" .
GOOS=linux GOARCH=amd64 go build -ldflags "LDFLAGS=-linkmode external -extldflags -static" -o "${ARTIFACTS}/find-guardduty-user_${VERSION}_Linux_x86_64" .
pushd ${ARTIFACTS} > /dev/null || exit
	sha256sum find-guardduty-user-* >> checksum.txt
popd > /dev/null || exit
