.DEFAULT_GOAL := build

.PHONY: clean build fmt test

TAG           ?= "v0.0.2"

BUILD_FLAGS   ?=
BINARY        ?= spring-config-decryptor
VERSION       ?= $(shell git describe --tags --always --dirty)
LDFLAGS       ?= -w -s

IMAGE         ?= spring-config-decryptor
TAG           ?= latest
CLOUD_IMAGE   ?= grepplabs/spring-config-decryptor:$(TAG)

ROOT_DIR      := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

default: build

test:
	GO111MODULE=on go test -mod=vendor -v ./...

build:
	CGO_ENABLED=0 GO111MODULE=on go build -mod=vendor -o $(BINARY) $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" .

fmt:
	go fmt ./...

clean:
	@rm -rf $(BINARY)

.PHONY: deps
deps:
	GO111MODULE=on go get ./...

.PHONY: vendor
vendor:
	GO111MODULE=on go mod vendor

.PHONY: tidy
tidy:
	GO111MODULE=on go mod tidy

.PHONY: docker.build
docker.build:
	docker build --pull -t $(IMAGE) -f Dockerfile .

.PHONY: docker.push
docker.push: docker.build
	docker tag $(IMAGE) $(CLOUD_IMAGE)
	docker push $(CLOUD_IMAGE)

tag:
	git tag $(TAG)

.PHONY: release.setup
release.setup:
	curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh

.PHONY: release.skip-publish
release.skip-publish: release.setup
	$(ROOT_DIR)/bin/goreleaser release --rm-dist --skip-publish --snapshot

.PHONY: release.publish
release.publish: release.setup
	@[ "${GITHUB_TOKEN}" ] && echo "releasing $(TAG)" || ( echo "GITHUB_TOKEN is not set"; exit 1 )
	git push origin $(TAG)
	$(ROOT_DIR)/bin/goreleaser release --rm-dist
