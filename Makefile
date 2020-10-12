.DEFAULT_GOAL := build

.PHONY: clean build fmt test

TAG           ?= "v0.0.3"

BUILD_FLAGS   ?=
BINARY        ?= spring-config-decryptor
VERSION       ?= $(shell git describe --tags --always --dirty)
LDFLAGS       ?= -w -s

GOARCH        ?= amd64
GOOS          ?= linux

IMAGE         ?= spring-config-decryptor
TAG           ?= latest
CLOUD_IMAGE   ?= grepplabs/spring-config-decryptor:$(TAG)

ROOT_DIR      := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

OS_IMAGE      ?= local/$(GOOS)-$(GOARCH)/$(BINARY)
OS_BIN        ?= $(BINARY)-$(GOOS)-$(GOARCH)

default: build

test:
	GO111MODULE=on go test -mod=vendor -v ./...

build:
	CGO_ENABLED=0 GO111MODULE=on go build -mod=vendor -o $(BINARY) $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" .

.PHONY: os.build
os.build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 GO111MODULE=on go build -mod=vendor -o $(BINARY) $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" .

fmt:
	go fmt ./...

clean:
	@rm -rf $(BINARY)*

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

.PHONY: os.bin
os.bin:
	docker build -t $(OS_IMAGE) --build-arg GOOS=$(GOOS) --build-arg GOARCH=$(GOARCH) -f Dockerfile.build .
	$(eval BUILDCONTAINER=$(shell sh -c "docker create $(OS_IMAGE)"))
	$(shell docker cp $(BUILDCONTAINER):/spring-config-decryptor ./$(OS_BIN))
	$(eval RESULT=$(shell sh -c "docker rm $(BUILDCONTAINER)"))
	$(eval RESULT=$(shell sh -c "docker rmi $(OS_IMAGE)"))
	@echo "Binary copied to local directory"

.PHONY: build.linux
build.linux: clean
	make GOOS=linux OS_BIN=$(BINARY) os.bin

.PHONY: build.darwin
build.darwin: clean
	make GOOS=darwin OS_BIN=$(BINARY) os.bin

.PHONY: build.windows
build.windows: clean
	make GOOS=windows OS_BIN=$(BINARY).exe os.bin

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
