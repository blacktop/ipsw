REPO=blacktop
NAME=ipsw
CUR_VERSION=$(shell svu current)
NEXT_VERSION=$(shell svu patch)

SOURCE_FILES?=$$(go list ./... | grep -v /vendor/)
TEST_PATTERN?=.
TEST_OPTIONS?=


setup: ## Install all the build and lint dependencies
	@echo "===> Installing deps"
	go get -u github.com/alecthomas/gometalinter
	go install github.com/goreleaser/goreleaser
	go get -u github.com/pierrre/gotestcover
	go get -u github.com/spf13/cobra/cobra 
	go get -u golang.org/x/tools/cmd/cover
	go get -u github.com/caarlos0/svu
	gometalinter --install

test: ## Run all the tests
	gotestcover $(TEST_OPTIONS) -covermode=atomic -coverprofile=coverage.txt $(SOURCE_FILES) -run $(TEST_PATTERN) -timeout=30s

cover: test ## Run all the tests and opens the coverage report
	go tool cover -html=coverage.txt

fmt: ## gofmt and goimports all go files
	find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done

lint: ## Run all the linters
	gometalinter --vendor --disable-all \
		--enable=deadcode \
		--enable=ineffassign \
		--enable=gosimple \
		--enable=staticcheck \
		--enable=gofmt \
		--enable=goimports \
		--enable=dupl \
		--enable=misspell \
		--enable=errcheck \
		--enable=vet \
		--enable=vetshadow \
		--deadline=10m \
		./...
		markdownfmt -w README.md

.PHONY: update_mod
update_mod:
	rm go.sum
	go mod download
	go mod tidy

.PHONY: update_devs
update_devs:
	CGO_ENABLED=1 CGO_CFLAGS=-I/usr/local/include CGO_LDFLAGS=-L/usr/local/lib CC=gcc go run ./cmd/ipsw/main.go device-list-gen pkg/xcode/device_traits.json

.PHONY: update_keys
update_keys:
	CGO_ENABLED=0 go run ./cmd/ipsw/main.go key-list-gen pkg/info/data/firmware_keys.json

.PHONY: dry_release
dry_release:
	@echo " > Creating Pre-release Build ${NEXT_VERSION}"
	@goreleaser build --rm-dist --skip-validate

.PHONY: release
release: ## Create a new release from the NEXT_VERSION
	@echo " > Creating Release ${NEXT_VERSION}"
	@hack/make/release ${NEXT_VERSION}
	@goreleaser --rm-dist

.PHONY: release-minor
release-minor: ## Create a new minor semver release
	@echo " > Creating Release $(shell svu minor)"
	@hack/make/release $(shell svu minor)
	@goreleaser --rm-dist

destroy: ## Remove release from the CUR_VERSION
	@echo " > Deleting Release ${CUR_VERSION}"
	rm -rf dist
	git tag -d ${CUR_VERSION}
	git push origin :refs/tags/${CUR_VERSION}

ci: lint test ## Run all the tests and code checks

build: ## Build a beta version of malice
	@echo "===> Building Binaries"
	go build

.PHONY: docs
docs:
	@echo "===> Building Docs"
	hack/publish/gh-pages

.PHONY: docker
docker: ## Build docker image
	@echo "===> Building Docker Image"
	docker build -t $(REPO)/$(NAME):$(NEXT_VERSION) .

docker-tag: docker
	docker tag $(REPO)/$(NAME):$(NEXT_VERSION) docker.pkg.github.com/blacktop/ipsw/$(NAME):$(NEXT_VERSION)

docker-push: docker-tag
	docker push docker.pkg.github.com/blacktop/ipsw/$(NAME):$(NEXT_VERSION)

.PHONY: test-docker
test-docker: ## Run docker test
	@echo "===> Testing Docker Image"
	docker run --init -it --rm --device /dev/fuse --cap-add=SYS_ADMIN -v `pwd`:/data $(REPO)/$(NAME):$(NEXT_VERSION) -V extract --dyld /data/iPhone12_1_13.2.3_17B111_Restore.ipsw

.PHONY: size
size: ## Get built image size
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(REPO)/$(NAME):$(NEXT_VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: ssh
ssh:
	@docker run --init -it --rm --device /dev/fuse --cap-add SYS_ADMIN --mount type=tmpfs,destination=/app -v `pwd`/test-caches/ipsws:/data --entrypoint=bash $(REPO)/$(NAME):$(NEXT_VERSION)

.PHONY: run
run:
	@docker run --init -it --rm --device /dev/fuse --cap-add SYS_ADMIN --mount type=tmpfs,destination=/app -v `pwd`/test-caches/ipsws:/data $(REPO)/$(NAME):$(NEXT_VERSION)
	@go run cmd/ipsw/main.go dyld webkit `pwd`/test-caches/ipsws/dyld_shared_cache_*

clean: ## Clean up artifacts
	rm *.tar || true
	rm *.ipsw || true
	rm kernelcache.release.* || true
	rm -rf dist

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help