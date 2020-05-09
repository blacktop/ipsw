REPO=blacktop
NAME=ipsw
VERSION=$(shell cat VERSION)
MESSAGE?="New release ${VERSION}"

# TODO remove \|/templates/\|/api
SOURCE_FILES?=$$(go list ./... | grep -v /vendor/)
TEST_PATTERN?=.
TEST_OPTIONS?=

GIT_COMMIT=$(git rev-parse HEAD)
GIT_DIRTY=$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)
GIT_DESCRIBE=$(git describe --tags)


setup: ## Install all the build and lint dependencies
	@echo "===> Installing deps"
	go get -u github.com/alecthomas/gometalinter
	go get -u github.com/pierrre/gotestcover
	go get -u golang.org/x/tools/cmd/cover
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
	CGO_ENABLED=1 CC=gcc go run ./cmd/ipsw/main.go device-list-gen pkg/info/data/device_traits.json

.PHONY: dry_release
dry_release:
	goreleaser --skip-publish --rm-dist --skip-validate

.PHONY: bump
bump: ## Incriment version patch number
	@echo " > Bumping VERSION"
	@hack/bump/version -p $(shell cat VERSION) > VERSION
	@git commit -am "bumping version to $(shell cat VERSION)"
	@git push

.PHONY: release
release: bump ## Create a new release from the VERSION
	@echo " > Creating Release"
	@hack/make/release v$(shell cat VERSION)
	@goreleaser --rm-dist

destroy: ## Remove release from the VERSION
	@echo " > Deleting Release"
	rm -rf dist
	git tag -d v${VERSION}
	git push origin :refs/tags/v${VERSION}

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
	docker build -t $(REPO)/$(NAME):$(VERSION) .

docker-tag: docker
	docker tag $(REPO)/$(NAME):$(VERSION) docker.pkg.github.com/blacktop/ipsw/$(NAME):$(VERSION)

docker-push: docker-tag
	docker push docker.pkg.github.com/blacktop/ipsw/$(NAME):$(VERSION)

.PHONY: test-docker
test-docker: ## Run docker test
	@echo "===> Testing Docker Image"
	docker run --init -it --rm --device /dev/fuse --cap-add=SYS_ADMIN -v `pwd`:/data $(REPO)/$(NAME):$(VERSION) -V extract --dyld /data/iPhone12_1_13.2.3_17B111_Restore.ipsw

.PHONY: size
size: ## Get built image size
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(REPO)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: ssh
ssh:
	@docker run --init -it --rm --device /dev/fuse --cap-add SYS_ADMIN --mount type=tmpfs,destination=/app -v `pwd`/test-caches/ipsws:/data --entrypoint=bash $(REPO)/$(NAME):$(VERSION)

.PHONY: run
run:
	@docker run --init -it --rm --device /dev/fuse --cap-add SYS_ADMIN --mount type=tmpfs,destination=/app -v `pwd`/test-caches/ipsws:/data $(REPO)/$(NAME):$(VERSION)
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