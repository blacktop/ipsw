REPO=blacktop
NAME=partialzip
VERSION=$(shell cat VERSION)
MESSAGE?="New release ${VERSION}"

# TODO remove \|/templates/\|/api
SOURCE_FILES?=$$(go list ./... | grep -v /vendor/)
TEST_PATTERN?=.
TEST_OPTIONS?=

GIT_COMMIT=$(git rev-parse HEAD)
GIT_DIRTY=$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)
GIT_DESCRIBE=$(git describe --tags)


.PHONY: vendor
vendor:
	GO111MODULE=on go mod vendor

.PHONY: setup
setup: ## Install all the build and lint dependencies
	@echo "===> Installing deps"
	go get -u github.com/alecthomas/gometalinter
	go get -u github.com/pierrre/gotestcover
	go get -u golang.org/x/tools/cmd/cover
	gometalinter --install

.PHONY: test
test: ## Run all the tests
	gotestcover $(TEST_OPTIONS) -covermode=atomic -coverprofile=coverage.txt $(SOURCE_FILES) -run $(TEST_PATTERN) -timeout=30s

.PHONY: cover
cover: test ## Run all the tests and opens the coverage report
	go tool cover -html=coverage.txt

.PHONY: fmt
fmt: ## gofmt and goimports all go files
	find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done

.PHONY: lint
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

.PHONY: dry_release
dry_release:
	goreleaser --skip-publish --rm-dist --skip-validate

.PHONY: bump
bump: ## Incriment version patch number
	@echo " > Bumping VERSION"
	@hack/bump/version -p $(shell cat VERSION) > VERSION
	@git commit -am "bumping version to $(VERSION)"
	@git push

.PHONY: release
release: bump ## Create a new release from the VERSION
	@echo " > Creating Release"
	@hack/make/release $(shell cat VERSION)
	@goreleaser --rm-dist

.PHONY: destroy
destroy: ## Remove release from the VERSION
	@echo " > Deleting Release"
	rm -rf dist
	git tag -d ${VERSION}
	git push origin :refs/tags/${VERSION}

.PHONY: ci
ci: lint test ## Run all the tests and code checks

.PHONY: build
build: ## Build a beta version of malice
	@echo "===> Building Binaries"
	go build

clean: ## Clean up artifacts
	rm *.tar || true
	rm *.ipsw || true
	rm rm kernelcache.release.* || true
	rm -rf dist

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help