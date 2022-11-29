REPO=blacktop
NAME=ipsw
CUR_VERSION=$(shell gh release view --json tagName -q '.tagName')
LOCAL_VERSION=$(shell svu current)
NEXT_VERSION=$(shell svu patch)
GO_BIN=go

.PHONY: build-deps
build-deps: x86-brew ## Install the build dependencies
	@echo " > Installing build deps"
	brew install $(GO_BIN) goreleaser zig unicorn libusb

.PHONY: dev-deps
dev-deps: ## Install the dev dependencies
	@echo " > Installing dev deps"
	$(GO_BIN) install golang.org/x/tools/...@latest
	$(GO_BIN) install github.com/spf13/cobra-cli@latest
	$(GO_BIN) get -d golang.org/x/tools/cmd/cover
	$(GO_BIN) get -d golang.org/x/tools/cmd/stringer
	$(GO_BIN) get -d github.com/caarlos0/svu@v1.4.1

.PHONY: x86-brew
x86-brew: ## Install the x86_64 homebrew on Apple Silicon
	cd ~/Downloads; mkdir homebrew
	cd ~/Downloads; curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip 1 -C homebrew
	sudo mv ~/Downloads/homebrew /usr/local/homebrew
	arch -x86_64 /usr/local/homebrew/bin/brew install unicorn libusb

.PHONY: setup
setup: build-deps dev-deps ## Install all the build and dev dependencies

.PHONY: dry_release
dry_release: ## Run goreleaser without releasing/pushing artifacts to github
	@echo " > Creating Pre-release Build ${NEXT_VERSION}"
	@GOROOT=$(shell go env GOROOT) goreleaser build --id darwin_arm64_extras_build --rm-dist --snapshot --single-target --output dist/ipsw

.PHONY: snapshot
snapshot: ## Run goreleaser snapshot
	@echo " > Creating Snapshot ${NEXT_VERSION}"
	@GOROOT=$(shell go env GOROOT) goreleaser --rm-dist --snapshot

.PHONY: release
release: ## Create a new release from the NEXT_VERSION
	@echo " > Creating Release ${NEXT_VERSION}"
	@hack/make/release ${NEXT_VERSION}
	@GOROOT=$(shell go env GOROOT) goreleaser --rm-dist

.PHONY: release-minor
release-minor: ## Create a new minor semver release
	@echo " > Creating Release $(shell svu minor)"
	@hack/make/release $(shell svu minor)
	@GOROOT=$(shell go env GOROOT) goreleaser --rm-dist

.PHONY: destroy
destroy: ## Remove release from the CUR_VERSION
	@echo " > Deleting Release ${LOCAL_VERSION}"
	rm -rf dist
	git tag -d ${LOCAL_VERSION}
	git push origin :refs/tags/${LOCAL_VERSION}

build: ## Build ipsw
	@echo " > Building ipsw"
	@$(GO_BIN) mod download
	@CGO_ENABLED=1 $(GO_BIN) build -ldflags "-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=$(CUR_VERSION) -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppBuildTime==$(date -u +%Y%m%d)" ./cmd/ipsw

build-ios: ## Build ipsw for iOS
	@echo " > Building ipsw"
	@$(GO_BIN) mod download
	@CGO_ENABLED=1 GOOS=ios GOARHC=arm64 CC=$(shell go env GOROOT)/misc/ios/clangwrap.sh $(GO_BIN) build -ldflags "-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=$(CUR_VERSION) -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppBuildTime==$(date -u +%Y%m%d)" ./cmd/ipsw
	@codesign --entitlements hack/make/data/ent.plist -s - -f ipsw

.PHONY: docs
docs: ## Build the hugo docs
	@echo " > Building Docs"
	hack/publish/gh-pages

.PHONY: test-docs
test-docs: ## Start local server hosting hugo docs
	@echo " > Testing Docs"
	cd docs; hugo server -D

.PHONY: update_mod
update_mod: ## Update go.mod file
	@echo " > Updating go.mod"
	rm go.sum || true
	$(GO_BIN) mod download
	$(GO_BIN) mod tidy

.PHONY: update_devs
update_devs: ## Parse XCode database for new devices
	@echo " > Updating device_traits.json"
	CGO_ENABLED=1 CGO_CFLAGS=-I/usr/local/include CGO_LDFLAGS=-L/usr/local/lib CC=gcc $(GO_BIN) run ./cmd/ipsw/main.go device-list-gen pkg/xcode/device_traits.json

.PHONY: update_keys
update_keys: ## Scrape the iPhoneWiki for AES keys
	@echo " > Updating firmware_keys.json"
	CGO_ENABLED=0 $(GO_BIN) run ./cmd/ipsw/main.go key-list-gen pkg/info/data/firmware_keys.json

.PHONY: docker
docker: ## Build docker image
	@echo " > Building Docker Image"
	docker build --build-arg VERSION=$(NEXT_VERSION) -t $(REPO)/$(NAME):$(NEXT_VERSION) .

.PHONY: docker-tag
docker-tag: docker ## Tag docker image
	docker tag $(REPO)/$(NAME):$(NEXT_VERSION) docker.pkg.github.com/blacktop/ipsw/$(NAME):$(NEXT_VERSION)

.PHONY: docker-ssh
docker-ssh: ## SSH into docker image
	@docker run --init -it --rm --device /dev/fuse --cap-add SYS_ADMIN --mount type=tmpfs,destination=/app -v `pwd`/test-caches/ipsws:/data --entrypoint=bash $(REPO)/$(NAME):$(NEXT_VERSION)

.PHONY: docker-push
docker-push: docker-tag ## Push docker image to github
	docker push docker.pkg.github.com/blacktop/ipsw/$(NAME):$(NEXT_VERSION)

.PHONY: docker-test
docker-test: ## Run docker test
	@echo " > Testing Docker Image"
	docker run --init -it --rm --device /dev/fuse --cap-add=SYS_ADMIN -v `pwd`:/data $(REPO)/$(NAME):$(NEXT_VERSION) -V extract --dyld /data/iPhone12_1_13.2.3_17B111_Restore.ipsw

clean: ## Clean up artifacts
	@echo " > Cleaning"
	rm *.tar || true
	rm *.ipsw || true
	rm kernelcache.release.* || true
	rm -rf dist

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help