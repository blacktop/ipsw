REPO=blacktop
NAME=ipsw
CUR_VERSION=$(shell gh release view --json tagName -q '.tagName')
CUR_COMMIT=$(shell git rev-parse --short HEAD)
LOCAL_VERSION=$(shell go tool svu --tag.pattern 'v3.1.*' current)
NEXT_VERSION=$(shell go tool svu --tag.pattern 'v3.1.*' patch)

.PHONY: build-deps
build-deps: ## Install the build dependencies
	@echo " > Installing build deps"
	brew install gh go git goreleaser zig unicorn libusb

.PHONY: dev-deps
dev-deps: ## Install the dev dependencies
	@echo " > Installing Go dev tools"
	@go mod download
	@go install github.com/goreleaser/goreleaser@latest
	@go install golang.org/x/perf/cmd/benchstat@latest

.PHONY: x86-brew
x86-brew: ## Install the x86_64 homebrew on Apple Silicon
	mkdir /tmp/homebrew
	cd /tmp; curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip 1 -C homebrew
	sudo mv /tmp/homebrew /usr/local/homebrew
	arch -x86_64 /usr/local/homebrew/bin/brew install unicorn libusb

.PHONY: setup
setup: build-deps dev-deps ## Install all the build and dev dependencies

.PHONY: dry_release
dry_release: ## Run goreleaser without releasing/pushing artifacts to github
	@echo " > Creating Pre-release Build ${NEXT_VERSION}"
	@GOROOT=$(shell go env GOROOT) goreleaser build --id darwin_extras_build --clean --timeout 60m --snapshot --single-target --output dist/ipsw

.PHONY: snapshot
snapshot: ## Run goreleaser snapshot
	@echo " > Creating Snapshot ${NEXT_VERSION}"
	@GOROOT=$(shell go env GOROOT) goreleaser --clean --timeout 60m --snapshot

.PHONY: release
release: ## Create a new release from the NEXT_VERSION
	@echo " > Creating Release ${NEXT_VERSION}"
	@hack/make/release ${NEXT_VERSION}
	@GOROOT=$(shell go env GOROOT) goreleaser --clean --timeout 60m --skip=validate
	@echo " > Update Portfile ${NEXT_VERSION}"
	@hack/make/portfile ../ports

.PHONY: release-minor
release-minor: ## Create a new minor semver release
	@echo " > Creating Release $(shell go tool svu --tag.pattern 'v3.1.*' minor)"
	@hack/make/release $(shell go tool svu --tag.pattern 'v3.1.*' minor)
	@GOROOT=$(shell go env GOROOT) goreleaser --clean --timeout 60m --skip=validate

.PHONY: destroy
destroy: ## Remove release from the CUR_VERSION
	@echo " > Deleting Release ${LOCAL_VERSION}"
	rm -rf dist
	git tag -d ${LOCAL_VERSION}
	git push origin :refs/tags/${LOCAL_VERSION}

build: ## Build ipsw
	@echo " > Building ipsw"
	@go mod download
	@CGO_ENABLED=1 go build -ldflags "-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=$(CUR_VERSION) -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppBuildCommit=$(CUR_COMMIT)" ./cmd/ipsw

.PHONY: build-ios
build-ios: ## Build ipsw for iOS
	@echo " > Building ipsw"
	@go mod download
	@CGO_ENABLED=1 GOOS=ios GOARCH=arm64 CC=$(shell go env GOROOT)/misc/ios/clangwrap.sh go build -ldflags "-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=$(CUR_VERSION) -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppBuildCommit==$(CUR_COMMIT)" ./cmd/ipsw
	@codesign --entitlements hack/make/data/ent.plist -s - -f ipsw

.PHONY: build-linux
build-linux: ## Build ipsw (linux)
	@echo " > Building ipsw (linux)"
	@go mod download
	@CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC='zig cc -target aarch64-linux-musl' CXX='zig c++ -target aarch64-linux-musl' go build -ldflags "-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=$(CUR_VERSION) -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppBuildCommit=$(CUR_COMMIT)" ./cmd/ipsw
	@echo " > Building ipswd (linux)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w --X github.com/blacktop/ipsw/api/types.BuildVersion=$(CUR_VERSION) -X github.com/blacktop/ipsw/api/types.BuildTime=$(date -u +%Y%m%d)" ./cmd/ipswd

.PHONY: docs
docs: ## Build the cli docs
	@echo " > Updating CLI Docs"
	go generate ./...
	hack/make/docs

.PHONY: docs-search
docs-search: ## Build/Update the docs search index
	@echo " > 🕸️ Crawling Docs 🕸️"
	@http -a ${CRAWLER_USER_ID}:${CRAWLER_API_KEY} POST "https://crawler.algolia.com/api/1/crawlers/${CRAWLER_ID}/reindex"

.PHONY: test-docs
test-docs: ## Start local server hosting docusaurus docs
	@echo " > Testing Docs"
	cd www; pnpm start

.PHONY: update_mod
update_mod: ## Update go.mod file
	@echo " > Updating go.mod"
	rm go.sum || true
	# go list -f '{{if not (or .Main .Indirect)}}{{.Path}}{{end}}' -m all | xargs --no-run-if-empty go get
	go mod download
	go mod tidy

.PHONY: update_devs
update_devs: ## Parse XCode database for new devices
	@echo " > Updating device_traits.json"
	go run ./cmd/ipsw/main.go device-list-gen pkg/xcode/data/device_traits.json

FSC_FLAGS ?=

.PHONY: update_fcs_keys
update_fcs_keys: ## Scrape the iPhoneWiki for AES keys
	@echo " > Updating fcs-keys.json"
	CGO_ENABLED=1 go run ./cmd/ipsw/main.go dl appledb --os iOS $(FSC_FLAGS) --fcs-keys-json --output pkg/aea/data/ --confirm
	@CGO_ENABLED=1 go run ./cmd/ipsw/main.go dl appledb --os macOS $(FSC_FLAGS) --fcs-keys-json --output pkg/aea/data/ --confirm
	@CGO_ENABLED=1 go run ./cmd/ipsw/main.go dl appledb --os visionOS $(FSC_FLAGS) --fcs-keys-json --output pkg/aea/data/ --confirm
	@hack/make/json_mini

.PHONY: update_fcs_keys_rc
update_fcs_keys_rc: FSC_FLAGS=--rc --latest ## Scrape the iPhoneWiki for AES keys
update_fcs_keys_rc: update_fcs_keys ## Scrape the iPhoneWiki for AES keys

.PHONY: update_fcs_keys_beta
update_fcs_keys_beta: FSC_FLAGS=--beta --latest ## Scrape the iPhoneWiki for AES keys
update_fcs_keys_beta: update_fcs_keys ## Scrape the iPhoneWiki for AES keys

FCS_IOS_BUILD ?=
FCS_MOS_BUILD ?=
FCS_VOS_BUILD ?=

.PHONY: update_fcs_keys_release
update_fcs_keys_release: ## Scrape the iPhoneWiki for AES keys
	@echo " > Updating fcs-keys.json"
	@CGO_ENABLED=1 go run ./cmd/ipsw/main.go  dl appledb --os iOS --build $(FCS_IOS_BUILD) --fcs-keys-json --output pkg/aea/data/ --confirm
	@CGO_ENABLED=1 go run ./cmd/ipsw/main.go  dl appledb --os macOS --build $(FCS_MOS_BUILD) --fcs-keys-json --output pkg/aea/data/ --confirm
	@CGO_ENABLED=1 go run ./cmd/ipsw/main.go  dl appledb --os visionOS --build $(FCS_VOS_BUILD) --fcs-keys-json --output pkg/aea/data/ --confirm
	@hack/make/json_mini

.PHONY: update_keys
update_keys: ## Scrape the iPhoneWiki for AES keys
	@echo " > Updating firmware_keys.json"
	CGO_ENABLED=0 go run ./cmd/ipsw/main.go key-list-gen pkg/info/data/firmware_keys.json

.PHONY: update_frida
update_frida: ## Updates the frida-core-devkits used in the frida cmd
	@echo " > Updating frida-core-devkits"
	@hack/make/frida-deps

.PHONY: update_proxy
update_proxy: ## Update the proxy pkgs
	@echo " > Updating proxy list"
	@GOPROXY=${IPSW_GO_PROXY} go mod download all
	@GOPROXY=${IPSW_GO_PROXY} go mod tidy

.PHONY: work-macho
work-macho: ## Work on go-macho package
	@echo " > Working on go-macho package"
	@go work init
	@go work use . ../go-macho

.PHONY: work-apfs
work-apfs: ## Work on go-apfs package
	@echo " > Working on go-apfs package"
	@go work init
	@go work use . ../go-apfs

.PHONY: docker
docker: ## Build docker image
	@echo " > Building Docker Image"
	docker build --build-arg VERSION=$(NEXT_VERSION) -t $(REPO)/$(NAME):$(NEXT_VERSION) .

.PHONY: docker-daemon
docker-daemon: ## Build daemon docker image
	@echo " > Building Docker Image"
	docker build --build-arg VERSION=$(NEXT_VERSION) -t $(REPO)/$(NAME)-daemon:$(NEXT_VERSION) -f Dockerfile.daemon .

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
