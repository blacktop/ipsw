# Contributing

By participating in this project, you agree to abide by our [code of conduct](https://github.com/blacktop/ipsw/blob/master/.github/CODE_OF_CONDUCT.md).

`ipsw` is a maintainer-driven project. Clear, well-scoped, well-tested contributions are much easier to land than broad speculative changes.

## The Critical Rule

You must understand what you are submitting.

If you open an issue, discussion, or pull request that used AI assistance, you must still be able to explain the problem, the proposed change, and the relevant tradeoffs in your own words. If you cannot explain the work without relying on the AI tool, do not submit it.

## AI Usage

AI tools are allowed, but low-effort AI submissions are not.

Please read the full [AI Usage Policy](AI_POLICY.md) before opening an issue or pull request. The short version is:

- Disclose any material AI assistance.
- Review and edit AI-assisted text before posting it.
- Do not submit code, repro steps, logs, analysis, or conclusions you do not personally understand and verify.
- Maintainers may close low-effort or undisclosed AI-assisted issues and pull requests without detailed review.

## Before You Open an Issue

- Search existing open and closed issues first.
- Use [GitHub Discussions](https://github.com/blacktop/ipsw/discussions) for questions, early design ideas, and anything that is not yet actionable.
- Use the bug report template for reproducible bugs and include the exact command, firmware or Mach-O you were analyzing, and `ipsw version`.
- Use the feature request template for concrete enhancements.
- If AI helped draft the report, disclose that and trim the write-up down to the facts that matter.

## Before You Open a Pull Request

- For non-trivial changes, start from an existing issue or discussion so the work is scoped before implementation.
- Keep pull requests focused. Small, reviewable changes land faster.
- If AI assisted with the patch or the PR text, disclose the tool and scope of use.
- Be ready to explain the change, defend the approach, and follow up on review feedback yourself.

## Setup Your Machine

`ipsw` is written in [Go](https://golang.org/).

Prerequisites:

- [Go 1.26+](https://go.dev/doc/install)

Other things you might need to run the tests:

- [Buildpacks](https://buildpacks.io/)
- [cosign](https://github.com/sigstore/cosign)
- [Docker](https://www.docker.com/)
- [GPG](https://gnupg.org)
- [Podman](https://podman.io/)
- [Snapcraft](https://snapcraft.io/)

Clone `ipsw` anywhere:

```sh
git clone git@github.com:blacktop/ipsw.git
```

`cd` into the directory and install the dependencies:

```sh
make setup
```

A good way to make sure everything is working is to run the Go test suite:

```sh
go test ./...
```

## Test Your Change

Create a branch for your changes and build from source as you go:

```sh
make build
```

Before you open a pull request, run the relevant tests for your change and make sure the CLI still builds:

```sh
go test ./...
make build
```

Before you commit, also run:

```sh
make fmt
```

## Create a Commit

Commit messages should be well formatted. This project uses [Conventional Commits](https://www.conventionalcommits.org).

## Submit a Pull Request

Push your branch to your `ipsw` fork and open a pull request against the `master` branch.
