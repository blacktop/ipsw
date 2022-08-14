# Contributing

By participating to this project, you agree to abide our [code of conduct](https://github.com/blacktop/ipsw/blob/master/.github/CODE_OF_CONDUCT.md).

## Setup your machine

`ipsw` is written in [Go](https://golang.org/).

Prerequisites:

- [Task](https://taskfile.dev/#/installation)
- [Go 1.19+](https://golang.org/doc/install)

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

A good way of making sure everything is all right is running the test suite:

```sh
make test
```

## Test your change

You can create a branch for your changes and try to build from the source as you go:

```sh
make build
```

When you are satisfied with the changes, we suggest you run:

```sh
task ci
```

Before you commit the changes, we also suggest you run:

```sh
task fmt
```

## Create a commit

Commit messages should be well formatted, and to make that "standardized", we
are using Conventional Commits.

You can follow the documentation on
[their website](https://www.conventionalcommits.org).

## Submit a pull request

Push your branch to your `ipsw` fork and open a pull request against the main branch.
