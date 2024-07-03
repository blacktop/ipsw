//go:build tools

package main

import (
	_ "github.com/caarlos0/svu"
	_ "github.com/go-swagger/go-swagger/cmd/swagger"
	_ "github.com/goreleaser/goreleaser"
	_ "github.com/spf13/cobra-cli"
	_ "golang.org/x/perf/cmd/benchstat"
	_ "golang.org/x/tools/cmd/stringer"
)
