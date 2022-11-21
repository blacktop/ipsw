/*
Copyright © 2022 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/blacktop/ipsw/cmd/ipsw/cmd/download"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/dyld"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/idev"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/img4"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/kernel"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/macho"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/ota"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const fmTemplate = `---
date: %s
title: "%s"
slug: %s
url: %s
---
`

func init() {
	rootCmd.AddCommand(docsCmd)
}

// docsCmd represents the docs command
var docsCmd = &cobra.Command{
	Use:                   "docs",
	Short:                 "Generates ipsw's command line docs",
	SilenceUsage:          true,
	DisableFlagsInUseLine: true,
	Hidden:                true,
	Args:                  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCmd.Root().DisableAutoGenTag = true
		filePrepender := func(filename string) string {
			now := time.Now().Format(time.RFC3339)
			name := filepath.Base(filename)
			base := strings.TrimSuffix(name, path.Ext(name))
			url := "/commands/" + strings.ToLower(base) + "/"
			return fmt.Sprintf(fmTemplate, now, strings.Replace(base, "_", " ", -1), base, url)
		}
		doc.GenMarkdownTreeCustom(download.DownloadCmd, "www/docs/cmd/download", filePrepender, func(s string) string {
			return "/cmd/" + strings.TrimSuffix(s, ".md") + "/"
		})
		doc.GenMarkdownTreeCustom(dyld.DyldCmd, "www/docs/cmd/dyld", filePrepender, func(s string) string {
			return "/cmd/" + strings.TrimSuffix(s, ".md") + "/"
		})
		doc.GenMarkdownTreeCustom(idev.IDevCmd, "www/docs/cmd/idev", filePrepender, func(s string) string {
			return "/cmd/" + strings.TrimSuffix(s, ".md") + "/"
		})
		doc.GenMarkdownTreeCustom(img4.Img4Cmd, "www/docs/cmd/img4", filePrepender, func(s string) string {
			return "/cmd/" + strings.TrimSuffix(s, ".md") + "/"
		})
		doc.GenMarkdownTreeCustom(kernel.KernelcacheCmd, "www/docs/cmd/kernel", filePrepender, func(s string) string {
			return "/cmd/" + strings.TrimSuffix(s, ".md") + "/"
		})
		doc.GenMarkdownTreeCustom(macho.MachoCmd, "www/docs/cmd/macho", filePrepender, func(s string) string {
			return "/cmd/" + strings.TrimSuffix(s, ".md") + "/"
		})
		doc.GenMarkdownTreeCustom(ota.OtaCmd, "www/docs/cmd/ota", filePrepender, func(s string) string {
			return "/cmd/" + strings.TrimSuffix(s, ".md") + "/"
		})
		return nil
	},
}
