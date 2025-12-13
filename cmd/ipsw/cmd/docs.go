/*
Copyright © 2018-2025 blacktop

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
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const fmTemplate = `---
id: %s
title: %s
hide_title: true
hide_table_of_contents: true
sidebar_label: %s
description: %s
---
`

func GenMarkdownTreeCustom(cmd *cobra.Command, dir string, filePrepender func(string, string) string, linkHandler func(string) string) error {
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := GenMarkdownTreeCustom(c, dir, filePrepender, linkHandler); err != nil {
			return err
		}
	}

	basename := strings.ReplaceAll(cmd.CommandPath(), " ", "/")

	var filename string
	if cmd.HasSubCommands() {
		filename = filepath.Join(dir, basename, cmd.Name()+".md")
	} else {
		filename = filepath.Join(dir, basename+".md")
	}

	os.MkdirAll(filepath.Dir(filename), 0750)

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.WriteString(f, filePrepender(filename, cmd.Short)); err != nil {
		return err
	}
	if err := doc.GenMarkdownCustom(cmd, f, linkHandler); err != nil {
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(docsCmd)
}

// docsCmd represents the docs command
var docsCmd = &cobra.Command{
	Use:                   "docs",
	Short:                 "Generates ipsw's command line docs",
	DisableFlagsInUseLine: true,
	Hidden:                true,
	Args:                  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCmd.Root().DisableAutoGenTag = true

		if err := GenMarkdownTreeCustom(cmd.Root(), "www/docs/cli/", func(filename, description string) string {
			name := filepath.Base(filename)
			base := strings.TrimSuffix(name, path.Ext(name))
			subCmdName := strings.Split(base, "_")[len(strings.Split(base, "_"))-1]
			return fmt.Sprintf(fmTemplate,
				base,
				strings.Replace(base, "_", " ", -1),
				subCmdName,
				description)
		}, func(s string) string {
			s = strings.TrimSuffix(s, ".md")
			if s == "ipsw.md" {
				return "/docs/cli/ipsw"
			}
			return filepath.Join("/docs/cli/", filepath.Join(strings.Split(s, "_")...))
		}); err != nil {
			return err
		}

		return nil
	},
}
