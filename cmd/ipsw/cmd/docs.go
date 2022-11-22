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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/blacktop/ipsw/cmd/ipsw/cmd/idev"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const fmTemplate = `---
id: %s
title: %s
hide_title: true
sidebar_label: %s
description: %s
last_update:
  date: %s
  author: blacktop
---
`

type link struct {
	Type  string `json:"type,omitempty"`
	Title string `json:"title,omitempty"`
}

type category struct {
	Label       string `json:"label,omitempty"`
	Collapsible bool   `json:"collapsible,omitempty"`
	Collapsed   bool   `json:"collapsed,omitempty"`
	Link        link   `json:"link,omitempty"`
}

func createCategoryJSON(cmd *cobra.Command, dir string) error {
	category, err := json.Marshal(&category{
		Label:       cmd.Name(),
		Collapsible: true,
		Collapsed:   true,
		Link: link{
			Type:  "generated-index",
			Title: cmd.Name(),
		},
	})
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(dir, "_category_.json"), category, 0644); err != nil {
		return err
	}
	return nil
}

func generateGroup(c *cobra.Command, dir string) error {
	os.MkdirAll(dir+c.Name(), 0750)
	if err := doc.GenMarkdownTreeCustom(c, dir+c.Name(), func(filename string) string {
		name := filepath.Base(filename)
		base := strings.TrimSuffix(name, path.Ext(name))
		subCmdName := strings.Split(base, "_")[len(strings.Split(base, "_"))-1]
		cc, _, err := c.Find([]string{subCmdName})
		if err != nil {
			return ""
		}
		return fmt.Sprintf(fmTemplate,
			base,
			strings.Replace(base, "_", " ", -1),
			subCmdName,
			cc.Short,
			time.Now().Format(time.RFC3339))
	}, func(s string) string {
		return fmt.Sprintf("/docs/cli/%s/%s", c.Name(), strings.TrimSuffix(s, ".md"))
	}); err != nil {
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
	SilenceUsage:          true,
	DisableFlagsInUseLine: true,
	Hidden:                true,
	Args:                  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rootCmd.Root().DisableAutoGenTag = true
		for _, c := range idev.IDevCmd.Commands() {
			if err := generateGroup(c, "www/docs/cli/idev/"); err != nil {
				return err
			}
		}
		for _, c := range cmd.Root().Commands() {
			if c.HasSubCommands() {
				if err := generateGroup(c, "www/docs/cli/"); err != nil {
					return err
				}
				// os.MkdirAll("www/docs/cli/"+c.Name(), 0750)
				// if err := doc.GenMarkdownTreeCustom(c, "www/docs/cli/"+c.Name(), func(filename string) string {
				// 	name := filepath.Base(filename)
				// 	base := strings.TrimSuffix(name, path.Ext(name))
				// 	subCmdName := strings.Split(base, "_")[len(strings.Split(base, "_"))-1]
				// 	cc, _, err := c.Find([]string{subCmdName})
				// 	if err != nil {
				// 		return ""
				// 	}
				// 	return fmt.Sprintf(fmTemplate,
				// 		base,
				// 		strings.Replace(base, "_", " ", -1),
				// 		subCmdName,
				// 		cc.Short,
				// 		time.Now().Format(time.RFC3339))
				// }, func(s string) string {
				// 	return fmt.Sprintf("/docs/cli/%s/%s", c.Name(), strings.TrimSuffix(s, ".md"))
				// }); err != nil {
				// 	return err
				// }
			} else {
				if !c.Hidden {
					if err := doc.GenMarkdownTreeCustom(c, "www/docs/cli/", func(filename string) string {
						name := filepath.Base(filename)
						base := strings.TrimSuffix(name, path.Ext(name))
						return fmt.Sprintf(fmTemplate,
							strings.Replace(base, "_", "-", -1),
							strings.Replace(base, "_", " ", -1),
							strings.Split(base, "_")[len(strings.Split(base, "_"))-1],
							c.Short,
							time.Now().Format(time.RFC3339))
					}, func(s string) string {
						return fmt.Sprintf("/docs/cli/%s/%s", c.Name(), strings.TrimSuffix(s, ".md"))
					}); err != nil {
						return err
					}
				} else {
					os.Remove("www/docs/cli/" + c.Name() + ".md")
				}
			}
		}
		// return doc.GenMarkdownTreeCustom(cmd.Root(), "www/docs/cli", filePrepender, func(s string) string {
		// 	return "/cli/" + strings.TrimSuffix(s, ".md") + "/"
		// })

		return nil
	},
}
