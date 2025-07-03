/*
Copyright © 2025 blacktop

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
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho/pkg/cpio"
	"github.com/blacktop/go-macho/pkg/xar"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/blacktop/ipsw/pkg/pkg/distrib"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(pkgCmd)

	// pkgCmd.Flags().BoolP("scripts", "s", false, "Show scripts")
	pkgCmd.Flags().BoolP("bom", "b", false, "Show BOM")
	pkgCmd.Flags().BoolP("pay", "l", false, "Show Payload")
	pkgCmd.Flags().BoolP("dist", "d", false, "Show distribution")
	pkgCmd.Flags().BoolP("scripts", "s", false, "Show scripts")
	pkgCmd.Flags().BoolP("all", "a", false, "Show all contents")
	pkgCmd.Flags().StringP("pattern", "p", "", "Extract files that match regex")
	pkgCmd.Flags().BoolP("flat", "f", false, "Do NOT preserve directory structure when extracting with --pattern")
	pkgCmd.Flags().StringP("output", "o", "", "Output folder")
	pkgCmd.MarkFlagDirname("output")
	// viper.BindPFlag("pkg.scripts", pkgCmd.Flags().Lookup("scripts"))
	viper.BindPFlag("pkg.bom", pkgCmd.Flags().Lookup("bom"))
	viper.BindPFlag("pkg.pay", pkgCmd.Flags().Lookup("pay"))
	viper.BindPFlag("pkg.dist", pkgCmd.Flags().Lookup("dist"))
	viper.BindPFlag("pkg.scripts", pkgCmd.Flags().Lookup("scripts"))
	viper.BindPFlag("pkg.all", pkgCmd.Flags().Lookup("all"))
	viper.BindPFlag("pkg.pattern", pkgCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("pkg.flat", pkgCmd.Flags().Lookup("flat"))
	viper.BindPFlag("pkg.output", pkgCmd.Flags().Lookup("output"))
}

// pkgCmd represents the pkg command
var pkgCmd = &cobra.Command{
	Use:           "pkg PKG",
	Short:         "🚧 List contents of a DMG/PKG file",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showPayload := viper.GetBool("pkg.pay")
		showBom := viper.GetBool("pkg.bom")
		showDistribution := viper.GetBool("pkg.dist")
		showScripts := viper.GetBool("pkg.scripts")
		showAll := viper.GetBool("pkg.all")
		pattern := viper.GetString("pkg.pattern")
		flat := viper.GetBool("pkg.flat")
		output := viper.GetString("pkg.output")

		var cwd string
		if len(output) == 0 {
			cwd, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current working directory: %w", err)
			}
			output = cwd
		}

		infile := filepath.Clean(args[0])

		if isXar, err := magic.IsXar(infile); err != nil {
			return fmt.Errorf("failed to check if file is a xar/pkg file: %w", err)
		} else if !isXar {
			return fmt.Errorf("file is not a dmg OR pkg file")
		}

		pkg, err := xar.Open(infile)
		if err != nil {
			return err
		}
		defer pkg.Close()
		if !pkg.ValidSignature() {
			log.Warn("PKG/XAR file signature is invalid, this may be a corrupted file")
		}
		if pattern != "" {
			found := false
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex pattern: '%s'", pattern)
			}
			var payload *xar.File
			for _, file := range pkg.Files {
				if strings.HasSuffix(file.Name, "Payload") {
					payload = file
				}
				if re.MatchString(file.Name) {
					found = true
					fname := filepath.Join(output, file.Name)
					if flat {
						fname = filepath.Join(output, filepath.Base(file.Name))
						utils.Indent(log.Info, 2)("Extracting " + strings.TrimPrefix(fname, cwd+"/"))
					} else {
						utils.Indent(log.Info, 2)("Extracting " + fname)
					}
					if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
						return err
					}
					in, err := file.Open()
					if err != nil {
						return err
					}
					defer in.Close()
					out, err := os.Create(fname)
					if err != nil {
						return err
					}
					defer out.Close()
					if _, err := io.Copy(out, in); err != nil {
						return err
					}
				}
			}
			if payload != nil {
				log.Infof("Checking for files in %s...", payload.Name)
				f, err := payload.Open()
				if err != nil {
					return err
				}
				var cr *cpio.Reader
				if IsPBZX, err := magic.IsPBZXData(f); err != nil {
					return fmt.Errorf("failed to check if %s file is a pbzx file: %w", payload.Name, err)
				} else if IsPBZX {
					f.Close() // dumb hack to reset the file pointer
					f, err = payload.Open()
					if err != nil {
						return err
					}
					defer f.Close()
					var pbuf bytes.Buffer
					if err := pbzx.Extract(context.Background(), f, &pbuf, runtime.NumCPU()); err != nil {
						return err
					}
					cr, err = cpio.NewReader(bytes.NewReader(pbuf.Bytes()), int64(pbuf.Len()))
					if err != nil {
						return err
					}
				} else {
					f.Close() // dumb hack to reset the file pointer
					f, err = payload.Open()
					if err != nil {
						return err
					}
					defer f.Close()
					gzr, err := gzip.NewReader(f)
					if err != nil {
						return err
					}
					defer gzr.Close()
					data, err := io.ReadAll(gzr)
					if err != nil {
						return err
					}
					cr, err = cpio.NewReader(bytes.NewReader(data), int64(len(data)))
					if err != nil {
						return fmt.Errorf("failed to create cpio reader from %s: %w", payload.Name, err)
					}
				}
				for _, file := range cr.Files {
					log.Debug(file.Name)
					if re.MatchString(file.Name) {
						found = true
						fname := filepath.Join(output, file.Name)
						if flat {
							fname = filepath.Join(output, filepath.Base(file.Name))
							utils.Indent(log.Info, 2)("Extracting " + strings.TrimPrefix(fname, cwd+"/"))
						} else {
							utils.Indent(log.Info, 2)("Extracting " + fname)
						}
						if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
							return err
						}
						in, err := file.Open()
						if err != nil {
							return err
						}
						defer in.Close()
						out, err := os.Create(fname)
						if err != nil {
							return err
						}
						defer out.Close()
						if _, err := io.Copy(out, in); err != nil {
							return err
						}
					}
				}
				if !found {
					log.Warnf("No files found that match pattern '%s'", pattern)
				}
			}
		} else {
			var names []string
			var payload *xar.File
			var bomFile *xar.File
			var scripts *xar.File
			var distribution *xar.File

			for _, file := range pkg.Files {
				names = append(names, file.Name)
				if strings.HasSuffix(file.Name, "Payload") {
					payload = file
				}
				if strings.Contains(file.Name, "Bom") {
					bomFile = file
				}
				if strings.Contains(file.Name, "Distribution") {
					distribution = file
				}
				if strings.Contains(file.Name, "Scripts") {
					scripts = file
				}
			}

			sort.StringSlice(names).Sort()

			if showAll || (!showBom && !showDistribution) {
				log.Info("Package contents")
				for _, name := range names {
					fmt.Println(name)
				}
			}

			if payload != nil && (showPayload || showAll) {
				log.Infof("Parsing %s...", payload.Name)
				f, err := payload.Open()
				if err != nil {
					return err
				}
				defer f.Close()
				var cr *cpio.Reader
				if IsPBZX, err := magic.IsPBZXData(f); err != nil {
					return fmt.Errorf("failed to check if %s file is a pbzx file: %w", payload.Name, err)
				} else if IsPBZX {
					f.Close() // dumb hack to reset the file pointer
					f, err = payload.Open()
					if err != nil {
						return err
					}
					defer f.Close()
					var pbuf bytes.Buffer
					if err := pbzx.Extract(context.Background(), f, &pbuf, runtime.NumCPU()); err != nil {
						return err
					}
					cr, err = cpio.NewReader(bytes.NewReader(pbuf.Bytes()), int64(pbuf.Len()))
					if err != nil {
						return err
					}
				} else {
					f.Close() // dumb hack to reset the file pointer
					f, err = payload.Open()
					if err != nil {
						return err
					}
					defer f.Close()
					gzr, err := gzip.NewReader(f)
					if err != nil {
						return err
					}
					defer gzr.Close()
					data, err := io.ReadAll(gzr)
					if err != nil {
						return err
					}
					cr, err = cpio.NewReader(bytes.NewReader(data), int64(len(data)))
					if err != nil {
						return fmt.Errorf("failed to create cpio reader from %s: %w", payload.Name, err)
					}
				}
				var keys []string
				for key := range maps.Keys(cr.Files) {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
				for _, key := range keys {
					if cr.Files[key].Info.Mode.IsDir() {
						// fmt.Fprintf(w, "%s\t%s\t%s\n", f.Mode(), f.ModTime().Format(time.RFC3339), f.Name())
					} else {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", cr.Files[key].Info.Mode, cr.Files[key].Info.Mtime.Format(time.RFC3339), humanize.Bytes(uint64(cr.Files[key].Size)), cr.Files[key].Name)
					}
				}
				w.Flush()
			}

			if bomFile != nil && (showBom || showAll) {
				log.Infof("Parsing %s...", bomFile.Name)
				f, err := bomFile.Open()
				if err != nil {
					return err
				}
				defer f.Close()

				data, err := io.ReadAll(f)
				if err != nil {
					return err
				}
				bm, err := bom.New(bytes.NewReader(data))
				if err != nil {
					return err
				}
				files, err := bm.GetPaths()
				if err != nil {
					return err
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
				for _, f := range files {
					if f.IsDir() {
						// fmt.Fprintf(w, "%s\t%s\t%s\n", f.Mode(), f.ModTime().Format(time.RFC3339), f.Name())
					} else {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), f.ModTime().Format(time.RFC3339), humanize.Bytes(uint64(f.Size())), f.Name())
					}
				}
				w.Flush()
			}

			if distribution != nil && (showDistribution || showAll) {
				log.Infof("Parsing %s...", distribution.Name)
				f, err := distribution.Open()
				if err != nil {
					return err
				}
				defer f.Close()
				dist, err := distrib.Read(f)
				if err != nil {
					return err
				}
				utils.Indent(log.Info, 2)("Distribution Scripts")
				if main, ok := dist.GetScripts()["main"]; ok {
					for _, script := range main {
						quick.Highlight(os.Stdout, script, "js", "terminal256", "nord")
					}
				}
			}

			if scripts != nil && (showScripts || showAll) {
				log.Infof("Checking for scripts in %s...", scripts.Name)
				sf, err := scripts.Open()
				if err != nil {
					return err
				}
				defer sf.Close()
				gzr, err := gzip.NewReader(sf)
				if err != nil {
					return fmt.Errorf("failed to create gzip reader: %v", err)
				}
				defer gzr.Close()
				var buf bytes.Buffer
				if _, err := io.Copy(&buf, gzr); err != nil {
					return fmt.Errorf("failed to read gzip data: %v", err)
				}
				cr, err := cpio.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
				if err != nil {
					return err
				}
				for _, file := range cr.Files {
					utils.Indent(log.Info, 2)(file.Name)
					openedFile, err := file.Open()
					if err != nil {
						return fmt.Errorf("failed to open file %s: %v", file.Name, err)
					}
					defer openedFile.Close()
					data, err := io.ReadAll(openedFile)
					if err != nil {
						return fmt.Errorf("failed to read file %s: %v", file.Name, err)
					}
					var lexerName string
					for line := range strings.Lines(string(data)) {
						switch {
						case strings.Contains(line, "perl"):
							lexerName = "perl"
						case strings.Contains(line, "python"):
							lexerName = "python"
						case strings.Contains(line, "bash"):
							lexerName = "bash"
						case strings.Contains(line, "sh"):
							lexerName = "sh"
						case strings.Contains(line, "zsh"):
							lexerName = "zsh"
						case strings.Contains(line, "fish"):
							lexerName = "fish"
						case strings.Contains(line, "ruby"):
							lexerName = "ruby"
						case strings.Contains(line, "php"):
							lexerName = "php"
						case strings.Contains(line, "lua"):
							lexerName = "lua"
						default:
							lexerName = "sh"
						}
						break
					}
					quick.Highlight(os.Stdout, string(data), lexerName, "terminal256", "nord")
				}
			}
		}

		return nil
	},
}
