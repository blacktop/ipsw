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
package idev

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/syslog"
	"github.com/caarlos0/ctrlc"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var loc *time.Location

func init() {
	IDevCmd.AddCommand(SyslogCmd)

	SyslogCmd.Flags().Uint64P("timeout", "t", 0, "Log timeout in seconds")
	viper.BindPFlag("idev.syslog.timeout", SyslogCmd.Flags().Lookup("timeout"))
}

var colorTime = colors.BoldHiBlue().SprintFunc()
var colorProc = colors.BoldHiMagenta().SprintFunc()
var colorLib = colors.BoldHiCyan().SprintFunc()
var colorNotice = colors.BoldHiGreen().SprintFunc()
var colorError = colors.BoldHiRed().SprintFunc()
var colorErrorMsg = colors.FaintHiRed().SprintFunc()
var colorWarning = colors.BoldHiYellow().SprintFunc()
var colorWarningMsg = colors.Yellow().SprintFunc()
var colorDebug = colors.BoldHiWhite().SprintFunc()

func colorSyslog(line string) string {
	re := regexp.MustCompile(`(?s)(?P<date>\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?P<device>\S+)\s(?P<proc>[a-zA-Z]+)(\((?P<lib>\S+)\))?\[(?P<pid>\S+)\]\s(?P<type>\S+)\s(?P<msg>.*)\n$`)
	return re.ReplaceAllStringFunc(line, func(s string) string {
		matches := re.FindStringSubmatch(line)
		level := strings.Trim(matches[7], "<>:")
		body := matches[8]
		switch level {
		case "Notice":
			level = colorNotice(level)
		case "Error":
			level = colorError(level)
			body = colorErrorMsg(body)
		case "Warning":
			level = colorWarning(level)
			body = colorWarningMsg(body)
		case "Debug":
			level = colorDebug(level)
		default:
			level = colorDebug(level)
		}
		t, _ := time.Parse(time.Stamp, matches[1])
		t = t.AddDate(time.Now().Year(), 0, 0)
		var lib string
		if matches[5] != "" {
			lib = fmt.Sprintf("(%s)", colorLib(matches[5]))
		}
		proc := fmt.Sprintf("%s%s[%s]", colorProc(matches[3]), lib, colorDebug(matches[6]))
		return colorTime(t.In(loc).Format("02Jan2006 15:04:05 MST")) + " " + level + " " + proc + " " + body
	})
}

// SyslogCmd represents the syslog command
var SyslogCmd = &cobra.Command{
	Use:           "syslog",
	Short:         "Dump syslog lines",
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		udid := viper.GetString("idev.udid")
		timeout := viper.GetDuration("idev.syslog.timeout")

		if len(udid) == 0 {
			dev, err := utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
			udid = dev.UniqueDeviceID
			loc, _ = time.LoadLocation(dev.TimeZone)
		}

		var ctx context.Context
		var cancel context.CancelFunc
		if timeout > 0 {
			ctx, cancel = context.WithTimeout(context.Background(), timeout)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
		}
		defer cancel()

		if err := ctrlc.Default.Run(ctx, func() error {
			r, err := syslog.Syslog(udid)
			if err != nil {
				return err
			}
			defer r.Close()

			if colors.Active() {
				br := bufio.NewReader(r)
				for {
					line, err := br.ReadString('\x00')
					if err != nil {
						if err == io.EOF {
							break
						}
						return fmt.Errorf("failed to read syslog line: %w", err)
					}
					fmt.Println(colorSyslog(strings.Trim(line, "\x00")))
				}
			} else {
				_, err = io.Copy(os.Stdout, r)
				return err
			}
			return nil
		}); err != nil {
			if errors.As(err, &ctrlc.ErrorCtrlC{}) {
				log.Warn("Exiting...")
			} else {
				return err
			}
		}

		return nil
	},
}
