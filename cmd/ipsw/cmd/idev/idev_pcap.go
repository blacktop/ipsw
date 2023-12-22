/*
Copyright © 2018-2024 blacktop

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
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	"github.com/blacktop/ipsw/pkg/usb/pcap"
	"github.com/caarlos0/ctrlc"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	IDevCmd.AddCommand(PcapCmd)

	PcapCmd.Flags().StringP("proc", "p", "", "process to get pcap for")
	PcapCmd.Flags().StringP("output", "o", "", "Folder to save pcap")
	PcapCmd.MarkFlagDirname("output")
}

// PcapCmd represents the pcap command
var PcapCmd = &cobra.Command{
	Use:           "pcap",
	Short:         "Dump network traffic",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid, _ := cmd.Flags().GetString("udid")
		proc, _ := cmd.Flags().GetString("proc")
		output, _ := cmd.Flags().GetString("output")

		var err error
		var dev *lockdownd.DeviceValues
		if len(udid) == 0 {
			dev, err = utils.PickDevice()
			if err != nil {
				return fmt.Errorf("failed to pick USB connected devices: %w", err)
			}
		} else {
			ldc, err := lockdownd.NewClient(udid)
			if err != nil {
				return fmt.Errorf("failed to connect to lockdownd: %w", err)
			}
			dev, err = ldc.GetValues()
			if err != nil {
				return fmt.Errorf("failed to get device values for %s: %w", udid, err)
			}
			ldc.Close()
		}

		cli, err := pcap.NewClient(dev.UniqueDeviceID)
		if err != nil {
			return fmt.Errorf("failed to connect to pcap: %w", err)
		}
		defer cli.Close()

		pcapName := fmt.Sprintf("%s.pcap", time.Now())
		pcapName = filepath.Join(output, fmt.Sprintf("%s_%s_%s", dev.ProductType, dev.HardwareModel, dev.BuildVersion), pcapName)
		if err := os.MkdirAll(filepath.Dir(pcapName), 0755); err != nil {
			return fmt.Errorf("failed to create pcap directory %s: %w", filepath.Dir(pcapName), err)
		}
		pcapfile, err := os.Create(pcapName)
		if err != nil {
			return fmt.Errorf("failed to create pcap file: %w", err)
		}
		defer pcapfile.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := ctrlc.Default.Run(ctx, func() error {
			if err := cli.ReadPacket(ctx, proc, pcapfile, func(hdr pcap.IOSPacketHeader, data []byte) {
				var subProc string
				if len(bytes.Trim(hdr.SubProcName[:], "\x00")) > 0 {
					subProc = fmt.Sprintf(", Sub Process %s[%s]", colorProc(string(hdr.SubProcName[:])), colorDebug(int32(bits.ReverseBytes32(hdr.SubPid))))
				}
				var sevice string
				if bits.ReverseBytes32(hdr.Svc) > 0 {
					sevice = fmt.Sprintf(", Service %s", colorDebug(int32(bits.ReverseBytes32(hdr.Svc))))
				}
				fmt.Printf("%s: Process %s[%s]%s%s, Interface: %s (%s) %s\n%s\n",
					colorTime(time.Unix(int64(hdr.Seconds), int64(hdr.MicroSeconds)).Format("02Jan06 15:04:05")),
					colorProc(string(hdr.ProcName[:])),
					colorDebug(int32(bits.ReverseBytes32(hdr.Pid))),
					subProc,
					sevice,
					colorDebug(string(hdr.InterfaceName[:])),
					colorLib(hdr.InterfaceType),
					colorNotice(hdr.ProtocolFamily),
					utils.HexDump(data, 0))
			}); err != nil {
				return fmt.Errorf("failed to read packets: %w", err)
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
