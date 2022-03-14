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
	"github.com/spf13/cobra"
)

// vmCmd represents the vm command
var vmCmd = &cobra.Command{
	Use:   "vm",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {

		// vz.NewVirtualMachineConfiguration()
		// bootLoader := vz.NewLinuxBootLoader(
		// 	vmlinuz,
		// 	vz.WithCommandLine(strings.Join(kernelCommandLineArguments, " ")),
		// 	vz.WithInitrd(initrd),
		// )
		// log.Println("bootLoader:", bootLoader)

		// config := vz.NewVirtualMachineConfiguration(
		// 	bootLoader,
		// 	1,
		// 	2*1024*1024*1024,
		// )

		// setRawMode(os.Stdin)

		// // console
		// serialPortAttachment := vz.NewFileHandleSerialPortAttachment(os.Stdin, os.Stdout)
		// consoleConfig := vz.NewVirtioConsoleDeviceSerialPortConfiguration(serialPortAttachment)
		// config.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{
		// 	consoleConfig,
		// })

		// // network
		// natAttachment := vz.NewNATNetworkDeviceAttachment()
		// networkConfig := vz.NewVirtioNetworkDeviceConfiguration(natAttachment)
		// config.SetNetworkDevicesVirtualMachineConfiguration([]*vz.VirtioNetworkDeviceConfiguration{
		// 	networkConfig,
		// })
		// networkConfig.SetMACAddress(vz.NewRandomLocallyAdministeredMACAddress())

		// // entropy
		// entropyConfig := vz.NewVirtioEntropyDeviceConfiguration()
		// config.SetEntropyDevicesVirtualMachineConfiguration([]*vz.VirtioEntropyDeviceConfiguration{
		// 	entropyConfig,
		// })

		// diskImageAttachment, err := vz.NewDiskImageStorageDeviceAttachment(
		// 	diskPath,
		// 	false,
		// )
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// storageDeviceConfig := vz.NewVirtioBlockDeviceConfiguration(diskImageAttachment)
		// config.SetStorageDevicesVirtualMachineConfiguration([]vz.StorageDeviceConfiguration{
		// 	storageDeviceConfig,
		// })

		// // traditional memory balloon device which allows for managing guest memory. (optional)
		// config.SetMemoryBalloonDevicesVirtualMachineConfiguration([]vz.MemoryBalloonDeviceConfiguration{
		// 	vz.NewVirtioTraditionalMemoryBalloonDeviceConfiguration(),
		// })

		// // socket device (optional)
		// config.SetSocketDevicesVirtualMachineConfiguration([]vz.SocketDeviceConfiguration{
		// 	vz.NewVirtioSocketDeviceConfiguration(),
		// })
		// validated, err := config.Validate()
		// if !validated || err != nil {
		// 	log.Fatal("validation failed", err)
		// }

		// vm := vz.NewVirtualMachine(config)

		// signalCh := make(chan os.Signal, 1)
		// signal.Notify(signalCh, syscall.SIGTERM)

		// errCh := make(chan error, 1)

		// vm.Start(func(err error) {
		// 	if err != nil {
		// 		errCh <- err
		// 	}
		// })

		// for {
		// 	select {
		// 	case <-signalCh:
		// 		result, err := vm.RequestStop()
		// 		if err != nil {
		// 			log.Println("request stop error:", err)
		// 			return
		// 		}
		// 		log.Println("recieved signal", result)
		// 	case newState := <-vm.StateChangedNotify():
		// 		if newState == vz.VirtualMachineStateRunning {
		// 			log.Println("start VM is running")
		// 		}
		// 		if newState == vz.VirtualMachineStateStopped {
		// 			log.Println("stopped successfully")
		// 			return
		// 		}
		// 	case err := <-errCh:
		// 		log.Println("in start:", err)
		// 	}
		// }

	},
}

func init() {
	rootCmd.AddCommand(vmCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// vmCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// vmCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
