//go:build darwin && frida

/*
Copyright © 2018-2023 blacktop

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
package frida

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/frida/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/caarlos0/ctrlc"
	"github.com/fatih/color"
	"github.com/frida/frida-go/frida"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	//go:embed scripts/frida-objc.js
	objcScriptData []byte // CREDIT: https://gist.github.com/aemmitt-ns/457f44bccac1eefc32e77e812fe27aff
)

func init() {
	FridaCmd.AddCommand(fridaObjcCmd)

	fridaObjcCmd.Flags().StringP("name", "n", "", "Name of process")
	fridaObjcCmd.Flags().IntP("pid", "p", -1, "PID of process")
	fridaObjcCmd.Flags().StringP("spawn", "s", "", "File to spawn")
	fridaObjcCmd.Flags().StringArrayP("args", "a", []string{}, "File spawn arguments")
	fridaObjcCmd.Flags().StringArrayP("methods", "m", []string{}, "Method selector like \"*[NSMutable* initWith*]\"")
	fridaObjcCmd.Flags().StringP("watch", "w", "", "Watch a script for changes and reload it automatically")
	fridaObjcCmd.MarkFlagRequired("methods")
	viper.BindPFlag("frida.objc.name", fridaObjcCmd.Flags().Lookup("name"))
	viper.BindPFlag("frida.objc.pid", fridaObjcCmd.Flags().Lookup("pid"))
	viper.BindPFlag("frida.objc.spawn", fridaObjcCmd.Flags().Lookup("spawn"))
	viper.BindPFlag("frida.objc.args", fridaObjcCmd.Flags().Lookup("args"))
	viper.BindPFlag("frida.objc.methods", fridaObjcCmd.Flags().Lookup("methods"))
	viper.BindPFlag("frida.objc.watch", fridaObjcCmd.Flags().Lookup("watch"))
}

// fridaObjcCmd represents the frida command
var fridaObjcCmd = &cobra.Command{
	Use:           "objc",
	Aliases:       []string{"o"},
	Short:         "Trace ObjC methods",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		udid := viper.GetString("frida.udid")
		procName := viper.GetString("frida.objc.name")
		procPID := viper.GetInt("frida.objc.pid")
		spawnPath := viper.GetString("frida.objc.spawn")
		spawnArgs := viper.GetStringSlice("frida.objc.args")
		methods := viper.GetStringSlice("frida.objc.methods")
		watch := viper.GetString("frida.objc.watch")
		// verify flag args
		if procPID == -1 && len(procName) == 0 && len(spawnPath) == 0 {
			return fmt.Errorf("must specify --name, --pid or --spawn")
		} else if len(spawnPath) > 0 && (procPID != -1 || len(procName) > 0) {
			return errors.New("cannot specify --spawn process AND --name OR --pid")
		} else if procPID != -1 && len(procName) > 0 {
			return errors.New("cannot specify both --name AND --pid")
		}

		log.WithField("version", fridaVersion).Info("Frida")

		mgr := frida.NewDeviceManager()
		mgr.EnumerateDevices()

		var err error
		var dev *frida.Device

		if len(udid) > 0 {
			dev, err = mgr.DeviceByID(udid)
			if err != nil {
				return fmt.Errorf("failed to get device by id %s: %v", udid, err)
			}
		} else {
			devices, err := mgr.EnumerateDevices()
			if err != nil {
				return fmt.Errorf("failed to enumerate devices: %v", err)
			}
			if len(devices) == 0 {
				return fmt.Errorf("no devices found")
			} else if len(devices) == 1 {
				dev = devices[0]
			} else {
				var selected int
				var choices []string
				for _, d := range devices {
					choices = append(choices, fmt.Sprintf("[%-6s] %s (%s)", strings.ToUpper(d.DeviceType().String()), d.Name(), d.ID()))
				}
				prompt := &survey.Select{
					Message: "Select what device to connect to:",
					Options: choices,
				}
				if err := survey.AskOne(prompt, &selected); err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				dev = devices[selected]
			}
		}

		log.Infof("Chosen device: %s", dev.Name())

		var session *frida.Session
		if len(spawnPath) > 0 {
			log.Infof("Spawning process '%s'", spawnPath)
			opts := frida.NewSpawnOptions()
			argv := make([]string, len(spawnArgs)+1)
			argv[0] = spawnPath
			for i, arg := range spawnArgs {
				argv[i+1] = arg
			}
			opts.SetArgv(argv)
			procPID, err = dev.Spawn(spawnPath, opts)
			if err != nil {
				return fmt.Errorf("error spawning '%s': %v", spawnPath, err)
			}
			session, err = dev.Attach(procPID, nil)
			if err != nil {
				return fmt.Errorf("failed to attach to spawned process with PID %d: %v", err, spawnPath, procPID)
			}
			defer session.Detach()
		} else {
			if procPID == -1 && len(procName) > 0 {
				processes, err := dev.EnumerateProcesses(frida.ScopeMinimal)
				if err != nil {
					return fmt.Errorf("error enumerating processes: %v", err)
				}
				found := false
				log.Debugf("Searching process '%s'", procName)
				for _, proc := range processes {
					utils.Indent(log.WithFields(log.Fields{
						"pid":  proc.PID(),
						"name": proc.Name(),
					}).Debug, 2)("Process")
					if proc.Name() == procName {
						procPID = proc.PID()
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("process '%s' not found", procName)
				}
				log.WithFields(log.Fields{
					"name": procName,
					"pid":  procPID,
				}).Info("Attaching to process")
			} else {
				log.Infof("Attaching to PID %d", procPID)
			}
			session, err = dev.Attach(procPID, nil)
			if err != nil {
				return fmt.Errorf("failed to attach to PID: %v", err)
			}
			defer session.Clean()
		}

		session.On("detached", func(reason frida.SessionDetachReason, crash *frida.Crash) {
			log.Warnf("session detached: reason='{%s}'", frida.SessionDetachReason(reason))
			if crash != nil {
				log.Errorf("session crash: %s %s", crash.Report(), crash.Summary())
			}
		})

		onMessage := func(data string) {
			msg, err := frida.ScriptMessageToMessage(data)
			if err != nil {
				log.Errorf("error parsing script message: %v", err)
			}
			switch msg.Type {
			case frida.MessageTypeError:
				log.WithFields(log.Fields{
					"line":   msg.LineNumber,
					"column": msg.ColumnNumber,
				}).Errorf("Received '%s' - %v", msg.Type, msg.Description)
			case frida.MessageTypeSend:
				if msg.IsPayloadMap {
					var p types.Payload
					if err := mapstructure.Decode(msg.Payload, &p); err != nil {
						log.Errorf("error decoding payload: %v", err)
					}
					log.Infof("Received '%s':\n%s", msg.Type, p)
					utils.Indent(log.Debug, 2)(fmt.Sprintf("Backtrace:\n\t%s", types.ColorFaint(p.Backtrace)))
				} else {
					log.Infof("Received '%s' - %s", msg.Type, msg.Payload)
				}
			case frida.MessageTypeLog:
				switch msg.Level {
				case frida.LevelTypeLog:
					log.Infof("Received '%s' - %v", msg.Type, msg.Payload)
				case frida.LevelTypeWarn:
					log.Warnf("Received '%s' - %v", msg.Type, msg.Payload)
				case frida.LevelTypeError:
					log.Errorf("Received '%s' - %v", msg.Type, msg.Payload)
				}
			default:
				log.Errorf("Received: (unknown) %v", msg)
			}
		}

		var script *frida.Script
		if len(watch) > 0 {
			compiler := frida.NewCompiler()
			compiler.On("output", func(bundle string) {
				if script != nil {
					log.Info("Unloading old bundle")
					if err := script.Unload(); err != nil {
						log.Errorf("error unloading script: %v", err)
					}
					script = nil
				}

				log.Info("Compiling bundle...")
				script, err = session.CreateScript(bundle)
				if err != nil {
					log.Errorf("error ocurred creating script: %v", err)
					return
				}

				script.On("message", onMessage)

				log.Info("Loading new bundle")
				if err := script.Load(); err != nil {
					log.Errorf("error loading script: %v", err)
				}
			})

			if err := compiler.Watch(watch); err != nil {
				return fmt.Errorf("error watching file: %v", err)
			}
			log.Infof("Watching %s for changes", watch)
		} else {
			script, err = session.CreateScript(string(objcScriptData))
			if err != nil {
				return fmt.Errorf("error ocurred creating script: %v", err)
			}

			script.On("message", onMessage)

			if err := script.Load(); err != nil {
				return fmt.Errorf("error loading script: %v", err)
			}
			defer script.Unload()
		}
		log.Info("Loaded script")

		if len(spawnPath) > 0 {
			if err := dev.Resume(procPID); err != nil {
				return fmt.Errorf("error resuming: %v", err)
			}
			log.Info("Resumed process")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := ctrlc.Default.Run(ctx, func() error {

			for _, m := range methods {
				utils.Indent(log.WithFields(log.Fields{
					"method": fmt.Sprintf("'%s'", m),
				}).Info, 2)("Hooking")
				script.ExportsCall("hook", m)
			}

			s := bufio.NewScanner(os.Stdin)
			for s.Scan() {
				fmt.Println(s.Text())
			}

			return nil
		}); err != nil {
			if errors.As(err, &ctrlc.ErrorCtrlC{}) {
				log.Warn("Detaching Session...")
			} else {
				return err
			}
		}

		return nil
	},
}
