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
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
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
	scriptData []byte // CREDIT: https://gist.github.com/aemmitt-ns/457f44bccac1eefc32e77e812fe27aff
)

var colorHeader = color.New(color.FgHiBlue).SprintFunc()
var colorFaint = color.New(color.Faint, color.FgHiBlue).SprintFunc()
var colorBold = color.New(color.Bold).SprintFunc()

type argument struct {
	TypeString        string `json:"typeString,omitempty"`
	TypeDescription   string `json:"typeDescription,omitempty"`
	Object            string `json:"object,omitempty"`
	ObjectDescription string `json:"objectDescription,omitempty"`
}

func (a argument) String() string {
	return fmt.Sprintf("\t\t%s (%s)", colorBold(a.TypeDescription), colorFaint(a.ObjectDescription))
}

type payload struct {
	TargetType         string     `json:"targetType,omitempty"`
	TargetClass        string     `json:"targetClass,omitempty"`
	TargetMethod       string     `json:"targetMethod,omitempty"`
	Args               []argument `json:"args,omitempty"`
	ReturnType         string     `json:"returnType,omitempty"`
	RetTypeDescription string     `json:"retTypeDescription,omitempty"`
	ReturnDescription  string     `json:"returnDescription,omitempty"`
}

func (p payload) String() string {
	var args []string
	for _, arg := range p.Args {
		args = append(args, arg.String())
	}
	return fmt.Sprintf("\t%s %s(\n%s\n\t) -> %s (%s)", colorBold(p.TargetType), colorHeader(p.TargetClass), strings.Join(args, ",\n"), colorBold(p.RetTypeDescription), colorFaint(p.ReturnDescription))
}

func init() {
	FridaCmd.AddCommand(fridaObjcCmd)

	fridaObjcCmd.Flags().BoolP("spawn", "s", false, "Spawn process")
	fridaObjcCmd.Flags().StringP("name", "n", "", "Name of process")
	fridaObjcCmd.Flags().StringArray("methods", []string{}, "Method selector like \"*[NSMutable* initWith*]\"")
	fridaObjcCmd.Flags().StringP("watch", "w", "", "Watch a script for changes and reload it automatically")
	fridaObjcCmd.MarkFlagRequired("name")
	fridaObjcCmd.MarkFlagRequired("methods")
	viper.BindPFlag("frida.objc.spawn", fridaObjcCmd.Flags().Lookup("spawn"))
	viper.BindPFlag("frida.objc.name", fridaObjcCmd.Flags().Lookup("name"))
	viper.BindPFlag("frida.objc.methods", fridaObjcCmd.Flags().Lookup("methods"))
	viper.BindPFlag("frida.objc.watch", fridaObjcCmd.Flags().Lookup("watch"))
}

// fridaObjcCmd represents the frida command
var fridaObjcCmd = &cobra.Command{
	Use:           "objc",
	Aliases:       []string{"o"},
	Short:         "Trace ObjC methods",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid := viper.GetString("frida.udid")
		shouldSpawn := viper.GetBool("frida.objc.spawn")
		procName := viper.GetString("frida.objc.name")
		methods := viper.GetStringSlice("frida.objc.methods")
		watch := viper.GetString("frida.objc.watch")

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

		log.Infof("Chosen device: %s", dev.Name())

		var session *frida.Session
		if shouldSpawn {
			log.Infof("Spawning process %s", procName)
			pid, err := dev.Spawn(procName, nil)
			if err != nil {
				return fmt.Errorf("failed to spawn process: %v", err)
			}
			log.Infof("Attaching to PID %d", pid)
			session, err = dev.Attach(pid, nil)
			if err != nil {
				return fmt.Errorf("failed to attach to PID: %v", err)
			}
			defer session.Detach()
		} else {
			log.WithField("proc", procName).Info("Attaching")
			session, err = dev.Attach(procName, nil)
			if err != nil {
				return fmt.Errorf("failed to attach to process: %v", err)
			}
			defer session.Detach()
		}

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
					var p payload
					if err := mapstructure.Decode(msg.Payload, &p); err != nil {
						log.Errorf("error decoding payload: %v", err)
					}
					log.Infof("Received '%s':\n%s", msg.Type, p)
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
			script, err := session.CreateScript(string(scriptData))
			if err != nil {
				return fmt.Errorf("error ocurred creating script: %v", err)
			}

			script.On("message", onMessage)

			if err := script.Load(); err != nil {
				return fmt.Errorf("error loading script: %v", err)
			}
		}

		session.On("detached", func(reason frida.SessionDetachReason) {
			log.Infof("session detached: reason='{%s}'", frida.SessionDetachReason(reason))
		})

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
			log.Warn("Detaching Session...")
		}

		return nil
	},
}
