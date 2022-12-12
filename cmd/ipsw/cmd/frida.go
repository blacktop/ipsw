//go:build darwin && frida

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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/caarlos0/ctrlc"
	"github.com/frida/frida-go/frida"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const fridaVersion = "16.0.7"

// CREDIT: https://gist.github.com/aemmitt-ns/457f44bccac1eefc32e77e812fe27aff
var script = `
const typeMap = {
    "c": "char",
    "i": "int",
    "s": "short",
    "l": "long",
    "q": "long long",
    "C": "unsigned char",
    "I": "unsigned int",
    "S": "unsigned short",
    "L": "unsigned long",
    "Q": "unsigned long long",
    "f": "float",
    "d": "double",
    "B": "bool",
    "v": "void",
    "*": "char *",
    "@": "id",
    "#": "Class",
    ":": "SEL",
    "[": "Array",
    "{": "struct",
    "(": "union",
    "b": "Bitfield",
    "^": "*",
    "r": "char *",
    "?": "void *" // just so it works
};

const descMap = {
    "NSXPCConnection": (obj) => {
        return "service name: " + obj.serviceName();
    },
    "Protocol": (obj) => {
        return obj.description() + " " + object.name();
    },
    "NSString": (obj) => {
        return '@"' + obj.description() + '"';
    }
};

const descCache = {};

function getClassName(obj) {
    const object = new ObjC.Object(obj);
    if (object.$methods.indexOf("- className") != -1) {
        return object.className();
    } else {
        return "id"
    }
}

function getDescription(object) {
    const klass = object.class();
    const name = "" + object.className();
    if (!descCache[name]) {
        const klasses = Object.keys(descMap);
        for(let i = 0; i < klasses.length; i++) {
            let k = klasses[i];
            if (klass["+ isSubclassOfClass:"](ObjC.classes[k])) {
                return descMap[k](object);
            }
        }
    }
    descCache[name] = 1;
    if (object.$methods.indexOf("- description") != -1) {
        return "/* " + object.description() + " */ " + ptr(object);
    } else {
        return "" + ptr(object);
    }
}

function typeDescription(t, obj) {
    if (t != "@") {
        let p = "";
        let nt = t;
        if (t[0] == "^") {
            nt = t.substring(1);
            p = " *";
        }
        return typeMap[nt[0]] + p;
    } else {
        return getClassName(obj) + " *";
    }
}

function objectDescription(t, obj) {
    if (t == "@") {
        const object = new ObjC.Object(obj);
        return getDescription(object);
    } else if (t == "#") {
        const object = new ObjC.Object(obj);
        return "/* " + obj + " */ " + object.description();
    } else if (t == ":") {
        // const object = new ObjC.Object(obj);
        const description = "" + obj.readCString(); 
        return "/* " + description + " */ " + obj;
    } else if (t == "*" || t == "r*") {
        return '"' + obj.readCString() + '"';
    } else if ("ilsILS".indexOf(t) != -1) {
        return "" + obj.toInt32();
    } else {
        return "" + obj;
    }
}

const hookMethods = (selector) => {
    if(ObjC.available) {
        const resolver = new ApiResolver('objc');
        const matches = resolver.enumerateMatches(selector);

        matches.forEach(m => {
            // console.log(JSON.stringify(element));
            const name = m.name;
            const t = name[0];
            const klass = name.substring(2, name.length-1).split(" ")[0];
            const method = name.substring(2, name.length-1).split(" ")[1];
            const mparts = method.split(":");

            try {
                Interceptor.attach(m.address, {
                    onEnter(args)  {
                        const obj = new ObjC.Object(args[0]);
                        const sel = args[1];
                        const sig = obj["- methodSignatureForSelector:"](sel);
                        this.invocation = null;

                        if (sig !== null) {
                            this.invocation = {
                                "targetType": t,
                                "targetClass": klass,
                                "targetMethod": method,
                                "args": []
                            };

                            const nargs = sig["- numberOfArguments"]();
                            this.invocation.returnType = sig["- methodReturnType"]();
                            for(let i = 0; i < nargs; i++) {
                                // console.log(sig["- getArgumentTypeAtIndex:"](i));
                                const argtype = sig["- getArgumentTypeAtIndex:"](i);
                                this.invocation.args.push({
                                    "typeString": argtype,
                                    "typeDescription": typeDescription(argtype, args[i]),
                                    "object": args[i],
                                    "objectDescription": objectDescription(argtype, args[i])
                                });
                            }
                        }
                    },
                    onLeave(ret) {
                        if (this.invocation !== null) {
                            this.invocation.retTypeDescription = typeDescription(this.invocation.returnType, ret);
                            this.invocation.returnDescription = objectDescription(this.invocation.returnType, ret);
                            send(JSON.stringify(this.invocation));
                        }
                    }
                });
            } catch (err) {
                // sometimes it cant hook copyWithZone? dunno but its not good to hook it anyway.
                if (method != "copyWithZone:") {
                    console.log(` + "`" + `Could not hook [${klass} ${method}] : ${err}` + "`" + `);
                }
            }
        });
    }
}

rpc.exports.hook = hookMethods;
`

type arg struct {
	TypeString        string `json:"typeString,omitempty"`
	TypeDescription   string `json:"typeDescription,omitempty"`
	Object            string `json:"object,omitempty"`
	ObjectDescription string `json:"objectDescription,omitempty"`
}

type payload struct {
	TargetType         string `json:"targetType,omitempty"`
	TargetClass        string `json:"targetClass,omitempty"`
	TargetMethod       string `json:"targetMethod,omitempty"`
	Args               []arg  `json:"args,omitempty"`
	ReturnType         string `json:"returnType,omitempty"`
	RetTypeDescription string `json:"retTypeDescription,omitempty"`
	ReturnDescription  string `json:"returnDescription,omitempty"`
}

type message struct {
	Type         string  `json:"type,omitempty"`
	Payload      payload `json:"payload,omitempty"`
	Description  string  `json:"description,omitempty"`
	Stack        string  `json:"stack,omitempty"`
	FileName     string  `json:"fileName,omitempty"`
	LineNumber   int     `json:"lineNumber,omitempty"`
	ColumnNumber int     `json:"columnNumber,omitempty"`
}

type outterMsg struct {
	Type         string `json:"type,omitempty"`
	Payload      string `json:"payload,omitempty"`
	Description  string `json:"description,omitempty"`
	Stack        string `json:"stack,omitempty"`
	FileName     string `json:"fileName,omitempty"`
	LineNumber   int    `json:"lineNumber,omitempty"`
	ColumnNumber int    `json:"columnNumber,omitempty"`
}

func init() {
	rootCmd.AddCommand(fridaCmd)

	fridaCmd.Flags().StringP("udid", "u", "", "Device UniqueDeviceID to connect to")
	fridaCmd.Flags().BoolP("spawn", "s", false, "Spawn process")
	fridaCmd.Flags().StringP("name", "n", "", "Name of process")
	fridaCmd.Flags().StringArray("methods", []string{}, "Method selector like \"*[NSMutable* initWith*]\"")
	fridaCmd.MarkFlagRequired("name")
	fridaCmd.MarkFlagRequired("methods")
	viper.BindPFlag("frida.udid", fridaCmd.Flags().Lookup("udid"))
	viper.BindPFlag("frida.spawn", fridaCmd.Flags().Lookup("spawn"))
	viper.BindPFlag("frida.name", fridaCmd.Flags().Lookup("name"))
	viper.BindPFlag("frida.methods", fridaCmd.Flags().Lookup("methods"))
}

// fridaCmd represents the frida command
var fridaCmd = &cobra.Command{
	Use:           "frida",
	Short:         "Trace ObjC methods using Frida",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		udid := viper.GetString("frida.udid")
		shouldSpawn := viper.GetBool("frida.spawn")
		procName := viper.GetString("frida.name")
		methods := viper.GetStringSlice("frida.methods")

		log.WithField("version", fridaVersion).Info("Frida")

		mgr := frida.NewDeviceManager()

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

			var choices []string
			for _, d := range devices {
				choices = append(choices, fmt.Sprintf("[%-6s] %s (%s)", strings.ToUpper(d.DeviceType().String()), d.Name(), d.ID()))
			}
			var selected int
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

		script, err := session.CreateScript(script)
		if err != nil {
			return fmt.Errorf("error ocurred creating script: %v", err)
		}

		script.On("message", func(data string) {
			log.Debug(data)
			var m outterMsg
			var p payload
			if err := json.Unmarshal([]byte(data), &m); err != nil {
				log.Warnf("Error parsing message: %v", err)
			}
			if len(m.Payload) > 0 {
				if err := json.Unmarshal([]byte(m.Payload), &p); err != nil {
					log.Warnf("Error parsing message: %v", err)
				}
			}
			if m.Type == "error" {
				log.Errorf("Error: %v", m)
			} else {
				log.Infof("Received '%s' - %v", m.Type, p)
			}
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := ctrlc.Default.Run(ctx, func() error {
			if err := script.Load(); err != nil {
				return fmt.Errorf("error loading script: %v", err)
			}

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
