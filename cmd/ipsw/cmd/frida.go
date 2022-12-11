//go:build darwin && cgo && frida

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
	"fmt"
	"os"

	"github.com/apex/log"
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

func init() {
	rootCmd.AddCommand(fridaCmd)

	fridaCmd.Flags().BoolP("spawn", "s", false, "Spawn process")
	fridaCmd.Flags().StringP("name", "n", "", "Name of process")
	fridaCmd.Flags().StringArray("methods", []string{}, "Method selector like \"*[NSMutable* initWith*]\"")

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

		shouldSpawn := viper.GetBool("frida.spawn")
		procName := viper.GetString("frida.name")
		methods := viper.GetStringSlice("frida.methods")

		log.Info("[*] Frida Version: " + fridaVersion)

		mgr := frida.NewDeviceManager()

		devices, err := mgr.EnumerateDevices()
		if err != nil {
			return fmt.Errorf("failed to enumerate devices: %v", err)
		}

		for _, d := range devices {
			log.Infof("[*] Found device with id: %d", d.ID())
		}

		localDev, err := mgr.LocalDevice()
		if err != nil {
			return fmt.Errorf("failed to get local device: %v", err)
		}

		log.Infof("[*] Chosen device: %s", localDev.Name())

		var session *frida.Session
		if shouldSpawn {
			log.Infof("[*] Spawning process %s", procName)
			pid, err := localDev.Spawn(procName, nil)
			if err != nil {
				return fmt.Errorf("failed to spawn process: %v", err)
			}
			log.Infof("[*] Attaching to PID %d", pid)
			session, err = localDev.Attach(pid, nil)
			if err != nil {
				return fmt.Errorf("failed to attach to PID: %v", err)
			}
			defer session.Detach()
		} else {
			log.Infof("[*] Attaching to %s", procName)
			session, err = localDev.Attach(procName, nil)
			if err != nil {
				return fmt.Errorf("failed to attach to process: %v", err)
			}
			defer session.Detach()
		}

		script, err := session.CreateScript(script)
		if err != nil {
			return fmt.Errorf("error ocurred creating script: %v", err)
		}

		script.On("message", func(msg string) {
			log.Infof("[*] Received %s", msg)
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := ctrlc.Default.Run(ctx, func() error {
			if err := script.Load(); err != nil {
				return fmt.Errorf("error loading script: %v", err)
			}

			for _, m := range methods {
				log.Infof("[*] Hooking %s", m)
				script.ExportsCall("hook", m)
			}

			r := bufio.NewReader(os.Stdin)
			r.ReadLine()

			return nil
		}); err != nil {
			log.Warn("Exiting...")
		}

		return nil
	},
}
