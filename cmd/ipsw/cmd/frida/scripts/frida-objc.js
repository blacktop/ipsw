// CREDIT: https://gist.github.com/aemmitt-ns/457f44bccac1eefc32e77e812fe27aff
const typeMap = {
  c: "char",
  i: "int",
  s: "short",
  l: "long",
  q: "long long",
  C: "unsigned char",
  I: "unsigned int",
  S: "unsigned short",
  L: "unsigned long",
  Q: "unsigned long long",
  f: "float",
  d: "double",
  B: "bool",
  v: "void",
  "*": "char *",
  "@": "id",
  "#": "Class",
  ":": "SEL",
  "[": "Array",
  "{": "struct",
  "(": "union",
  b: "Bitfield",
  "^": "*",
  r: "char *",
  "?": "void *", // just so it works
};

const descMap = {
  NSXPCConnection: (obj) => {
    return "service name: " + obj.serviceName();
  },
  Protocol: (obj) => {
    return obj.description() + " " + object.name();
  },
  NSString: (obj) => {
    return '@"' + obj.description() + '"';
  },
};

const descCache = {};

function getClassName(obj) {
  const object = new ObjC.Object(obj);
  if (object.$methods.indexOf("- className") != -1) {
    return object.className();
  } else {
    return "id";
  }
}

function getDescription(object) {
  const klass = object.class();
  const name = "" + object.className();
  if (!descCache[name]) {
    const klasses = Object.keys(descMap);
    for (let i = 0; i < klasses.length; i++) {
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
  if (ObjC.available) {
    const resolver = new ApiResolver("objc");
    const matches = resolver.enumerateMatches(selector);

    matches.forEach((m) => {
      // console.log(JSON.stringify(element));
      const name = m.name;
      const t = name[0];
      const klass = name.substring(2, name.length - 1).split(" ")[0];
      const method = name.substring(2, name.length - 1).split(" ")[1];
      const mparts = method.split(":");

      try {
        Interceptor.attach(m.address, {
          onEnter(args) {
            const obj = new ObjC.Object(args[0]);
            const sel = args[1];
            console.log(`obj: ${obj}, sel: ${sel}`);
            if (obj !== null && sel !== null) {
              const sig = obj["- methodSignatureForSelector:"](sel);
              this.invocation = null;

              if (sig !== null) {
                this.invocation = {
                  targetType: t,
                  targetClass: klass,
                  targetMethod: method,
                  args: [],
                };

                const nargs = sig["- numberOfArguments"]();
                this.invocation.returnType = sig["- methodReturnType"]();
                for (let i = 0; i < nargs; i++) {
                  // console.log(sig["- getArgumentTypeAtIndex:"](i));
                  const argtype = sig["- getArgumentTypeAtIndex:"](i);
                  this.invocation.args.push({
                    typeString: argtype,
                    typeDescription: typeDescription(argtype, args[i]),
                    object: args[i],
                    objectDescription: objectDescription(argtype, args[i]),
                  });
                }
              }
            }
          },
          onLeave(ret) {
            if (this.invocation !== null) {
              this.invocation.retTypeDescription = typeDescription(
                this.invocation.returnType,
                ret
              );
              this.invocation.returnDescription = objectDescription(
                this.invocation.returnType,
                ret
              );
              send(JSON.stringify(this.invocation));
            }
          },
        });
      } catch (err) {
        // sometimes it cant hook copyWithZone? dunno but its not good to hook it anyway.
        if (method != "copyWithZone:") {
          console.log(`Could not hook [${klass} ${method}] : ${err}`);
        }
      }
    });
  }
};

rpc.exports.hook = hookMethods;
