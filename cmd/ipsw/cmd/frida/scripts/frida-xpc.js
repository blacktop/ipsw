// CREDIT: https://github.com/NSEcho/gxpc/blob/main/script.js

const LIBXPC_PATH = "/usr/lib/system/libxpc.dylib";

// ObjC classes
const { NSData, NSPropertyListSerialization, NSXPCDecoder } = ObjC.classes;

// Intercept these functions
const xpc_connection_send_notification = Module.findExportByName(
  LIBXPC_PATH,
  "xpc_connection_send_notification"
);
const xpc_connection_send_message = Module.findExportByName(
  LIBXPC_PATH,
  "xpc_connection_send_message"
);
const xpc_connection_send_message_with_reply = Module.findExportByName(
  LIBXPC_PATH,
  "xpc_connection_send_message_with_reply"
);
const xpc_connection_send_message_with_reply_sync = Module.findExportByName(
  LIBXPC_PATH,
  "xpc_connection_send_message_with_reply_sync"
);
const xpc_connection_create_mach_service = Module.findExportByName(
  LIBXPC_PATH,
  "xpc_connection_create_mach_service"
);
const xpc_connection_set_event_handler = Module.findExportByName(
  LIBXPC_PATH,
  "xpc_connection_set_event_handler"
);

const __CFBinaryPlistCreate15 = DebugSymbol.fromName(
  "__CFBinaryPlistCreate15"
).address;
const _xpc_connection_call_event_handler = DebugSymbol.fromName(
  "_xpc_connection_call_event_handler"
).address;
const CFBinaryPlistCreate15 = new NativeFunction(
  __CFBinaryPlistCreate15,
  "pointer",
  ["pointer", "int", "pointer"]
);
const xpc_connection_call_event_handler = new NativeFunction(
  _xpc_connection_call_event_handler,
  "void",
  ["pointer", "pointer"]
);

// Use these functions to make sense out of xpc_object_t and xpc_connection_t
const xpc_connection_get_name = getFunc("xpc_connection_get_name", "pointer", [
  "pointer",
]);
const xpc_get_type = getFunc("xpc_get_type", "pointer", ["pointer"]);
const xpc_type_get_name = getFunc("xpc_type_get_name", "pointer", ["pointer"]);
const xpc_dictionary_get_value = getFunc(
  "xpc_dictionary_get_value",
  "pointer",
  ["pointer", "pointer"]
);
const xpc_string_get_string_ptr = getFunc(
  "xpc_string_get_string_ptr",
  "pointer",
  ["pointer"]
);
const xpc_copy_description = getFunc("xpc_copy_description", "pointer", [
  "pointer",
]);

const xpc_uint64_get_value = getFunc("xpc_uint64_get_value", "int", [
  "pointer",
]);
const xpc_int64_get_value = getFunc("xpc_int64_get_value", "int", ["pointer"]);
const xpc_double_get_value = getFunc("xpc_double_get_value", "double", [
  "pointer",
]);
const xpc_bool_get_value = getFunc("xpc_bool_get_value", "bool", ["pointer"]);
const xpc_uuid_get_bytes = getFunc("xpc_uuid_get_bytes", "pointer", [
  "pointer",
]);

const xpc_array_get_count = getFunc("xpc_array_get_count", "int", ["pointer"]);
const xpc_array_get_value = getFunc("xpc_array_get_value", "pointer", [
  "pointer",
  "int",
]);

const xpc_data_get_length = getFunc("xpc_data_get_length", "int", ["pointer"]);
const xpc_data_get_bytes = getFunc("xpc_data_get_bytes", "int", [
  "pointer",
  "pointer",
  "int",
  "int",
]);

const xpc_date_get_value = getFunc("xpc_date_get_value", "int64", ["pointer"]);

const xpc_connection_get_pid = getFunc("xpc_connection_get_pid", "int", [
  "pointer",
]);

// helper function that will create new NativeFunction
function getFunc(name, ret_type, args) {
  return new NativeFunction(
    Module.findExportByName(null, name),
    ret_type,
    args
  );
}

// get value type name from xpc_object_t
function getValueTypeName(val) {
  var valueType = xpc_get_type(val);
  var name = xpc_type_get_name(valueType);
  return Memory.readCString(name);
}

// create C string from JavaScript string
function cstr(str) {
  return Memory.allocUtf8String(str);
}

// get JavaScript string from C string
function rcstr(cstr) {
  return Memory.readCString(cstr);
}

// get C string from XPC string
function getXPCString(val) {
  var content = xpc_string_get_string_ptr(val);
  return rcstr(content);
}

// get human-readable date from Unix timestamp
function getXPCDate(val) {
  var nanoseconds = xpc_date_get_value(val);

  // Convert nanoseconds to milliseconds
  const timestampInMilliseconds = nanoseconds / 1000000;

  // Create a JavaScript Date object in UTC
  const date = new Date(timestampInMilliseconds);

  return {
    iso: date.toISOString(),
    nanoseconds: nanoseconds,
  };
}

function getXPCData(conn, dict, buff, n) {
  const hdr = buff.readCString(8);
  if (hdr == "bplist15") {
    const plist = CFBinaryPlistCreate15(buff, n, NULL);
    return ObjC.Object(plist).description().toString();
  } else if (hdr == "bplist17") {
    if (conn != null) {
      return parseBPList17(conn, dict);
    } else {
      return "cannot parse blplist17 for xpc_handler_t";
    }
  } else if (hdr == "bplist00") {
    const format = Memory.alloc(8);
    format.writeU64(0xaaaaaaaa);
    var ObjCData = NSData.dataWithBytes_length_(buff, n);
    const plist =
      NSPropertyListSerialization.propertyListWithData_options_format_error_(
        ObjCData,
        0,
        format,
        NULL
      );
    return ObjC.Object(plist).description().toString();
  } else {
    var ObjCData = NSData.dataWithBytes_length_(buff, n);
    var base64Encoded = ObjCData.base64EncodedStringWithOptions_(0).toString();
    return base64Encoded;
  }
}

function getKeys(description) {
  const rex = /(.*?)"\s=>\s/g;
  let matches = (description.match(rex) || []).map((e) => e.replace(rex, "$1"));
  var realMatches = [];
  var first = true;
  var depth = 0;
  for (var i in matches) {
    if (first) {
      depth = (matches[i].match(/\t/g) || []).length;
      first = false;
    }
    var elemDepth = (matches[i].match(/\t/g) || []).length;
    if (elemDepth == depth) {
      realMatches.push(matches[i].slice(2));
    }
  }
  return realMatches;
}

// https://github.com/nst/iOS-Runtime-Headers/blob/master/Frameworks/Foundation.framework/NSXPCDecoder.h
function parseBPList17(conn, dict) {
  var decoder = NSXPCDecoder.alloc().init();
  decoder["- set_connection:"](conn);
  decoder["- _startReadingFromXPCObject:"](dict);
  return decoder.debugDescription().toString();
}

function extract(conn, xpc_object, dict) {
  var ret = null;
  var xpc_object_type = getValueTypeName(xpc_object);
  switch (xpc_object_type) {
    case "dictionary":
      ret = {};
      dict = xpc_object;
      var keys = getKeys(rcstr(xpc_copy_description(xpc_object)));
      for (var i in keys) {
        var val = xpc_dictionary_get_value(dict, cstr(keys[i]));
        ret[keys[i]] = extract(conn, val, dict);
      }
      return ret;
    case "bool":
      return xpc_bool_get_value(xpc_object);
    case "uuid":
      return xpc_uuid_get_bytes(xpc_object);
    case "double":
      return xpc_double_get_value(xpc_object);
    case "string":
      return getXPCString(xpc_object);
    case "data":
      var dataLen = xpc_data_get_length(xpc_object);
      if (dataLen > 0) {
        var buff = Memory.alloc(Process.pointerSize * dataLen);
        var n = xpc_data_get_bytes(xpc_object, buff, 0, dataLen);
        return getXPCData(conn, dict, buff, n);
      } else {
        var empty = new Uint8Array();
        return empty;
      }
    case "uint64":
      return xpc_uint64_get_value(xpc_object);
    case "int64":
      return xpc_int64_get_value(xpc_object);
    case "date":
      return getXPCDate(xpc_object);
    case "array":
      ret = [];
      var count = xpc_array_get_count(xpc_object);
      for (var j = 0; j < count; j++) {
        var elem = xpc_array_get_value(xpc_object, j);
        var el = extract(conn, elem);
        ret.push(el);
      }
      return ret;
    default:
      return {};
  }
}

var ps = new NativeCallback(
  (fnName, conn, dict) => {
    var ret = {};
    var fname = rcstr(fnName);
    ret["name"] = fname;
    ret["connName"] = "UNKNOWN";
    ret["pid"] = xpc_connection_get_pid(conn);
    if (conn != null) {
      var connName = xpc_connection_get_name(conn);
      if (!connName.isNull()) {
        ret["connName"] = rcstr(connName);
      }
    }
    if (fname == "xpc_connection_set_event_handler") {
      var data = { blockImplementation: dict.toString() };
      ret["dictionary"] = data;
    } else {
      ret["dictionary"] = extract(conn, dict, dict);
    }
    send(JSON.stringify(ret));
  },
  "void",
  ["pointer", "pointer", "pointer"]
);

var cm_notification = new CModule(
  `
    #include <gum/guminterceptor.h>
    extern void ps(void*,void*,void*);
    
    void onEnter(GumInvocationContext * ic)
    {
        void * conn = gum_invocation_context_get_nth_argument(ic,0);
        void * obj = gum_invocation_context_get_nth_argument(ic,1);
        ps("xpc_connection_send_notification", conn, obj);
    }
`,
  { ps }
);

var cm_send_message = new CModule(
  `
    #include <gum/guminterceptor.h>
    extern void ps(void*,void*,void*);
    
    void onEnter(GumInvocationContext * ic)
    {
        void * conn = gum_invocation_context_get_nth_argument(ic,0);
        void * obj = gum_invocation_context_get_nth_argument(ic,1);
        ps("xpc_connection_send_message", conn, obj);
    }
`,
  { ps }
);

var cm_send_message_with_reply = new CModule(
  `
    #include <gum/guminterceptor.h>
    extern void ps(void*,void*,void*);
    
    void onEnter(GumInvocationContext * ic)
    {
        void * conn = gum_invocation_context_get_nth_argument(ic,0);
        void * obj = gum_invocation_context_get_nth_argument(ic,1);
        ps("xpc_connection_send_message_with_reply", conn, obj);
    }
`,
  { ps }
);

var cm_send_message_with_reply_sync = new CModule(
  `
    #include <gum/guminterceptor.h>
    extern void ps(void*,void*,void*);
    
    void onEnter(GumInvocationContext * ic)
    {
        void * conn = gum_invocation_context_get_nth_argument(ic,0);
        void * obj = gum_invocation_context_get_nth_argument(ic,1);
        ps("xpc_connection_send_message_with_reply_sync", conn, obj);
    }
`,
  { ps }
);

var cm_call_event_handler = new CModule(
  `
    #include <gum/guminterceptor.h>
    extern void ps(void*,void*,void*);
    
    void onEnter(GumInvocationContext * ic)
    {
        void * conn = gum_invocation_context_get_nth_argument(ic,0);
        void * obj = gum_invocation_context_get_nth_argument(ic,1);
        ps("xpc_connection_call_event_handler", conn, obj);
    }
`,
  { ps }
);

var psize = Memory.alloc(Process.pointerSize);
Memory.writeInt(psize, Process.pointerSize * 2);

var cm_set_event_handler = new CModule(
  `
    #include <gum/guminterceptor.h>
    extern int pointerSize;
    extern void ps(void*,void*,void*);
    
    void onEnter(GumInvocationContext * ic)
    {
        void * conn = gum_invocation_context_get_nth_argument(ic,0);
        void * obj = gum_invocation_context_get_nth_argument(ic,1);
        void * impl = obj + (pointerSize*2);
        ps("xpc_connection_set_event_handler", conn, impl);
    }
`,
  { pointerSize: psize, ps }
);

Interceptor.attach(xpc_connection_send_notification, cm_notification);
Interceptor.attach(xpc_connection_send_message, cm_send_message);
Interceptor.attach(
  xpc_connection_send_message_with_reply,
  cm_send_message_with_reply
);
Interceptor.attach(
  xpc_connection_send_message_with_reply_sync,
  cm_send_message_with_reply_sync
);
Interceptor.attach(xpc_connection_call_event_handler, cm_call_event_handler);

Interceptor.attach(xpc_connection_set_event_handler, cm_set_event_handler);

Interceptor.attach(xpc_connection_create_mach_service, {
  onEnter(args) {
    var ret = {};
    ret["connName"] = rcstr(args[0]);
    ret["name"] = "xpc_connection_create_mach_service";
    ret["dictionary"] = {
      "Service name": rcstr(args[0]),
    };
    send(JSON.stringify(ret));
  },
});
