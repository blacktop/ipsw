//go:build darwin && cgo

package apsd

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: ${SRCDIR}/ApplePushService.tbd
#include <stdint.h>
#include "applepushservice.h"
const char* state(uint64_t style) {
	@autoreleasepool {
		[APSConnection finishLogin];
		return [[APSConnection connectionsDebuggingStateOfStyle:style] UTF8String];
	}
}
*/
import "C"

const (
	APSConnectionDefaultDebugStyle      = 1
	APSConnectionDefaultLLDBStyle       = 2
	APSConnectionDefaultJsonStyle       = 3
	APSConnectionDefaultPrettyJsonStyle = 4
	APSConnectionIosAndMacosDebugStyle  = 5
)

func State(style int) string {
	return C.GoString(C.state(C.uint64_t(style)))
}
