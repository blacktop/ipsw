//go:build darwin && cgo

package render

/*
#cgo LDFLAGS: -framework AppKit -framework ImageIO -framework CoreGraphics
#include "render_darwin.h"
*/
import "C"

import (
	"fmt"
	"image"
	"runtime"
	"unsafe"

	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

func renderNative(data []byte, format string, width, height int) (image.Image, error) {
	// Keep an AppKit image's creation, drawing, and destruction on one thread.
	// Offscreen rendering works on worker threads and does not need NSApplication.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	kind := C.int(0)
	switch format {
	case "HEIF":
		kind = 1
	case "PDF ":
		kind = 2
	case "SVG ":
		kind = 3
	}
	var source *C.ipsw_car_render
	var sourceWidth, sourceHeight C.size_t
	// The bridge copies the source into CFData. It never retains Go memory.
	msg := C.ipsw_car_render_open((*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)), kind,
		C.size_t(pixel.MaxBytes), &source, &sourceWidth, &sourceHeight)
	if msg != nil {
		return nil, fmt.Errorf("render %s: %s", format, C.GoString(msg))
	}
	defer C.ipsw_car_render_close(source)
	if width == 0 {
		width, height = int(sourceWidth), int(sourceHeight)
	}
	if _, _, err := pixel.Layout(width, height, 4, 0); err != nil {
		return nil, err
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// CGContext borrows these pointer-free bytes only for this call.
	msg = C.ipsw_car_render_draw(source, C.size_t(width), C.size_t(height),
		(*C.uchar)(unsafe.Pointer(&img.Pix[0])), C.size_t(len(img.Pix)))
	if msg != nil {
		return nil, fmt.Errorf("render %s: %s", format, C.GoString(msg))
	}
	return img, nil
}
