package decor

import (
	"fmt"
)

const (
	_ = iota
	UnitKiB
	UnitKB
)

// CountersNoUnit is a wrapper around Counters with no unit param.
func CountersNoUnit(pairFmt string, wcc ...WC) Decorator {
	return Counters(0, pairFmt, wcc...)
}

// CountersKibiByte is a wrapper around Counters with predefined unit
// UnitKiB (bytes/1024).
func CountersKibiByte(pairFmt string, wcc ...WC) Decorator {
	return Counters(UnitKiB, pairFmt, wcc...)
}

// CountersKiloByte is a wrapper around Counters with predefined unit
// UnitKB (bytes/1000).
func CountersKiloByte(pairFmt string, wcc ...WC) Decorator {
	return Counters(UnitKB, pairFmt, wcc...)
}

// Counters decorator with dynamic unit measure adjustment.
//
//	`unit` one of [0|UnitKiB|UnitKB] zero for no unit
//
//	`pairFmt` printf compatible verbs for current and total, like "%f" or "%d"
//
//	`wcc` optional WC config
//
// pairFmt example if unit=UnitKB:
//
//	pairFmt="%.1f / %.1f"   output: "1.0MB / 12.0MB"
//	pairFmt="% .1f / % .1f" output: "1.0 MB / 12.0 MB"
//	pairFmt="%d / %d"       output: "1MB / 12MB"
//	pairFmt="% d / % d"     output: "1 MB / 12 MB"
//
func Counters(unit int, pairFmt string, wcc ...WC) Decorator {
	var wc WC
	for _, widthConf := range wcc {
		wc = widthConf
	}
	wc.Init()
	if pairFmt == "" {
		pairFmt = "%d / %d"
	}
	d := &countersDecorator{
		WC:      wc,
		unit:    unit,
		pairFmt: pairFmt,
	}
	return d
}

type countersDecorator struct {
	WC
	unit        int
	pairFmt     string
	completeMsg *string
}

func (d *countersDecorator) Decor(st *Statistics) string {
	if st.Completed && d.completeMsg != nil {
		return d.FormatMsg(*d.completeMsg)
	}

	var res string
	switch d.unit {
	case UnitKiB:
		res = fmt.Sprintf(d.pairFmt, SizeB1024(st.Current), SizeB1024(st.Total))
	case UnitKB:
		res = fmt.Sprintf(d.pairFmt, SizeB1000(st.Current), SizeB1000(st.Total))
	default:
		res = fmt.Sprintf(d.pairFmt, st.Current, st.Total)
	}

	return d.FormatMsg(res)
}

func (d *countersDecorator) OnCompleteMessage(msg string) {
	d.completeMsg = &msg
}
