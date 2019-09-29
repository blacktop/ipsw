package decor

import (
	"fmt"
	"io"
	"math"
	"time"

	"github.com/VividCortex/ewma"
)

type speedType struct {
	fmt.Formatter
}

func (self *speedType) Format(st fmt.State, verb rune) {
	self.Formatter.Format(st, verb)
	io.WriteString(st, "/s")
}

// EwmaSpeed exponential-weighted-moving-average based speed decorator.
// Note that it's necessary to supply bar.Incr* methods with incremental
// work duration as second argument, in order for this decorator to
// work correctly. This decorator is a wrapper of MovingAverageSpeed.
func EwmaSpeed(unit int, format string, age float64, wcc ...WC) Decorator {
	var average MovingAverage
	if age == 0 {
		average = ewma.NewMovingAverage()
	} else {
		average = ewma.NewMovingAverage(age)
	}
	return MovingAverageSpeed(unit, format, average, wcc...)
}

// MovingAverageSpeed decorator relies on MovingAverage implementation
// to calculate its average.
//
//	`unit` one of [0|UnitKiB|UnitKB] zero for no unit
//
//	`format` printf compatible verb for value, like "%f" or "%d"
//
//	`average` MovingAverage implementation
//
//	`wcc` optional WC config
//
// format examples:
//
//	unit=UnitKiB, format="%.1f"  output: "1.0MiB/s"
//	unit=UnitKiB, format="% .1f" output: "1.0 MiB/s"
//	unit=UnitKB,  format="%.1f"  output: "1.0MB/s"
//	unit=UnitKB,  format="% .1f" output: "1.0 MB/s"
//
func MovingAverageSpeed(unit int, format string, average MovingAverage, wcc ...WC) Decorator {
	var wc WC
	for _, widthConf := range wcc {
		wc = widthConf
	}
	if format == "" {
		format = "%.0f"
	}
	wc.Init()
	d := &movingAverageSpeed{
		WC:       wc,
		average:  average,
		producer: chooseSpeedProducer(unit, format),
	}
	return d
}

type movingAverageSpeed struct {
	WC
	producer    func(float64) string
	average     ewma.MovingAverage
	msg         string
	completeMsg *string
}

func (d *movingAverageSpeed) Decor(st *Statistics) string {
	if st.Completed {
		if d.completeMsg != nil {
			return d.FormatMsg(*d.completeMsg)
		}
		return d.FormatMsg(d.msg)
	}

	var speed float64
	if v := math.Round(d.average.Value()); v != 0 {
		speed = 1 / time.Duration(v).Seconds()
	}

	d.msg = d.producer(speed)
	return d.FormatMsg(d.msg)
}

func (d *movingAverageSpeed) NextAmount(n int64, wdd ...time.Duration) {
	var workDuration time.Duration
	for _, wd := range wdd {
		workDuration = wd
	}
	durPerByte := float64(workDuration) / float64(n)
	if math.IsInf(durPerByte, 0) || math.IsNaN(durPerByte) {
		return
	}
	d.average.Add(durPerByte)
}

func (d *movingAverageSpeed) OnCompleteMessage(msg string) {
	d.completeMsg = &msg
}

// AverageSpeed decorator with dynamic unit measure adjustment. It's
// a wrapper of NewAverageSpeed.
func AverageSpeed(unit int, format string, wcc ...WC) Decorator {
	return NewAverageSpeed(unit, format, time.Now(), wcc...)
}

// NewAverageSpeed decorator with dynamic unit measure adjustment and
// user provided start time.
//
//	`unit` one of [0|UnitKiB|UnitKB] zero for no unit
//
//	`format` printf compatible verb for value, like "%f" or "%d"
//
//	`startTime` start time
//
//	`wcc` optional WC config
//
// format examples:
//
//	unit=UnitKiB, format="%.1f"  output: "1.0MiB/s"
//	unit=UnitKiB, format="% .1f" output: "1.0 MiB/s"
//	unit=UnitKB,  format="%.1f"  output: "1.0MB/s"
//	unit=UnitKB,  format="% .1f" output: "1.0 MB/s"
//
func NewAverageSpeed(unit int, format string, startTime time.Time, wcc ...WC) Decorator {
	var wc WC
	for _, widthConf := range wcc {
		wc = widthConf
	}
	if format == "" {
		format = "%.0f"
	}
	wc.Init()
	d := &averageSpeed{
		WC:        wc,
		startTime: startTime,
		producer:  chooseSpeedProducer(unit, format),
	}
	return d
}

type averageSpeed struct {
	WC
	startTime   time.Time
	producer    func(float64) string
	msg         string
	completeMsg *string
}

func (d *averageSpeed) Decor(st *Statistics) string {
	if st.Completed {
		if d.completeMsg != nil {
			return d.FormatMsg(*d.completeMsg)
		}
		return d.FormatMsg(d.msg)
	}

	speed := float64(st.Current) / time.Since(d.startTime).Seconds()
	d.msg = d.producer(speed)

	return d.FormatMsg(d.msg)
}

func (d *averageSpeed) OnCompleteMessage(msg string) {
	d.completeMsg = &msg
}

func (d *averageSpeed) AverageAdjust(startTime time.Time) {
	d.startTime = startTime
}

func chooseSpeedProducer(unit int, format string) func(float64) string {
	switch unit {
	case UnitKiB:
		return func(speed float64) string {
			return fmt.Sprintf(format, &speedType{SizeB1024(math.Round(speed))})
		}
	case UnitKB:
		return func(speed float64) string {
			return fmt.Sprintf(format, &speedType{SizeB1000(math.Round(speed))})
		}
	default:
		return func(speed float64) string {
			return fmt.Sprintf(format, speed)
		}
	}
}
