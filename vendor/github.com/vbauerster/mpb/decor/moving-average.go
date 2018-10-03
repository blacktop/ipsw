package decor

import (
	"sort"

	"github.com/VividCortex/ewma"
)

// MovingAverage is the interface that computes a moving average over a time-
// series stream of numbers. The average may be over a window or exponentially
// decaying.
type MovingAverage interface {
	Add(float64)
	Value() float64
	Set(float64)
}

type median struct {
	window [3]float64
	dst    []float64
}

type sortable []float64

func (s sortable) Len() int           { return len(s) }
func (s sortable) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s sortable) Less(i, j int) bool { return s[i] < s[j] }

func (s *median) Add(v float64) {
	s.window[0], s.window[1] = s.window[1], s.window[2]
	s.window[2] = v
}

func (s *median) Value() float64 {
	copy(s.dst, s.window[:])
	sort.Sort(sortable(s.dst))
	return s.dst[1]
}

func (s *median) Set(value float64) {
	for i, _ := range s.window {
		s.window[i] = value
	}
}

// NewMedian is fixed last 3 samples median MovingAverage.
func NewMedian() MovingAverage {
	return &median{
		dst: make([]float64, 3),
	}
}

type medianEwma struct {
	count  uint
	median MovingAverage
	MovingAverage
}

func (s *medianEwma) Add(v float64) {
	s.median.Add(v)
	s.count++
	if s.count >= 3 {
		s.MovingAverage.Add(s.median.Value())
	}
}

// NewMedianEwma is ewma based MovingAverage, which gets its values from median MovingAverage.
func NewMedianEwma(age ...float64) MovingAverage {
	return &medianEwma{
		MovingAverage: ewma.NewMovingAverage(age...),
		median:        NewMedian(),
	}
}
