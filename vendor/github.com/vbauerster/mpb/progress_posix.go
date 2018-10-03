// +build !windows

package mpb

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (p *Progress) serve(s *pState) {
	winch := make(chan os.Signal, 2)
	signal.Notify(winch, syscall.SIGWINCH)

	var timer *time.Timer
	var tickerResumer <-chan time.Time
	resumeDelay := s.rr * 2

	for {
		select {
		case op := <-p.operateState:
			op(s)
		case <-s.ticker.C:
			if s.zeroWait {
				s.ticker.Stop()
				signal.Stop(winch)
				if s.shutdownNotifier != nil {
					close(s.shutdownNotifier)
				}
				close(p.done)
				return
			}
			tw, err := s.cw.GetWidth()
			if err != nil {
				tw = s.width
			}
			s.render(tw)
		case <-winch:
			tw, err := s.cw.GetWidth()
			if err != nil {
				tw = s.width
			}
			s.render(tw - tw/8)
			if timer != nil && timer.Reset(resumeDelay) {
				break
			}
			s.ticker.Stop()
			timer = time.NewTimer(resumeDelay)
			tickerResumer = timer.C
		case <-tickerResumer:
			s.ticker = time.NewTicker(s.rr)
			tickerResumer = nil
			timer = nil
		}
	}
}
