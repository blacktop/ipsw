// +build windows

package mpb

func (p *Progress) serve(s *pState) {
	for {
		select {
		case op := <-p.operateState:
			op(s)
		case <-s.ticker.C:
			if s.zeroWait {
				s.ticker.Stop()
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
		}
	}
}
