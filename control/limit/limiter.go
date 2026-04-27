package limit

import (
	"errors"
	"sync/atomic"
	"time"

	gerr "github.com/fatedier/golib/errors"
)

var (
	ErrTimeout = errors.New("limiter acquire timeout")
	ErrClosed  = errors.New("limiter closed")
)

// Limiter support update limit number dynamically
type Limiter struct {
	poolCh    chan struct{}
	releaseCh chan struct{}
	limitCh   chan int64

	current atomic.Int64
	waiting atomic.Int64
	limit   atomic.Int64
	closed  atomic.Int64
}

func NewLimiter(initLimit int64) (l *Limiter) {
	l = &Limiter{
		poolCh:    make(chan struct{}),
		releaseCh: make(chan struct{}),
		limitCh:   make(chan int64),
	}
	l.limit.Store(initLimit)
	go l.manager()
	return
}

func (l *Limiter) manager() {
	var err error
	for {
		if l.current.Load() < l.limit.Load() {
			err = gerr.PanicToError(func() {
				select {
				case l.poolCh <- struct{}{}:
					l.current.Add(1)
				case <-l.releaseCh:
					if l.current.Load() > 0 {
						l.current.Add(-1)
					}
				case newLimit := <-l.limitCh:
					l.limit.Store(newLimit)
				}
			})
			if err != nil {
				// closed
				close(l.releaseCh)
				close(l.limitCh)
				break
			}
			continue
		}

		select {
		case <-l.releaseCh:
			l.current.Add(-1)
		case newLimit := <-l.limitCh:
			l.limit.Store(newLimit)
		}
	}
}

func (l *Limiter) LimitNum() int64 {
	return l.limit.Load()
}

func (l *Limiter) RunningNum() int64 {
	return l.current.Load()
}

func (l *Limiter) WaitingNum() int64 {
	return l.waiting.Load()
}

// Acquire will wait for an available resource.
// timeout eq 0 means no timeout limit.
// Return ErrTimeout if no resource available after timeout duration.
// Return ErrClosed if this Limiter is closed.
func (l *Limiter) Acquire(timeout time.Duration) (err error) {
	l.waiting.Add(1)

	defer func() {
		l.waiting.Add(-1)
	}()

	if timeout == 0 {
		// no timeout limit
		_, ok := <-l.poolCh
		if !ok {
			err = ErrClosed
		}
	} else {
		select {
		case <-time.After(timeout):
			err = ErrTimeout
		case _, ok := <-l.poolCh:
			if !ok {
				err = ErrClosed
			}
		}
	}
	return
}

// Release resources.
func (l *Limiter) Release() {
	if err := gerr.PanicToError(func() {
		l.releaseCh <- struct{}{}
	}); err != nil {
		l.current.Add(-1)
	}
}

func (l *Limiter) SetLimit(num int64) {
	_ = gerr.PanicToError(func() {
		l.limitCh <- num
	})
}

func (l *Limiter) Close() {
	if l.closed.CompareAndSwap(0, 1) {
		close(l.poolCh)
	}
}
