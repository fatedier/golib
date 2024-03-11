package testing

import (
	"sync"
	"time"
)

type FakeClock struct {
	mu sync.RWMutex
	t  time.Time
}

func NewFakeClock(t time.Time) *FakeClock {
	return &FakeClock{t: t}
}

// Now returns f's time.
func (f *FakeClock) Now() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.t
}

// Since returns time since the time in f.
func (f *FakeClock) Since(t time.Time) time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.t.Sub(t)
}

// SetTime sets the time on the FakeClock.
func (f *FakeClock) SetTime(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t
}
