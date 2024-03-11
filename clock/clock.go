package clock

import "time"

type Clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

var Real Clock = realClock{}

type realClock struct{}

// Now returns the current time.
func (realClock) Now() time.Time {
	return time.Now()
}

// Since returns time since the specified timestamp.
func (realClock) Since(ts time.Time) time.Duration {
	return time.Since(ts)
}
