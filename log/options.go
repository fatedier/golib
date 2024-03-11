package log

import (
	"io"

	"github.com/fatedier/golib/clock"
)

// An Option configures a Logger.
type Option interface {
	apply(*Logger)
}

// optionFunc wraps a func so it satisfies the Option interface.
type optionFunc func(*Logger)

func (f optionFunc) apply(log *Logger) {
	f(log)
}

func WithOutput(w io.Writer) Option {
	return optionFunc(func(log *Logger) {
		log.out = w
	})
}

func WithLevel(l Level) Option {
	return optionFunc(func(log *Logger) {
		log.level = l
	})
}

func AddCallerSkip(skip int) Option {
	return optionFunc(func(log *Logger) {
		log.callerSkip += skip
	})
}

func WithCaller(enabled bool) Option {
	return optionFunc(func(log *Logger) {
		log.callerEnabled = enabled
	})
}

// WithClock specifies the clock used by the logger to determine the current
// time for logged entries. Defaults to the system clock with time.Now.
func WithClock(clock clock.Clock) Option {
	return optionFunc(func(log *Logger) {
		log.clock = clock
	})
}
