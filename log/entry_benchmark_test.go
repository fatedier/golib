package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

const benchmarkPrefix = "[0123456789abcdef] "

var (
	benchmarkOneArg  = []any{"127.0.0.1:7000"}
	benchmarkFiveArg = []any{"127.0.0.1:7000", "0.65.0", "host", "darwin", "arm64"}
	benchmarkSink    Entry
)

type benchmarkPrefixedMessage struct {
	prefix string
	format string
	args   []any
}

func (m benchmarkPrefixedMessage) String() string {
	if len(m.args) == 0 {
		return m.prefix + m.format
	}
	return m.prefix + fmt.Sprintf(m.format, m.args...)
}

type benchmarkLogWriter struct{}

func (benchmarkLogWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (benchmarkLogWriter) WriteLog(p []byte, _ Level, _ time.Time) (int, error) {
	return len(p), nil
}

func BenchmarkPrefixEnabled(b *testing.B) {
	tests := []struct {
		name   string
		format string
		args   []any
	}{
		{name: "infof_no_args", format: "progress 100% complete"},
		{name: "infof_one_arg", format: "client address [%s]", args: benchmarkOneArg},
		{
			name:   "infof_five_args",
			format: "client login info: ip [%s] version [%s] hostname [%s] os [%s] arch [%s]",
			args:   benchmarkFiveArg,
		},
	}

	for _, caller := range []struct {
		name    string
		enabled bool
	}{
		{name: "caller_off", enabled: false},
		{name: "caller_on", enabled: true},
	} {
		b.Run(caller.name, func(b *testing.B) {
			logger := newBenchmarkLogger(InfoLevel, caller.enabled, io.Discard)
			b.Run("info", func(b *testing.B) {
				benchmarkInfoVariants(b, logger, benchmarkPrefix, "client connected", true)
			})
			for _, tt := range tests {
				b.Run(tt.name, func(b *testing.B) {
					benchmarkFormattedVariants(b, logger, benchmarkPrefix, tt.format, tt.args, true)
				})
			}
		})
	}
}

func BenchmarkPrefixDisabled(b *testing.B) {
	logger := newBenchmarkLogger(InfoLevel, true, io.Discard)
	benchmarkDebugfVariants(
		b,
		logger,
		benchmarkPrefix,
		"client login info: ip [%s] version [%s] hostname [%s] os [%s] arch [%s]",
		benchmarkFiveArg,
	)
}

func BenchmarkPrefixLength(b *testing.B) {
	logger := newBenchmarkLogger(InfoLevel, false, io.Discard)
	for _, size := range []int{0, 16, 256, 4096, 64 * 1024} {
		prefix := strings.Repeat("p", size)
		b.Run(fmt.Sprintf("bytes_%d", size), func(b *testing.B) {
			benchmarkFormattedVariants(
				b,
				logger,
				prefix,
				"client address [%s]",
				benchmarkOneArg,
				false,
			)
		})
	}
}

func BenchmarkPrefixWriter(b *testing.B) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = devNull.Close()
	})

	for _, output := range []struct {
		name   string
		writer io.Writer
	}{
		{name: "io_writer", writer: io.Discard},
		{name: "log_writer", writer: benchmarkLogWriter{}},
		{name: "console_color", writer: NewConsoleWriter(ConsoleConfig{Colorful: true}, io.Discard)},
		{name: "os_dev_null", writer: devNull},
	} {
		b.Run(output.name, func(b *testing.B) {
			logger := newBenchmarkLogger(InfoLevel, false, output.writer)
			benchmarkFormattedVariants(
				b,
				logger,
				benchmarkPrefix,
				"client login info: ip [%s] version [%s] hostname [%s] os [%s] arch [%s]",
				benchmarkFiveArg,
				false,
			)
		})
	}
}

func BenchmarkPrefixParallel(b *testing.B) {
	logger := newBenchmarkLogger(InfoLevel, false, io.Discard)
	format := "client login info: ip [%s] version [%s] hostname [%s] os [%s] arch [%s]"
	entry := logger.WithPrefix(benchmarkPrefix)

	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				logger.Infof(format, benchmarkFiveArg...)
			}
		})
	})
	b.Run("legacy_concat", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				logger.Infof(benchmarkPrefix+format, benchmarkFiveArg...)
			}
		})
	})
	b.Run("safe_stringer", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				logger.Info(benchmarkPrefixedMessage{prefix: benchmarkPrefix, format: format, args: benchmarkFiveArg})
			}
		})
	})
	b.Run("entry_cached", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				entry.Infof(format, benchmarkFiveArg...)
			}
		})
	})
	b.Run("entry_inline", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				logger.WithPrefix(benchmarkPrefix).Infof(format, benchmarkFiveArg...)
			}
		})
	})
}

func BenchmarkAdversarialPrefix(b *testing.B) {
	logger := newBenchmarkLogger(InfoLevel, false, io.Discard)
	prefix := "[%1000000s] "
	format := "value [%s]"
	args := []any{"ok"}
	entry := logger.WithPrefix(prefix)

	b.Run("legacy_concat", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Infof(prefix+format, args...)
		}
		b.ReportMetric(float64(len(fmt.Sprintf(prefix+format, args...))), "log-bytes/op")
	})
	b.Run("safe_stringer", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Info(benchmarkPrefixedMessage{prefix: prefix, format: format, args: args})
		}
		b.ReportMetric(float64(len(prefix+fmt.Sprintf(format, args...))), "log-bytes/op")
	})
	b.Run("entry_cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			entry.Infof(format, args...)
		}
		b.ReportMetric(float64(len(prefix+fmt.Sprintf(format, args...))), "log-bytes/op")
	})
}

func BenchmarkWithPrefixConstruction(b *testing.B) {
	logger := newBenchmarkLogger(InfoLevel, false, io.Discard)
	for b.Loop() {
		benchmarkSink = logger.WithPrefix(benchmarkPrefix)
	}
}

func newBenchmarkLogger(level Level, caller bool, output io.Writer) *Logger {
	return New(
		WithLevel(level),
		WithCaller(caller),
		WithOutput(output),
	)
}

func benchmarkInfoVariants(b *testing.B, logger *Logger, prefix, message string, includeDirect bool) {
	entry := logger.WithPrefix(prefix)
	if includeDirect {
		b.Run("direct", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				logger.Info(message)
			}
		})
	}
	b.Run("legacy_concat", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Info(prefix + message)
		}
	})
	b.Run("safe_stringer", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Info(benchmarkPrefixedMessage{prefix: prefix, format: message})
		}
	})
	b.Run("entry_cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			entry.Info(message)
		}
	})
	b.Run("entry_inline", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.WithPrefix(prefix).Info(message)
		}
	})
}

func benchmarkFormattedVariants(
	b *testing.B,
	logger *Logger,
	prefix string,
	format string,
	args []any,
	includeDirect bool,
) {
	entry := logger.WithPrefix(prefix)
	if includeDirect {
		b.Run("direct", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				logger.Infof(format, args...)
			}
		})
	}
	b.Run("legacy_concat", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Infof(prefix+format, args...)
		}
	})
	b.Run("safe_stringer", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Info(benchmarkPrefixedMessage{prefix: prefix, format: format, args: args})
		}
	})
	b.Run("entry_cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			entry.Infof(format, args...)
		}
	})
	b.Run("entry_inline", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.WithPrefix(prefix).Infof(format, args...)
		}
	})
}

func benchmarkDebugfVariants(b *testing.B, logger *Logger, prefix, format string, args []any) {
	entry := logger.WithPrefix(prefix)
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Debugf(format, args...)
		}
	})
	b.Run("legacy_concat", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Debugf(prefix+format, args...)
		}
	})
	b.Run("safe_stringer", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.Debug(benchmarkPrefixedMessage{prefix: prefix, format: format, args: args})
		}
	})
	b.Run("entry_cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			entry.Debugf(format, args...)
		}
	})
	b.Run("entry_inline", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			logger.WithPrefix(prefix).Debugf(format, args...)
		}
	})
}
