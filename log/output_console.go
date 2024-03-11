package log

import (
	"io"
	"os"
	"time"
)

// brush is a color join function
type brush func(string) string

// newBrush returns a fix color Brush
func newBrush(color string) brush {
	pre := "\033["
	reset := "\033[0m"
	return func(text string) string {
		return pre + color + "m" + text + reset
	}
}

func emptyBrush(text string) string {
	return text
}

var colors = []brush{
	emptyBrush,       // Trace              No Color
	newBrush("1;36"), // Debug              Light Cyan
	newBrush("1;34"), // Info 				Blue
	newBrush("1;33"), // Warn               Yellow
	newBrush("1;31"), // Error              Red
}

func colorBrushByLevel(level Level) brush {
	switch level {
	case TraceLevel:
		return colors[0]
	case DebugLevel:
		return colors[1]
	case InfoLevel:
		return colors[2]
	case WarnLevel:
		return colors[3]
	case ErrorLevel:
		return colors[4]
	default:
		return colors[2]
	}
}

var _ io.Writer = (*ConsoleWriter)(nil)

type ConsoleConfig struct {
	Colorful bool
}

type ConsoleWriter struct {
	w io.Writer
}

func NewConsoleWriter(cfg ConsoleConfig, out io.Writer) io.Writer {
	if !cfg.Colorful {
		return out
	}
	if out == nil {
		out = os.Stdout
	}
	return &ConsoleWriter{
		w: out,
	}
}

func (cw *ConsoleWriter) Write(p []byte) (n int, err error) {
	return cw.w.Write(p)
}

func (cw *ConsoleWriter) WriteLog(p []byte, level Level, when time.Time) (n int, err error) {
	return cw.w.Write([]byte(colorBrushByLevel(level)(string(p))))
}
