package log

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/golib/clock"
)

type Writer interface {
	WriteLog([]byte, Level, time.Time) (n int, err error)
}

var DefaultWriter = os.Stdout

type Logger struct {
	outMu sync.Mutex
	out   io.Writer

	level         Level
	callerEnabled bool
	callerSkip    int
	clock         clock.Clock
}

func New(opts ...Option) *Logger {
	l := &Logger{}
	for _, opt := range opts {
		opt.apply(l)
	}
	if l.out == nil {
		l.out = DefaultWriter
	}
	if l.level == 0 {
		l.level = InfoLevel
	}
	if l.clock == nil {
		l.clock = clock.Real
	}
	return l
}

// WithOptions returns a new Logger with the given Options.
// It does not modify the original Logger.
func (l *Logger) WithOptions(opts ...Option) *Logger {
	c := l.clone()
	for _, opt := range opts {
		opt.apply(c)
	}
	return c
}

func (l *Logger) clone() *Logger {
	clone := &Logger{
		out:           l.out,
		level:         l.level,
		callerEnabled: l.callerEnabled,
		callerSkip:    l.callerSkip,
		clock:         l.clock,
	}
	return clone
}

func (l *Logger) Trace(args ...interface{}) {
	l.log(TraceLevel, 0, "", args...)
}

func (l *Logger) Debug(args ...interface{}) {
	l.log(DebugLevel, 0, "", args...)
}

func (l *Logger) Info(args ...interface{}) {
	l.log(InfoLevel, 0, "", args...)
}

func (l *Logger) Warn(args ...interface{}) {
	l.log(WarnLevel, 0, "", args...)
}

func (l *Logger) Error(args ...interface{}) {
	l.log(ErrorLevel, 0, "", args...)
}

func (l *Logger) Log(level Level, offset int, args ...interface{}) {
	l.log(level, offset, "", args...)
}

func (l *Logger) Tracef(msg string, args ...interface{}) {
	l.log(TraceLevel, 0, msg, args...)
}

func (l *Logger) Debugf(msg string, args ...interface{}) {
	l.log(DebugLevel, 0, msg, args...)
}

func (l *Logger) Infof(msg string, args ...interface{}) {
	l.log(InfoLevel, 0, msg, args...)
}

func (l *Logger) Warnf(msg string, args ...interface{}) {
	l.log(WarnLevel, 0, msg, args...)
}

func (l *Logger) Errorf(msg string, args ...interface{}) {
	l.log(ErrorLevel, 0, msg, args...)
}

func (l *Logger) Logf(level Level, offset int, msg string, args ...interface{}) {
	l.log(level, offset, msg, args...)
}

func (l *Logger) log(level Level, offset int, msg string, args ...interface{}) {
	if !l.level.Enabled(level) {
		return
	}

	when := l.clock.Now()

	buffer := bytesBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buffer.Reset()
		bytesBufferPool.Put(buffer)
	}()

	timeHeaderBuf := make([]byte, 23)
	_, _ = formatTimeHeader(when, timeHeaderBuf)

	buffer.Write(timeHeaderBuf)
	buffer.WriteByte(' ')
	buffer.WriteString(level.LogPrefix())
	buffer.WriteByte(' ')

	if l.callerEnabled {
		buffer.WriteString(getCallerPrefix(3 + l.callerSkip + offset))
		buffer.WriteByte(' ')
	}

	buffer.WriteString(getMessage(msg, args))
	buffer.WriteByte('\n')

	if lw, ok := l.out.(Writer); ok {
		l.outMu.Lock()
		defer l.outMu.Unlock()
		_, _ = lw.WriteLog(buffer.Bytes(), level, when)
		return
	}
	l.outMu.Lock()
	defer l.outMu.Unlock()
	_, _ = l.out.Write(buffer.Bytes())
}

func getMessage(template string, fmtArgs []interface{}) string {
	if len(fmtArgs) == 0 {
		return template
	}

	if template != "" {
		return fmt.Sprintf(template, fmtArgs...)
	}

	if len(fmtArgs) == 1 {
		if str, ok := fmtArgs[0].(string); ok {
			return str
		}
	}
	return fmt.Sprint(fmtArgs...)
}

func getCallerPrefix(skip int) string {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		file = "???"
		line = 0
	}
	return "[" + trimmedPath(file, line) + "]"
}

func fullPath(path string, line int) string {
	buf := getBuffer()
	defer putBuffer(buf)
	*buf = append(*buf, path...)
	*buf = append(*buf, ':')
	itoa(buf, line, -1)
	return string(*buf)
}

func trimmedPath(path string, line int) string {
	idx := strings.LastIndexByte(path, '/')
	if idx == -1 {
		return fullPath(path, line)
	}
	// Find the penultimate separator.
	idx = strings.LastIndexByte(path[:idx], '/')
	if idx == -1 {
		return fullPath(path, line)
	}
	buf := getBuffer()
	defer putBuffer(buf)
	*buf = append(*buf, path[idx+1:]...)
	*buf = append(*buf, ':')
	itoa(buf, line, -1)
	return string(*buf)
}
