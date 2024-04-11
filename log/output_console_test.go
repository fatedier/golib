package log

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testingclock "github.com/fatedier/golib/clock/testing"
)

func TestConsoleWriter(t *testing.T) {
	require := require.New(t)

	now := time.Now()
	fakeClock := testingclock.NewFakeClock(now)

	// no color
	testBuffer := bytes.NewBuffer(nil)
	w := NewConsoleWriter(ConsoleConfig{Colorful: false}, testBuffer)
	logger := New(WithOutput(w), WithLevel(TraceLevel), WithClock(fakeClock))
	logger.Trace("trace")
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")

	expect := testLogFormat(now, TraceLevel, "trace")
	expect += testLogFormat(now, DebugLevel, "debug")
	expect += testLogFormat(now, InfoLevel, "info")
	expect += testLogFormat(now, WarnLevel, "warn")
	expect += testLogFormat(now, ErrorLevel, "error")

	require.Equal(expect, testBuffer.String())

	// with color
	testBuffer.Reset()
	w = NewConsoleWriter(ConsoleConfig{Colorful: true}, testBuffer)
	logger = New(WithOutput(w), WithLevel(TraceLevel), WithClock(fakeClock))
	logger.Trace("trace")
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")

	expect = ""
	expect += colorBrushByLevel(TraceLevel)(testLogFormat(now, TraceLevel, "trace"))
	expect += colorBrushByLevel(DebugLevel)(testLogFormat(now, DebugLevel, "debug"))
	expect += colorBrushByLevel(InfoLevel)(testLogFormat(now, InfoLevel, "info"))
	expect += colorBrushByLevel(WarnLevel)(testLogFormat(now, WarnLevel, "warn"))
	expect += colorBrushByLevel(ErrorLevel)(testLogFormat(now, ErrorLevel, "error"))

	require.Equal(expect, testBuffer.String())
}
