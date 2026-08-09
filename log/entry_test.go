package log

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntryPrefixIsNotPartOfFormatString(t *testing.T) {
	output := bytes.NewBuffer(nil)
	logger := New(WithOutput(output), WithCaller(false))

	logger.WithPrefix("[%1000000s] ").Infof("value [%[2]s %[1]s]", "first", "second")

	require.Contains(t, output.String(), "[%1000000s] value [second first]")
	require.Less(t, output.Len(), 1024)
}

func TestEntryCaller(t *testing.T) {
	output := bytes.NewBuffer(nil)
	logger := New(WithOutput(output), WithCaller(true))

	logger.WithPrefix("[run] ").Info("value")

	require.Contains(t, output.String(), "log/entry_test.go:")
	require.NotContains(t, output.String(), "log/entry.go:")
}

func TestDisabledEntryDoesNotFormat(t *testing.T) {
	logger := New(WithOutput(io.Discard), WithLevel(InfoLevel))

	logger.WithPrefix("[run] ").Debugf("%s", panicStringer{})
}

func TestEntriesShareLoggerOutputLock(t *testing.T) {
	output := bytes.NewBuffer(nil)
	logger := New(WithOutput(output), WithCaller(false))
	first := logger.WithPrefix("[first] ")
	second := logger.WithPrefix("[second] ")

	const count = 100
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() { first.Info("value") })
		wg.Go(func() { second.Info("value") })
	}
	wg.Wait()

	require.Equal(t, count*2, strings.Count(output.String(), "\n"))
}

type panicStringer struct{}

func (panicStringer) String() string {
	panic("String called for disabled log entry")
}
