package log

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	testingclock "github.com/fatedier/golib/clock/testing"
)

func TestRotateFileWriter_RotateDaily(t *testing.T) {
	require := require.New(t)

	now := time.Now()
	nextDayTime := now.Add(24 * time.Hour)
	nextDay := time.Date(nextDayTime.Year(), nextDayTime.Month(), nextDayTime.Day(), 0, 0, 0, 0, now.Location())
	nextDay = nextDay.Add(time.Millisecond)

	rotateClock := testingclock.NewFakeClock(now)

	tmpDir := t.TempDir()
	// Don't call Init to start DailyRotate goroutine.
	// Call Rotate manually.
	w := NewRotateFileWriter(RotateFileConfig{
		FileName: filepath.Join(tmpDir, "rotate_daily", "test.log"),
		Mode:     RotateFileModeDaily,
		MaxDays:  2,
		Clock:    rotateClock,
	})
	t.Cleanup(func() {
		w.Close()
		os.RemoveAll(filepath.Join(tmpDir, "rotate_daily"))
	})

	getLogFileName := func(t time.Time) string {
		return "test." + t.Format(backupTimeFormat) + ".log"
	}

	logClock := testingclock.NewFakeClock(now)
	logger := New(WithOutput(w), WithLevel(TraceLevel), WithClock(logClock))

	logger.Info("test1")

	day1 := nextDay
	rotateClock.SetTime(day1)
	require.NoError(w.Rotate())
	require.EqualValues([]string{getLogFileName(day1)}, rorateLogFiles(w))

	logger.Info("test2")
	day2 := nextDay.Add(24 * time.Hour)
	rotateClock.SetTime(day2)
	require.NoError(w.Rotate())
	require.EqualValues([]string{getLogFileName(day1), getLogFileName(day2)}, rorateLogFiles(w))

	logger.Info("test3")
	day3 := nextDay.Add(2 * 24 * time.Hour)
	rotateClock.SetTime(day3)
	require.NoError(w.Rotate())
	require.EqualValues([]string{getLogFileName(day2), getLogFileName(day3)}, rorateLogFiles(w))
}

func rorateLogFiles(w *RotateFileWriter) []string {
	files, err := w.oldLogFiles()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.info.Name())
	}
	return out
}
