package log

var DefaultLogger = New()

func Trace(args ...any) {
	DefaultLogger.log(TraceLevel, 0, "", args...)
}

func Debug(args ...any) {
	DefaultLogger.log(DebugLevel, 0, "", args...)
}

func Info(args ...any) {
	DefaultLogger.log(InfoLevel, 0, "", args...)
}

func Warn(args ...any) {
	DefaultLogger.log(WarnLevel, 0, "", args...)
}

func Error(args ...any) {
	DefaultLogger.log(ErrorLevel, 0, "", args...)
}

func Log(level Level, offset int, args ...any) {
	DefaultLogger.log(level, offset, "", args...)
}

func Tracef(msg string, args ...any) {
	DefaultLogger.log(TraceLevel, 0, msg, args...)
}

func Debugf(msg string, args ...any) {
	DefaultLogger.log(DebugLevel, 0, msg, args...)
}

func Infof(msg string, args ...any) {
	DefaultLogger.log(InfoLevel, 0, msg, args...)
}

func Warnf(msg string, args ...any) {
	DefaultLogger.log(WarnLevel, 0, msg, args...)
}

func Errorf(msg string, args ...any) {
	DefaultLogger.log(ErrorLevel, 0, msg, args...)
}

func Logf(level Level, offset int, msg string, args ...any) {
	DefaultLogger.log(level, offset, msg, args...)
}
