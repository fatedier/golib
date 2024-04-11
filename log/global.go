package log

var DefaultLogger = New()

func Trace(args ...interface{}) {
	DefaultLogger.log(TraceLevel, 0, "", args...)
}

func Debug(args ...interface{}) {
	DefaultLogger.log(DebugLevel, 0, "", args...)
}

func Info(args ...interface{}) {
	DefaultLogger.log(InfoLevel, 0, "", args...)
}

func Warn(args ...interface{}) {
	DefaultLogger.log(WarnLevel, 0, "", args...)
}

func Error(args ...interface{}) {
	DefaultLogger.log(ErrorLevel, 0, "", args...)
}

func Log(level Level, offset int, args ...interface{}) {
	DefaultLogger.log(level, offset, "", args...)
}

func Tracef(msg string, args ...interface{}) {
	DefaultLogger.log(TraceLevel, 0, msg, args...)
}

func Debugf(msg string, args ...interface{}) {
	DefaultLogger.log(DebugLevel, 0, msg, args...)
}

func Infof(msg string, args ...interface{}) {
	DefaultLogger.log(InfoLevel, 0, msg, args...)
}

func Warnf(msg string, args ...interface{}) {
	DefaultLogger.log(WarnLevel, 0, msg, args...)
}

func Errorf(msg string, args ...interface{}) {
	DefaultLogger.log(ErrorLevel, 0, msg, args...)
}

func Logf(level Level, offset int, msg string, args ...interface{}) {
	DefaultLogger.log(level, offset, msg, args...)
}
