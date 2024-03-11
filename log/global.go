package log

var DefaultLogger = New()

func Trace(args ...interface{}) {
	DefaultLogger.log(TraceLevel, "", args...)
}

func Debug(args ...interface{}) {
	DefaultLogger.log(DebugLevel, "", args...)
}

func Info(args ...interface{}) {
	DefaultLogger.log(InfoLevel, "", args...)
}

func Warn(args ...interface{}) {
	DefaultLogger.log(WarnLevel, "", args...)
}

func Error(args ...interface{}) {
	DefaultLogger.log(ErrorLevel, "", args...)
}

func Tracef(msg string, args ...interface{}) {
	DefaultLogger.log(TraceLevel, msg, args...)
}

func Debugf(msg string, args ...interface{}) {
	DefaultLogger.log(DebugLevel, msg, args...)
}

func Infof(msg string, args ...interface{}) {
	DefaultLogger.log(InfoLevel, msg, args...)
}

func Warnf(msg string, args ...interface{}) {
	DefaultLogger.log(WarnLevel, msg, args...)
}

func Errorf(msg string, args ...interface{}) {
	DefaultLogger.log(ErrorLevel, msg, args...)
}
