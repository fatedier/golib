package log

// Entry is a logger bound to a text prefix. The prefix is written verbatim and
// is never interpreted as part of a format string.
type Entry struct {
	logger *Logger
	prefix string
}

// WithPrefix returns an Entry that writes prefix before every log message.
func (l *Logger) WithPrefix(prefix string) Entry {
	return Entry{
		logger: l,
		prefix: prefix,
	}
}

func (e Entry) Trace(args ...any) {
	e.logger.log(TraceLevel, 0, e.prefix, "", args...)
}

func (e Entry) Debug(args ...any) {
	e.logger.log(DebugLevel, 0, e.prefix, "", args...)
}

func (e Entry) Info(args ...any) {
	e.logger.log(InfoLevel, 0, e.prefix, "", args...)
}

func (e Entry) Warn(args ...any) {
	e.logger.log(WarnLevel, 0, e.prefix, "", args...)
}

func (e Entry) Error(args ...any) {
	e.logger.log(ErrorLevel, 0, e.prefix, "", args...)
}

func (e Entry) Log(level Level, offset int, args ...any) {
	e.logger.log(level, offset, e.prefix, "", args...)
}

func (e Entry) Tracef(msg string, args ...any) {
	e.logger.log(TraceLevel, 0, e.prefix, msg, args...)
}

func (e Entry) Debugf(msg string, args ...any) {
	e.logger.log(DebugLevel, 0, e.prefix, msg, args...)
}

func (e Entry) Infof(msg string, args ...any) {
	e.logger.log(InfoLevel, 0, e.prefix, msg, args...)
}

func (e Entry) Warnf(msg string, args ...any) {
	e.logger.log(WarnLevel, 0, e.prefix, msg, args...)
}

func (e Entry) Errorf(msg string, args ...any) {
	e.logger.log(ErrorLevel, 0, e.prefix, msg, args...)
}

func (e Entry) Logf(level Level, offset int, msg string, args ...any) {
	e.logger.log(level, offset, e.prefix, msg, args...)
}
