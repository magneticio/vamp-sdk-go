package logging

import (
	"os"

	"github.com/sirupsen/logrus"
)

type ILogger interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}

type LogrusWrapper struct {
	logrusLogger *logrus.Logger
}

func (wrapper *LogrusWrapper) Debug(args ...interface{}) {
	wrapper.logrusLogger.Debug(args...)
}

func (wrapper *LogrusWrapper) Debugf(format string, args ...interface{}) {
	wrapper.logrusLogger.Debugf(format, args...)
}

func (wrapper *LogrusWrapper) Info(args ...interface{}) {
	wrapper.logrusLogger.Info(args...)
}

func (wrapper *LogrusWrapper) Infof(format string, args ...interface{}) {
	wrapper.logrusLogger.Infof(format, args...)
}

func (wrapper *LogrusWrapper) Warn(args ...interface{}) {
	wrapper.logrusLogger.Warn(args...)
}

func (wrapper *LogrusWrapper) Warnf(format string, args ...interface{}) {
	wrapper.logrusLogger.Warnf(format, args...)
}

func (wrapper *LogrusWrapper) Error(args ...interface{}) {
	wrapper.logrusLogger.Error(args...)
}

func (wrapper *LogrusWrapper) Errorf(format string, args ...interface{}) {
	wrapper.logrusLogger.Errorf(format, args...)
}

func (wrapper *LogrusWrapper) Fatal(args ...interface{}) {
	wrapper.logrusLogger.Fatal(args...)
}

func (wrapper *LogrusWrapper) Fatalf(format string, args ...interface{}) {
	wrapper.logrusLogger.Fatalf(format, args...)
}

func Logger() ILogger {
	var logrusLogger = logrus.New()
	lvl, ok := os.LookupEnv("LOG_LEVEL")
	if !ok {
		logrusLogger.SetLevel(logrus.InfoLevel)
	}

	if lvl == "DEBUG" {
		logrusLogger.SetLevel(logrus.DebugLevel)
	} else {
		logrusLogger.SetLevel(logrus.InfoLevel)
	}
	return &LogrusWrapper{logrusLogger: logrusLogger}
}
