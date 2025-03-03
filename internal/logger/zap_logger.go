package logger

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ZapLogger struct {
	zapLogger *zap.Logger
}

func NewLogger(logLevel string, logFile string) (Logger, error) {
	lvl, err := parseLogLevel(logLevel)
	if err != nil {
		fmt.Printf("invalid log-level provided: %s \n", lvl)
		return nil, err
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)

	if logFile != "" {
		logDir := filepath.Dir(logFile)
		if logDir != "." && logDir != "/" {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				return nil, fmt.Errorf("unable to create log-path at root: %w", err)
			}
		}
	} else {
		cfg.OutputPaths = []string{"stdout", logFile}
		cfg.ErrorOutputPaths = []string{"stderr", logFile}
	}

	zapLogger, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("error while building zap logger: %v", err)
	}

	return &ZapLogger{zapLogger: zapLogger}, nil
}

func parseLogLevel(logLevel string) (zapcore.Level, error) {
	switch logLevel {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("invalid logLevel: %s provided", logLevel)
	}
}

func (l *ZapLogger) Debug(msg string, fields ...zap.Field) {
	l.zapLogger.Debug(msg, fields...)
}

func (l *ZapLogger) Info(msg string, fields ...zap.Field) {
	l.zapLogger.Info(msg, fields...)
}

func (l *ZapLogger) Warn(msg string, fields ...zap.Field) {
	l.zapLogger.Warn(msg, fields...)
}

func (l *ZapLogger) Error(msg string, fields ...zap.Field) {
	l.zapLogger.Error(msg, fields...)
}

func (l *ZapLogger) Fatal(msg string, fields ...zap.Field) {
	l.zapLogger.Fatal(msg, fields...)
}

func (l *ZapLogger) Sync() error {
	return l.zapLogger.Sync()
}
