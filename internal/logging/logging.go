package logging

import (
	"encoding/json"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

var (
	authorizationPattern = regexp.MustCompile(`(?i)(authorization)(["'=:\s]+)(?:bearer\s+)?([^\s",}]+)`)
	secretPattern        = regexp.MustCompile(`(?i)(token|password|private[_ -]?key|secret|credential)(["'=:\s]+)([^\s",}]+)`)
)

func Redact(value string) string {
	value = authorizationPattern.ReplaceAllString(value, `${1}${2}[REDACTED]`)
	value = secretPattern.ReplaceAllString(value, `${1}${2}[REDACTED]`)
	for _, marker := range []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----"} {
		if strings.Contains(value, marker) {
			return "[REDACTED PRIVATE KEY]"
		}
	}
	return value
}

type redactWriter struct{ target io.Writer }

func (w redactWriter) Write(p []byte) (int, error) {
	safe := []byte(Redact(string(p)))
	if !json.Valid(safe) {
		safe = append(safe, '\n')
	}
	_, err := w.target.Write(safe)
	return len(p), err
}

func New(target io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(redactWriter{target: target}, &slog.HandlerOptions{Level: level}))
}
