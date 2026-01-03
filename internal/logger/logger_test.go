package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogger(t *testing.T) {
	tests := []struct {
		name             string
		logLevel         string
		expectedContains []string
		expectedMissing  []string
	}{
		{
			name:     "Level ERROR",
			logLevel: "ERROR",
			expectedContains: []string{
				"error message",
			},
			expectedMissing: []string{
				"info message",
				"debug message",
			},
		},
		{
			name:     "Level INFO",
			logLevel: "INFO",
			expectedContains: []string{
				"error message",
				"info message",
			},
			expectedMissing: []string{
				"debug message",
			},
		},
		{
			name:     "Level DEBUG",
			logLevel: "DEBUG",
			expectedContains: []string{
				"error message",
				"info message",
				"debug message",
			},
			expectedMissing: []string{},
		},
		{
			name:     "Default Level (Unknown)",
			logLevel: "UNKNOWN",
			expectedContains: []string{
				"error message",
				"info message",
			},
			expectedMissing: []string{
				"debug message",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file for logging
			tmpDir := t.TempDir()
			logFilePath := filepath.Join(tmpDir, "test.log")

			// Initialize logger
			l := New(tt.logLevel, logFilePath)

			// Log messages
			l.Error("error message")
			l.Info("info message")
			l.Debug("debug message")

			// Read the log file
			content, err := os.ReadFile(logFilePath)
			if err != nil {
				t.Fatalf("Failed to read log file: %v", err)
			}
			output := string(content)

			// Verify expected strings are present
			for _, exp := range tt.expectedContains {
				if !strings.Contains(output, exp) {
					t.Errorf("Expected log output to contain %q, but it didn't.\nOutput:\n%s", exp, output)
				}
			}

			// Verify unexpected strings are missing
			for _, unexp := range tt.expectedMissing {
				if strings.Contains(output, unexp) {
					t.Errorf("Expected log output to NOT contain %q, but it did.\nOutput:\n%s", unexp, output)
				}
			}
		})
	}
}
