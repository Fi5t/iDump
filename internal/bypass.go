package internal

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Fi5t/idump/internal/ui"
	"github.com/frida/frida-go/frida"
)

// Call while the process is still suspended (before Resume) so hooks are in place before any app code runs.
func InjectBypass(session *frida.Session, script, agentName string) error {
	s, err := session.CreateScript(script)
	if err != nil {
		return fmt.Errorf("create bypass script: %w", err)
	}
	s.On("message", func(message string, _ []byte) {
		var msg FridaMessage
		if uerr := json.Unmarshal([]byte(message), &msg); uerr != nil {
			slog.Debug("frida.message", "agent", agentName, "raw", message)
			return
		}
		switch msg.Type {
		case "log":
			var text string
			if uerr := json.Unmarshal(msg.Payload, &text); uerr != nil {
				text = string(msg.Payload)
			}
			slog.Debug("frida.log", "agent", agentName, "level", msg.Level, "msg", text)
		case "error":
			slog.Error("frida.error", "agent", agentName, "description", msg.Description, "stack", msg.Stack)
			ui.Warn("bypass: " + msg.Description)
		default:
			slog.Debug("frida.message", "agent", agentName, "type", msg.Type, "raw", message)
		}
	})
	start := time.Now()
	if err := s.Load(); err != nil {
		return fmt.Errorf("load bypass script: %w", err)
	}
	slog.Debug("bypass.loaded",
		"agent", agentName,
		"bytes", len(script),
		"elapsed_ms", time.Since(start).Milliseconds())
	return nil
}

func CompileOrLoad(path string) (string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js":
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read script: %w", err)
		}
		return string(data), nil
	case ".ts":
		return compileTS(path)
	default:
		return "", fmt.Errorf("unsupported script extension %q: expected .js or .ts", filepath.Ext(path))
	}
}

func compileTS(path string) (string, error) {
	compiler := frida.NewCompiler()
	defer compiler.Clean()

	compiler.On("diagnostics", func(diag string) {
		ui.Warn("compilets: " + diag)
	})

	opts := frida.NewCompilerOptions()
	opts.SetProjectRoot(filepath.Dir(path))

	bundle, err := compiler.Build(path, opts)
	if err != nil {
		return "", fmt.Errorf("compile %s: %w", path, err)
	}
	return bundle, nil
}
