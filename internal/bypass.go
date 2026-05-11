package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Fi5t/idump/internal/ui"
	"github.com/frida/frida-go/frida"
)

// Call while the process is still suspended (before Resume) so hooks are in place before any app code runs.
func InjectBypass(session *frida.Session, script string) error {
	s, err := session.CreateScript(script)
	if err != nil {
		return fmt.Errorf("create bypass script: %w", err)
	}
	s.On("message", func(message string, _ []byte) {
		ui.Warn("bypass: " + message)
	})
	if err := s.Load(); err != nil {
		return fmt.Errorf("load bypass script: %w", err)
	}
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
