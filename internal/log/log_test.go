package log

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitDisabled(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	path, closer, err := Init(false)
	if err != nil {
		t.Fatalf("Init(false): %v", err)
	}
	if path != "" {
		t.Fatalf("path: got %q, want empty", path)
	}
	if err := closer(); err != nil {
		t.Fatalf("closer: %v", err)
	}

	slog.Debug("should be discarded", "k", "v")
}

// Not t.Parallel(): os.Chdir is process-global state.
func TestInitEnabledWritesToFile(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	path, closer, err := Init(true)
	if err != nil {
		t.Fatalf("Init(true): %v", err)
	}
	if path == "" {
		t.Fatalf("path is empty")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected log file to exist at %q: %v", path, err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("expected absolute path, got %q", path)
	}

	slog.Debug("marker", "k", "v")

	if err := closer(); err != nil {
		t.Fatalf("closer: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, "marker") || !strings.Contains(got, "k=v") {
		t.Fatalf("log missing expected fields: %q", got)
	}
	if !strings.Contains(got, "level=DEBUG") {
		t.Fatalf("log missing DEBUG level: %q", got)
	}
}
