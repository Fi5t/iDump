package log

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

func Init(enabled bool) (path string, closer func() error, err error) {
	if !enabled {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
		return "", func() error { return nil }, nil
	}

	name := fmt.Sprintf("idump-debug-%s.log", time.Now().UTC().Format("20060102T150405Z"))
	path, err = filepath.Abs(name)
	if err != nil {
		path = name
	}

	f, oerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if oerr != nil {
		return "", nil, fmt.Errorf("open debug log %s: %w", path, oerr)
	}

	h := slog.NewTextHandler(f, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	})
	slog.SetDefault(slog.New(h))

	return path, f.Close, nil
}
