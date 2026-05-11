package ui

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

const (
	reset  = "\033[0m"
	green  = "\033[32m"
	yellow = "\033[33m"
	dim    = "\033[2m"
	red    = "\033[31m"
)

var (
	stdoutColor = term.IsTerminal(int(os.Stdout.Fd()))
	stderrColor = term.IsTerminal(int(os.Stderr.Fd()))
)

func colorize(enabled bool, code, s string) string {
	if !enabled {
		return s
	}
	return code + s + reset
}

func FmtSize(b int64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func Step(msg string) {
	fmt.Printf("  %s  %s\n", colorize(stdoutColor, dim, "→"), msg)
}

func OK(msg string) {
	fmt.Printf("  %s  %s\n", colorize(stdoutColor, green, "✓"), msg)
}

func Warn(msg string) {
	fmt.Fprintf(os.Stderr, "  %s  %s\n", colorize(stderrColor, yellow, "⚠"), msg)
}

func Err(msg string) {
	fmt.Fprintf(os.Stderr, "  %s  %s\n", colorize(stderrColor, red, "✗"), msg)
}
