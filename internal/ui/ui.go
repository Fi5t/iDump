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
