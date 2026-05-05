package ui

import (
	"fmt"
	"os"
)

const (
	reset  = "\033[0m"
	green  = "\033[32m"
	yellow = "\033[33m"
	dim    = "\033[2m"
	red    = "\033[31m"
)

func Step(msg string) {
	fmt.Printf("  %s→%s  %s\n", dim, reset, msg)
}

func OK(msg string) {
	fmt.Printf("  %s✓%s  %s\n", green, reset, msg)
}

func Warn(msg string) {
	fmt.Fprintf(os.Stderr, "  %s⚠%s  %s\n", yellow, reset, msg)
}

func Err(msg string) {
	fmt.Fprintf(os.Stderr, "  %s✗%s  %s\n", red, reset, msg)
}
