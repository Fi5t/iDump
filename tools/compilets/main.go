// compilets compiles a Frida TypeScript agent into a JS bundle via the
// Frida compiler. Run from the project root:
//
//	go run tools/compilets/main.go [src] [out]
//
// Defaults: agent/dump.ts → internal/dump.js
// (or: make generate-ts after make devkit)
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/frida/frida-go/frida"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	tsFile := filepath.Join(cwd, "agent", "dump.ts")
	outFile := filepath.Join(cwd, "internal", "dump.js")

	if len(os.Args) == 3 {
		tsFile = filepath.Join(cwd, os.Args[1])
		outFile = filepath.Join(cwd, os.Args[2])
	} else if len(os.Args) != 1 {
		return errors.New("usage: compilets [src.ts out.js]")
	}

	compiler := frida.NewCompiler()
	defer compiler.Clean()

	compiler.On("diagnostics", func(diag string) {
		fmt.Fprintln(os.Stderr, diag)
	})

	opts := frida.NewCompilerOptions()
	opts.SetProjectRoot(filepath.Dir(tsFile))

	bundle, err := compiler.Build(tsFile, opts)
	if err != nil {
		return fmt.Errorf("compile error: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outFile), 0o750); err != nil { //nolint:gosec // path is a developer-supplied build output path
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(outFile, []byte(bundle), 0o600); err != nil { //nolint:gosec // path is a developer-supplied build output path
		return fmt.Errorf("write: %w", err)
	}
	fmt.Println("wrote", outFile)
	return nil
}
