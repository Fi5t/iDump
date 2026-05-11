// compilets compiles a Frida TypeScript agent into a JS bundle via the
// Frida compiler. Run from the project root:
//
//	go run tools/compilets/main.go [src] [out]
//
// Defaults: agent/dump.ts → internal/dump.js
// (or: make generate-ts after make devkit)
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/frida/frida-go/frida"
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
		os.Exit(1)
	}

	tsFile := filepath.Join(cwd, "agent", "dump.ts")
	outFile := filepath.Join(cwd, "internal", "dump.js")

	if len(os.Args) == 3 {
		tsFile = filepath.Join(cwd, os.Args[1])
		outFile = filepath.Join(cwd, os.Args[2])
	} else if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: compilets [src.ts out.js]\n")
		os.Exit(1)
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
		fmt.Fprintf(os.Stderr, "compile error: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(outFile), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outFile, []byte(bundle), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote", outFile)
}
