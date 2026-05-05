// compilets compiles agent/dump.ts into internal/dump.js via the
// Frida compiler. Run from the project root: go run tools/compilets/main.go
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

	assetsDir := filepath.Join(cwd, "agent")
	tsFile := filepath.Join(assetsDir, "dump.ts")

	compiler := frida.NewCompiler()
	defer compiler.Clean()

	compiler.On("diagnostics", func(diag string) {
		fmt.Fprintln(os.Stderr, diag)
	})

	opts := frida.NewCompilerOptions()
	opts.SetProjectRoot(assetsDir)

	bundle, err := compiler.Build(tsFile, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile error: %v\n", err)
		os.Exit(1)
	}

	outDir := filepath.Join(cwd, "internal")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	outFile := filepath.Join(outDir, "dump.js")
	if err := os.WriteFile(outFile, []byte(bundle), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("wrote", outFile)
}
