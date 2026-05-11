// Run after `make devkit` to recompile the Frida agents when TS sources change:
//
//	make generate-ts
//	git add internal/dump.js internal/bypass.js internal/bypass_advanced.js
//
//go:generate go run tools/compilets/main.go agent/dump.ts internal/dump.js
//go:generate go run tools/compilets/main.go agent/bypass.ts internal/bypass.js
//go:generate go run tools/compilets/main.go agent/bypass_advanced.ts internal/bypass_advanced.js
package main
