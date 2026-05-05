// Run after `make devkit` to recompile the Frida agent when agent/dump.ts changes:
//
//	make generate-ts
//	git add internal/dump.js
//
//go:generate go run tools/compilets/main.go
package main
