<p align="center">
  <img src="assets/logo.png" alt="iDump" width="500">
</p>

<p align="center">
  <strong>Decrypt and dump iOS app binaries to an IPA file</strong>
</p>

---

## Background

`idump` started as a rethink of [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) — the well-known Python tool that has been a go-to for iOS binary decryption for years. Unfortunately, `frida-ios-dump` no longer works with Frida 17+ and appears unmaintained. Rather than patch a Python script, the Frida agent was migrated and updated to work with modern Frida, then wrapped in a new host tool that eliminates the old setup friction: Python, pip dependencies, and a pre-configured SSH connection just to dump a single app.

The main goal of `idump` is **autonomy**: a single, self-contained binary that embeds the Frida agent script and works out of the box. No Python, no pip, no manually downloaded scripts. Just copy the binary to your PATH and run it.

Built in Go with [frida-go](https://github.com/frida/frida-go), `idump` takes advantage of modern tooling while staying close to the same core technique — inject a Frida agent, patch `cryptid` in `LC_ENCRYPTION_INFO`, pull the decrypted Mach-O segments, and reassemble a valid IPA.

---

## Installation

### Pre-built binaries

Download the latest release for your platform from the [Releases](https://github.com/Fi5t/idump/releases) page, then copy the binary to your PATH:

```bash
# macOS (Apple Silicon)
curl -L https://github.com/Fi5t/idump/releases/latest/download/idump-darwin-arm64 -o idump
chmod +x idump
cp idump /usr/local/bin/
```

### Build from source

**Prerequisites:** Go 1.21+, Frida CLI (`pip install frida-tools`), `curl`, `tar`

```bash
git clone https://github.com/Fi5t/idump.git
cd idump
make devkit   # downloads frida-core-devkit matching your installed frida version
make build    # produces ./idump
cp idump /usr/local/bin/
```

---

## Usage

`idump` connects to a USB-attached iOS device via Frida. The device must have `frida-server` running (or use a Frida gadget).

### List installed apps

```bash
idump -l
```

### Dump an app (USB mode)

File contents are transferred through Frida messages directly — no SSH required.

```bash
idump com.example.App               # by bundle ID
idump "My App"                      # by display name
idump -o output.ipa com.example.App # custom output filename
```

### Dump an app (SSH/SFTP mode)

The Frida agent writes `.fid` files to the device; `idump` then retrieves them over SFTP and assembles the IPA. Useful when USB transfer is slow or unreliable for large apps.

```bash
idump remote com.example.App                        # defaults: root@localhost:2222, password alpine
idump remote -H 192.168.1.10 -p 22 com.example.App # custom host/port
idump remote -K ~/.ssh/id_rsa com.example.App       # SSH key authentication
idump remote -u mobile -P password com.example.App  # custom credentials
```

### Dump multiple apps

Pass multiple targets at once, or use `--dump-all` to dump every app on the device. Both USB and SSH/SFTP modes support batch dumping.

```bash
# Dump a specific set of apps
idump com.example.App1 com.example.App2 com.example.App3

# Dump all installed apps into ./ipa-out/
idump --dump-all -d ./ipa-out

# Dump all non-Apple apps (skip com.apple.* identifiers)
idump --dump-all --skip-system -d ./ipa-out

# Dump only apps whose bundle ID contains a substring
idump --dump-all --filter com.mycompany. -d ./ipa-out

# Same flags work in SSH/SFTP mode
idump remote com.example.App1 com.example.App2 -d ./ipa-out
idump remote --dump-all --skip-system -d ./ipa-out
```

When dumping more than one app, `idump` prints a progress prefix (`[1/3] com.example.App`) before each target and a summary table when all are done:

```
  #  Name              Status    File / Note
  ────────────────────────────────────────────────────────
  1  My App            ✓         My App.ipa (42.1 MB)
  2  Another App       ✓         Another App.ipa (18.7 MB)
  3  Hardened App      ✗ failed  session detached: process-terminated
  ────────────────────────────────────────────────────────
  3 processed · 2 succeeded · 1 failed
```

Failed apps can be retried individually, optionally with `--dodge` or `--dodge=advanced`.

> **Note:** `--output` / `-o` is for single-app use only and cannot be combined with multiple targets or `--dump-all`. Use `--output-dir` / `-d` to control the destination directory for batch dumps.

### Bypass anti-Frida protection

Some apps detect Frida and crash before the dump script can run. Use spawn-gating to inject a bypass before the app starts:

```bash
# Basic bypass (hooks libc symbols: ptrace, sysctl, connect, stat, getenv, ...)
idump --dodge com.example.App

# Advanced bypass for hardened apps that issue raw syscalls, walk environ[],
# scan VM memory for Frida byte-signatures, and audit libc symbols for hooks.
# Hooks libsystem_kernel.dylib thunks (__sysctl, __connect, __stat, task_info,
# thread_info, vm_region_recurse_64) and the libc syscall multiplexer instead.
idump --dodge=advanced com.example.App

# Custom bypass script — provide your own hooks (.js or .ts)
idump --early bypass.js com.example.App
idump --early bypass.ts com.example.App   # compiled on the fly via frida.Compiler

# Same flags work in SSH/SFTP mode
idump remote --dodge com.example.App
idump remote --dodge=advanced com.example.App
```

`--dodge` and `--early` are mutually exclusive.

### Flags

**USB mode (`idump`):**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--list` | `-l` | — | List installed apps |
| `--output` | `-o` | app display name | Output IPA filename (single-app only; cannot be used with multiple targets or `--dump-all`) |
| `--output-dir` | `-d` | `.` | Directory to save IPA files (batch-friendly) |
| `--dump-all` | `-a` | — | Dump all installed apps |
| `--skip-system` | — | — | Skip `com.apple.*` apps (use with `--dump-all`) |
| `--filter` | — | — | Include only apps whose bundle ID contains this string (use with `--dump-all`) |
| `--dodge` | — | — | Basic bypass: hooks libc symbols via spawn-gating |
| `--dodge=advanced` | — | — | Advanced bypass for hardened apps (raw syscall hooks, environ scrub, VM scan) |
| `--early` | — | — | Path to custom bypass script (`.js` or `.ts`); mutually exclusive with `--dodge` |

**SSH/SFTP mode (`idump remote`):**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | app display name | Output IPA filename (single-app only; cannot be used with multiple targets or `--dump-all`) |
| `--output-dir` | `-d` | `.` | Directory to save IPA files (batch-friendly) |
| `--dump-all` | `-a` | — | Dump all installed apps |
| `--skip-system` | — | — | Skip `com.apple.*` apps (use with `--dump-all`) |
| `--filter` | — | — | Include only apps whose bundle ID contains this string (use with `--dump-all`) |
| `--host` | `-H` | `localhost` | SSH hostname |
| `--port` | `-p` | `2222` | SSH port |
| `--user` | `-u` | `root` | SSH username |
| `--password` | `-P` | `alpine` | SSH password |
| `--key` | `-K` | — | SSH private key file |
| `--dodge` | — | — | Basic bypass: hooks libc symbols via spawn-gating |
| `--dodge=advanced` | — | — | Advanced bypass for hardened apps (raw syscall hooks, environ scrub, VM scan) |
| `--early` | — | — | Path to custom bypass script (`.js` or `.ts`); mutually exclusive with `--dodge` |

---

## Development

### Prerequisites

- Go 1.21+
- Frida CLI (`pip install frida-tools`) — the devkit version is pinned to match it
- `curl`, `tar` (for downloading the devkit)

### 1. Get frida-go

`frida-go` uses CGO to wrap Frida's C library. Add it to the module:

```bash
go get github.com/frida/frida-go/frida@latest
```

### 2. Download the Frida Core devkit

The build requires `libfrida-core.a` and `frida-core.h`. The script auto-detects the Frida version from the system `frida` binary:

```bash
make devkit
```

To pin a specific version instead:

```bash
make devkit FRIDA_VERSION=17.x.y
```

This downloads and extracts the devkit to `build/frida-devkit/`.

### 3. Build

```bash
make build   # produces ./idump
```

### 4. Test

```bash
make test    # go test ./...
```

### Updating the Frida agents

The TypeScript agents are pre-compiled and embedded directly into the binary. When you edit `agent/dump.ts`, `agent/bypass.ts`, or `agent/bypass_advanced.ts`, recompile and commit:

```bash
make generate-ts                                                              # requires devkit (step 2)
git add internal/dump.js internal/bypass.js internal/bypass_advanced.js
git commit
```

To compile a single agent manually:

```bash
go run tools/compilets/main.go agent/bypass.ts internal/bypass.js
```
