#!/usr/bin/env bash
set -euo pipefail

FRIDA_VERSION="${1:-}"
DEVKIT_DIR="build/frida-devkit"

if [[ -z "$FRIDA_VERSION" ]]; then
    echo "No version specified, fetching latest Frida release..."
    FRIDA_VERSION=$(curl -fsSL "https://api.github.com/repos/frida/frida/releases/latest" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    echo "Latest version: $FRIDA_VERSION"
fi

if [[ -n "${DEVKIT_OS:-}" ]]; then
    OS="$DEVKIT_OS"
else
    case "$(uname -s)" in
        Darwin)               OS="macos" ;;
        Linux)                OS="linux" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *)                    echo "Unsupported OS: $(uname -s)"; exit 1 ;;
    esac
fi

if [[ -n "${DEVKIT_ARCH:-}" ]]; then
    ARCH="$DEVKIT_ARCH"
else
    case "$(uname -m)" in
        x86_64)          ARCH="x86_64" ;;
        aarch64|arm64)   ARCH="arm64" ;;
        i686|i386)       ARCH="x86" ;;
        *)               echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
fi

URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-core-devkit-${FRIDA_VERSION}-${OS}-${ARCH}.tar.xz"

echo "Downloading frida-core-devkit ${FRIDA_VERSION} for ${OS}/${ARCH}..."
mkdir -p $DEVKIT_DIR
curl -fL "$URL" | tar -xJ -C $DEVKIT_DIR
echo "Done. Files extracted to ./$DEVKIT_DIR"
