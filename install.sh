#!/bin/sh
set -e

# caddy-analyze static binary installer
# Supports: Linux (amd64, arm64, armv7, 386), macOS (amd64, arm64)

REPO="L9Lenny/caddy-analyzer"
BINARY_NAME="caddy-analyze"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    armv7*)
        ARCH="arm"
        ;;
    i386|i686)
        ARCH="386"
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case "$OS" in
    linux)
        OS="linux"
        ;;
    darwin)
        OS="darwin"
        ;;
    *)
        echo "Error: Unsupported operating system: $OS"
        exit 1
        ;;
esac

TAG=$(curl -sSfL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$TAG" ]; then
    TAG="v0.1.0"
fi

URL="https://github.com/$REPO/releases/download/$TAG/caddy-analyzer_${TAG#v}_${OS}_${ARCH}.tar.gz"
if ! curl -sSf -I "$URL" >/dev/null 2>&1; then
    URL="https://github.com/$REPO/releases/download/$TAG/caddy-analyze_${TAG#v}_${OS}_${ARCH}.tar.gz"
fi

echo "⚡ Installing $BINARY_NAME $TAG for $OS/$ARCH..."

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if echo "$URL" | grep -q '\.tar\.gz$'; then
    curl -sSfL "$URL" -o "$TMP_DIR/caddy-analyze.tar.gz"
    tar -xzf "$TMP_DIR/caddy-analyze.tar.gz" -C "$TMP_DIR"
    BIN_PATH="$TMP_DIR/$BINARY_NAME"
else
    curl -sSfL "$URL" -o "$TMP_DIR/$BINARY_NAME"
    BIN_PATH="$TMP_DIR/$BINARY_NAME"
fi

chmod +x "$BIN_PATH"

DEST_DIR="/usr/local/bin"
if [ ! -w "$DEST_DIR" ]; then
    echo "Installing to $DEST_DIR (requires sudo)..."
    sudo mv "$BIN_PATH" "$DEST_DIR/$BINARY_NAME"
else
    mv "$BIN_PATH" "$DEST_DIR/$BINARY_NAME"
fi

echo "✔ Success! $BINARY_NAME $TAG installed to $DEST_DIR/$BINARY_NAME"
echo "Run '$BINARY_NAME --help' to get started."
