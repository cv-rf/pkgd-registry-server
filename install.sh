#!/usr/bin/env bash
set -e

CLI_NAME="pkgd"
REPO="cv-rf/pkgd"

echo "=> Installing $CLI_NAME..."

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Linux" ]; then
    echo "Error: This script currently only supports Linux."
    echo "Mac/Windows binaries might come soon."
    exit 1
fi

# Map uname output to standard release asset naming conventions
if [ "$ARCH" = "x86_64" ]; then
    RELEASE_ARCH="amd64"
else
    echo "Error: Currently only x86_64 architecture is supported."
    exit 1
fi

LIBC="gnu"
if ldd /bin/sh 2>&1 | grep -iq 'musl'; then
    LIBC="musl"
fi

# Construct TARGET to match the uploaded 'linux-amd64-musl' format
TARGET="linux-${RELEASE_ARCH}-${LIBC}"
echo "=> Detected target: $TARGET"

echo "=> Fetching latest release version..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Error: Could not fetch latest release."
    exit 1
fi

echo "=> Found version $LATEST_TAG"

TAR_FILENAME="${CLI_NAME}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/${TAR_FILENAME}"
TMP_DIR=$(mktemp -d)
TAR_FILE="$TMP_DIR/binary.tar.gz"

echo "=> Downloading from $DOWNLOAD_URL..."
if ! curl -sfL "$DOWNLOAD_URL" -o "$TAR_FILE"; then
    echo "Error: Failed to download $TAR_FILENAME. Make sure it was uploaded to the latest release!"
    rm -rf "$TMP_DIR"
    exit 1
fi

tar -xzf "$TAR_FILE" -C "$TMP_DIR"

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

if [ -f "$TMP_DIR/bin/$CLI_NAME" ]; then
    mv "$TMP_DIR/bin/$CLI_NAME" "$INSTALL_DIR/$CLI_NAME"
elif [ -f "$TMP_DIR/$CLI_NAME" ]; then
    mv "$TMP_DIR/$CLI_NAME" "$INSTALL_DIR/$CLI_NAME"
else
    mv "$TMP_DIR"/*/"$CLI_NAME" "$INSTALL_DIR/$CLI_NAME" 2>/dev/null || mv "$TMP_DIR"/* "$INSTALL_DIR/$CLI_NAME"
fi

chmod +x "$INSTALL_DIR/$CLI_NAME"
rm -rf "$TMP_DIR"

echo "=> $CLI_NAME installed successfully to $INSTALL_DIR/$CLI_NAME"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    USER_SHELL=$(basename "$SHELL" 2>/dev/null || echo "bash")
    PROFILE_FILE="~/.bashrc"
    
    if [ "$USER_SHELL" = "zsh" ]; then
        PROFILE_FILE="~/.zshrc"
    elif [ "$USER_SHELL" = "sh" ] || [ "$USER_SHELL" = "dash" ]; then
        PROFILE_FILE="~/.profile"
    fi

    echo ""
    echo "WARNING: $INSTALL_DIR is not in your PATH."
    echo "Add the following line to your $PROFILE_FILE:"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\""
fi