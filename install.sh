#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

INSTALL_DIR="/usr/local/bin"
BUILD_DIR="build"

echo "🚀 Yeet Server Installation Script"
echo "----------------------------------"

# --- 1. Determine OS and Architecture ---
OS=$(uname -s)
ARCH=$(uname -m)

ZIG_TARGET_DIR=""
NODE_TARGET_DIR=""

if [ "$OS" = "Linux" ]; then
    if [ "$ARCH" = "x86_64" ]; then
        ZIG_TARGET_DIR="x86_64-linux-gnu"
        NODE_TARGET_DIR="linux-x86_64"
    elif [ "$ARCH" = "aarch64" ]; then
        ZIG_TARGET_DIR="aarch64-linux-gnu"
        NODE_TARGET_DIR="linux-aarch64"
    else
        echo "❌ Unsupported Linux architecture: $ARCH" ; exit 1
    fi
elif [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" = "x86_64" ]; then
        ZIG_TARGET_DIR="x86_64-macos-none"
        NODE_TARGET_DIR="macos-x86_64"
    elif [ "$ARCH" = "arm64" ]; then
        ZIG_TARGET_DIR="aarch64-macos-none"
        NODE_TARGET_DIR="macos-aarch64"
    else
        echo "❌ Unsupported macOS architecture: $ARCH" ; exit 1
    fi
elif [ "$OS" = "Windows" ]; then
    if [ "$ARCH" = "x86_64" ]; then
        ZIG_TARGET_DIR="x86_64-windows-gnu"
        NODE_TARGET_DIR="windows-x86_64"
    elif [ "$ARCH" = "aarch64" ]; then
        ZIG_TARGET_DIR="aarch64-windows-gnu"
        NODE_TARGET_DIR="windows-aarch64"
    else
        echo "❌ Unsupported Windows architecture: $ARCH" ; exit 1
    fi
else
    echo "❌ Unsupported OS: $OS" ; exit 1
fi

# --- 2. Check for pre-built binaries ---
if [ ! -d "$BUILD_DIR" ]; then
    echo "❌ Build directory '$BUILD_DIR' not found."
    echo "Please run 'build.sh' first to generate the executables."
    exit 1
fi

if [ ! -f "$BUILD_DIR/zig/$ZIG_TARGET_DIR/yeet" ]; then
    echo "❌ Zig executable for $OS ($ARCH) not found in '$BUILD_DIR/zig/$ZIG_TARGET_DIR/yeet'."
    echo "Please run 'build.sh' first."
    exit 1
fi

if [ ! -f "$BUILD_DIR/node/$NODE_TARGET_DIR/yeet-tui" ]; then
    echo "❌ Node.js TUI executable for $OS ($ARCH) not found in '$BUILD_DIR/node/$NODE_TARGET_DIR/yeet-tui'."
    echo "Please run 'build.sh' first."
    exit 1
fi

if [ ! -f "$BUILD_DIR/node/$NODE_TARGET_DIR/yeet-auth" ]; then
    echo "❌ Node.js Auth executable for $OS ($ARCH) not found in '$BUILD_DIR/node/$NODE_TARGET_DIR/yeet-auth'."
    echo "Please run 'build.sh' first."
    exit 1
fi

if [ ! -f "$BUILD_DIR/orchestrator/yeet.sh" ]; then
    echo "❌ Orchestrator script 'yeet.sh' not found in '$BUILD_DIR/orchestrator/'."
    echo "Please run 'build.sh' first."
    exit 1
fi

echo "✅ Found pre-built executables for $OS ($ARCH)."

# --- 3. Placement in PATH (Requires sudo) ---
echo ""
echo "Installing executables to $INSTALL_DIR (requires sudo)..."

# Ensure install directory exists
sudo mkdir -p "$INSTALL_DIR"

sudo cp "$BUILD_DIR/zig/$ZIG_TARGET_DIR/yeet" "$INSTALL_DIR/yeet_server"
sudo cp "$BUILD_DIR/node/$NODE_TARGET_DIR/yeet-tui" "$INSTALL_DIR/yeet_tui"
sudo cp "$BUILD_DIR/node/$NODE_TARGET_DIR/yeet-auth" "$INSTALL_DIR/yeet_auth"
sudo cp "$BUILD_DIR/orchestrator/yeet.sh" "$INSTALL_DIR/yeet"

# Make sure the copied scripts are executable
sudo chmod +x "$INSTALL_DIR/yeet_server"
sudo chmod +x "$INSTALL_DIR/yeet_tui"
sudo chmod +x "$INSTALL_DIR/yeet_auth"
sudo chmod +x "$INSTALL_DIR/yeet"

if [ $? -ne 0 ]; then
    echo "❌ Failed to copy executables. Please check sudo permissions or target directory."
    exit 1
fi
echo "✅ Executables installed to $INSTALL_DIR."

# --- 4. Cleanup ---
echo ""
echo "🧹 Cleaning up build artifacts..."
rm -rf "$BUILD_DIR"
echo "✅ Cleanup complete."

echo ""
echo "🎉 Installation complete!"
echo "You can now run 'yeet <path_to_serve> <port_number>' from any directory."
echo "Example: yeet . 9090"
