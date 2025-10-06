#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

INSTALL_DIR="/usr/local/bin"

echo "🚀 Yeet Server Installation Script"
echo "----------------------------------"

# --- 1. Dependency Checks & Installation (Interactive) ---

# Check for Zig
if ! command -v zig > /dev/null 2>&1; then
    echo ""
echo "❌ Zig is not installed or not in your PATH."
    echo "Please install Zig first. You can find instructions at https://ziglang.org/download/"
    echo "After installation, ensure 'zig' is in your system's PATH."
    exit 1
fi
echo "✅ Zig found."

# Check for Node.js and npm
if ! command -v node > /dev/null 2>&1 || ! command -v npm > /dev/null 2>&1; then
    echo ""
echo "❌ Node.js and/or npm are not installed or not in your PATH."
    echo "Please install Node.js (which includes npm). You can find instructions at https://nodejs.org/en/download/"
    echo "After installation, ensure 'node' and 'npm' are in your system's PATH.""
    exit 1
fi
echo "✅ Node.js and npm found."

# Check for pkg and install if not found
if ! npm list -g pkg > /dev/null 2>&1; then
    echo ""
echo "📦 'pkg' is not installed globally. Installing now..."
    npm install -g pkg
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install 'pkg'. Please check your npm installation or try running 'sudo npm install -g pkg'."
        exit 1
    fi
    echo "✅ 'pkg' installed globally."
else
    echo "✅ 'pkg' found globally."
fi

# --- 2. Build yeet (Zig executable) ---
echo ""
echo "⚙️ Building yeet server (Zig executable)..."
zig build-exe yeet.zig
if [ $? -ne 0 ]; then
    echo "❌ Failed to build yeet.zig. Please check for compilation errors."
    exit 1
fi
echo "✅ yeet executable built."

# --- 3. Build yeet-tui (Node.js executable) ---
echo ""
echo "📦 Installing Node.js dependencies for TUI..."
npm install
if [ $? -ne 0 ]; then
    echo "❌ Failed to install Node.js dependencies for TUI. Please check your npm installation."
    exit 1
fi
echo "✅ Node.js dependencies installed."

# Determine pkg target
OS=$(uname -s)
ARCH=$(uname -m)
LOWER_OS=$(echo "$OS" | tr '[:upper:]' '[:lower:]') # Convert OS to lowercase for pkg executable name
PKG_TARGET=""

if [ "$OS" = "Linux" ]; then
    if [ "$ARCH" = "x86_64" ]; then
        PKG_TARGET="node18-linux-x64"
    elif [ "$ARCH" = "aarch64" ]; then
        PKG_TARGET="node18-linux-arm64"
    else
        echo "❌ Unsupported Linux architecture: $ARCH" ; exit 1
    fi
elif [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" = "x86_64" ]; then
        PKG_TARGET="node18-macos-x64"
    elif [ "$ARCH" = "arm64" ]; then
        PKG_TARGET="node18-macos-arm64"
    else
        echo "❌ Unsupported macOS architecture: $ARCH" ; exit 1
    fi
else
    echo "❌ Unsupported OS: $OS" ; exit 1
fi

echo ""
echo "⚙️ Bundling yeet-tui (Node.js executable) for target: $PKG_TARGET..."
pkg . --targets "$PKG_TARGET"
if [ $? -ne 0 ]; then
    echo "❌ Failed to bundle yeet-tui. Please check 'pkg' output."
    exit 1
fi
echo "✅ yeet-tui executable bundled."

# --- 4. Placement in PATH (Requires sudo) ---
echo ""
echo "Installing executables to $INSTALL_DIR (requires sudo)..."

# Ensure install directory exists
sudo mkdir -p "$INSTALL_DIR"

sudo cp ./zig-out/bin/yeet "$INSTALL_DIR/yeet_server"
sudo cp ./dist/yeet-tui-"$LOWER_OS"-"$ARCH" "$INSTALL_DIR/yeet_tui"
sudo cp ./yeet.sh "$INSTALL_DIR/yeet"

# Make sure the copied scripts are executable
sudo chmod +x "$INSTALL_DIR/yeet_server"
sudo chmod +x "$INSTALL_DIR/yeet_tui"
sudo chmod +x "$INSTALL_DIR/yeet"

if [ $? -ne 0 ]; then
    echo "❌ Failed to copy executables. Please check sudo permissions or target directory."
    exit 1
fi
echo "✅ Executables installed to $INSTALL_DIR."

# --- 5. Cleanup ---
echo ""
echo "🧹 Cleaning up build artifacts..."
rm -rf zig-out dist node_modules
echo "✅ Cleanup complete."

echo ""
echo "🎉 Installation complete!"
echo "You can now run 'yeet <path_to_serve> <port_number>' from any directory."
echo "Example: yeet . 9090"