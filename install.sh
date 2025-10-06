#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

INSTALL_DIR="/usr/local/bin"

echo "🚀 Yeet Server Installation Script"
echo "----------------------------------"

# --- 1. Dependency Checks & Installation (Interactive) ---

# Check for Zig
if ! command -v zig &> /dev/null; then
    echo "
❌ Zig is not installed or not in your PATH."
    echo "Please install Zig first. You can find instructions at https://ziglang.org/download/"
    echo "After installation, ensure 'zig' is in your system's PATH."
    exit 1
fi
echo "✅ Zig found."

# Check for Node.js and npm
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    echo "
❌ Node.js and/or npm are not installed or not in your PATH."
    echo "Please install Node.js (which includes npm). You can find instructions at https://nodejs.org/en/download/"
    echo "After installation, ensure 'node' and 'npm' are in your system's PATH.""
    exit 1
fi
echo "✅ Node.js and npm found."

# Check for pkg and install if not found
if ! npm list -g pkg &> /dev/null; then
    echo "
📦 'pkg' is not installed globally. Installing now..."
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
echo "
⚙️ Building yeet server (Zig executable)..."
zig build-exe yeet.zig
if [ $? -ne 0 ]; then
    echo "❌ Failed to build yeet.zig. Please check for compilation errors."
    exit 1
fi
echo "✅ yeet executable built."

# --- 3. Build yeet-tui (Node.js executable) ---
echo "
📦 Installing Node.js dependencies for TUI..."
npm install
if [ $? -ne 0 ]; then
    echo "❌ Failed to install Node.js dependencies for TUI. Please check your npm installation."
    exit 1
fi
echo "✅ Node.js dependencies installed."

# Determine pkg target
OS=$(uname -s)
ARCH=$(uname -m)
PKG_TARGET=""

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64) PKG_TARGET="node18-linux-x64" ;;
            aarch64) PKG_TARGET="node18-linux-arm64" ;;
            *) echo "❌ Unsupported Linux architecture: $ARCH" ; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            x86_64) PKG_TARGET="node18-macos-x64" ;;
            arm64) PKG_TARGET="node18-macos-arm64" ;;
            *) echo "❌ Unsupported macOS architecture: $ARCH" ; exit 1 ;;
        esac
        ;;
    *) echo "❌ Unsupported OS: $OS" ; exit 1 ;;
esac

echo "
⚙️ Bundling yeet-tui (Node.js executable) for target: $PKG_TARGET..."
pkg . --targets "$PKG_TARGET"
if [ $? -ne 0 ]; then
    echo "❌ Failed to bundle yeet-tui. Please check 'pkg' output."
    exit 1
fi
echo "✅ yeet-tui executable bundled."

# --- 4. Placement in PATH (Requires sudo) ---
echo "
Installing executables to $INSTALL_DIR (requires sudo)..."

# Ensure install directory exists
sudo mkdir -p "$INSTALL_DIR"

sudo cp ./zig-out/bin/yeet "$INSTALL_DIR/yeet_server"
sudo cp ./dist/yeet-tui-"${OS,,}"-"${ARCH}" "$INSTALL_DIR/yeet_tui"
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
echo "
🧹 Cleaning up build artifacts..."
rm -rf zig-out dist node_modules
echo "✅ Cleanup complete."

echo "
🎉 Installation complete!"
echo "You can now run 'yeet <path_to_serve> <port_number>' from any directory."
echo "Example: yeet . 9090"
