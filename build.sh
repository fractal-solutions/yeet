#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

BUILD_DIR="build"
ZIG_OUT_DIR="$BUILD_DIR/zig"
NODE_OUT_DIR="$BUILD_DIR/node"
ORCHESTRATOR_OUT_DIR="$BUILD_DIR/orchestrator"

echo "🚀 Starting multi-platform build process..."
echo "-----------------------------------------"

# Clean previous build artifacts
echo "🧹 Cleaning up previous build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$ZIG_OUT_DIR" "$NODE_OUT_DIR" "$ORCHESTRATOR_OUT_DIR"
echo "✅ Cleaned and created build directories."

# --- Build yeet (Zig executable) for multiple targets ---
echo ""
echo "⚙️ Building yeet server (Zig executable) for multiple targets..."

# Define Zig targets
ZIG_TARGETS=(
    "x86_64-linux-gnu"
    "aarch64-linux-gnu"
    "x86_64-windows-gnu"
    "aarch64-windows-gnu"
    "x86_64-macos-none"
    "aarch64-macos-none"
)

for TARGET in "${ZIG_TARGETS[@]}"; do
    echo "  Building for Zig target: $TARGET"
    # Determine output filename based on target OS
    OUTPUT_NAME="yeet"
    if [[ "$TARGET" == *windows* ]]; then
        OUTPUT_NAME="yeet.exe"
    fi

    # Build the executable in the current directory
    zig build-exe -target "$TARGET" yeet.zig -lc
    if [ $? -ne 0 ]; then
        echo "❌ Failed to build yeet.zig for $TARGET. Please check Zig installation and target support."
        exit 1
    fi
    # Move and rename the executable to the target-specific directory
    mkdir -p "$ZIG_OUT_DIR/$TARGET"
    mv "$OUTPUT_NAME" "$ZIG_OUT_DIR/$TARGET/yeet" # Always rename to 'yeet' in the build directory
    echo "  ✅ Built yeet for $TARGET."
done
echo "✅ All yeet executables built."

# --- Build yeet-tui (Node.js executable) for multiple targets ---
echo ""
echo "📦 Installing Node.js dependencies for TUI..."
npm install
if [ $? -ne 0 ]; then
    echo "❌ Failed to install Node.js dependencies for TUI. Please check your npm installation."
    exit 1
fi
echo "✅ Node.js dependencies installed."

echo ""
echo "⚙️ Bundling yeet-tui (Node.js executable) for multiple targets..."

# Define pkg targets and their corresponding OS/ARCH for naming
declare -A PKG_TARGET_MAP
PKG_TARGET_MAP["node18-linux-x64"]="linux-x86_64"
PKG_TARGET_MAP["node18-linux-arm64"]="linux-aarch64"
PKG_TARGET_MAP["node18-win-x64"]="windows-x86_64"
PKG_TARGET_MAP["node18-win-arm64"]="windows-aarch64"
PKG_TARGET_MAP["node18-macos-x64"]="macos-x86_64"
PKG_TARGET_MAP["node18-macos-arm64"]="macos-aarch64"

for PKG_TARGET in "${!PKG_TARGET_MAP[@]}"; do
    OS_ARCH_NAME="${PKG_TARGET_MAP[$PKG_TARGET]}"
    echo "  Bundling for pkg target: $PKG_TARGET (Output name: yeet-tui-$OS_ARCH_NAME)"
    mkdir -p "$NODE_OUT_DIR/$OS_ARCH_NAME"
    pkg . --targets "$PKG_TARGET" -o "$NODE_OUT_DIR/$OS_ARCH_NAME/yeet-tui"
    if [ $? -ne 0 ]; then
        echo "❌ Failed to bundle yeet-tui for $PKG_TARGET. Please check 'pkg' output."
        exit 1
    fi
    echo "  ✅ Bundled yeet-tui for $PKG_TARGET."
done
    echo "✅ All yeet-tui executables bundled."

# --- Build yeet-auth (Node.js executable) for multiple targets ---
echo ""
echo "⚙️ Bundling yeet-auth (Node.js executable) for multiple targets..."

for PKG_TARGET in "${!PKG_TARGET_MAP[@]}"; do
    OS_ARCH_NAME="${PKG_TARGET_MAP[$PKG_TARGET]}"
    echo "  Bundling for pkg target: $PKG_TARGET (Output name: yeet-auth-$OS_ARCH_NAME)"
    mkdir -p "$NODE_OUT_DIR/$OS_ARCH_NAME"
    pkg auth-server.js --assets "auth-ui/,users.json" --targets "$PKG_TARGET" -o "$NODE_OUT_DIR/$OS_ARCH_NAME/yeet-auth"
    if [ $? -ne 0 ]; then
        echo "❌ Failed to bundle yeet-auth for $PKG_TARGET. Please check 'pkg' output."
        exit 1
    fi
    echo "  ✅ Bundled yeet-auth for $PKG_TARGET."
done
echo "✅ All yeet-auth executables bundled."

# --- Copy yeet.sh (orchestration script) ---
echo ""
echo "📝 Copying yeet.sh orchestrator script..."
cp yeet.sh "$ORCHESTRATOR_OUT_DIR/"
echo "✅ yeet.sh copied."

echo ""
echo "🎉 Multi-platform build complete! Binaries are in the '$BUILD_DIR' directory."
