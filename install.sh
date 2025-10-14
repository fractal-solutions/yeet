#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.

echo "Starting yeet installation..."

# --- 1. Check and Install Bun ---
if ! command -v bun &> /dev/null; then
    echo "Bun runtime not found. Attempting to install Bun..."

    # Try installing via npm if available
    if command -v npm &> /dev/null; then
        echo "npm found. Attempting to install Bun via npm..."
        if npm install -g bun; then
            echo "Bun installed successfully via npm."
        else
            echo "Failed to install Bun via npm. Trying curl method..."
            # Fallback to curl method
            /bin/bash -c "curl -fsSL https://bun.sh/install | bash"
            echo "Bun installed successfully via curl script."
        fi
    else
        echo "npm not found. Installing Bun via curl script..."
        /bin/bash -c "curl -fsSL https://bun.sh/install | bash"
        echo "Bun installed successfully via curl script."
    fi

    # Ensure Bun's bin directory is in PATH for the current session
    if [ -d "$HOME/.bun/bin" ] && [[ ":$PATH:" != *":$HOME/.bun/bin:"* ]]; then
        export PATH="$HOME/.bun/bin:$PATH"
        echo "Added $HOME/.bun/bin to PATH for current session."
    fi
else
    echo "Bun runtime already installed."
fi

# Verify Bun is now available
if ! command -v bun &> /dev/null; then
    echo "Error: Bun could not be installed or found. Please install Bun manually and re-run the script."
    exit 1
fi

echo "Bun is ready."

# --- 2. Build yeet Executable ---
echo "Building yeet executable..."
# Ensure we are in the project directory for bun install and build
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd "$SCRIPT_DIR"

bun install --production # Install production dependencies only
bun build tui.ts --compile --outfile yeet

if [ ! -f "./yeet" ]; then
    echo "Error: Failed to build yeet executable."
    exit 1
fi
echo "yeet executable built successfully."

# --- 3. Place Executable and Update PATH ---
INSTALL_DIR="$HOME/.local/bin"
EXECUTABLE_NAME="yeet"
EXECUTABLE_PATH="$INSTALL_DIR/$EXECUTABLE_NAME"

echo "Installing yeet to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
mv "./$EXECUTABLE_NAME" "$EXECUTABLE_PATH"
chmod +x "$EXECUTABLE_PATH"
echo "yeet executable moved to $EXECUTABLE_PATH."

# Automatically add ~/.local/bin to PATH if not already present
SHELL_CONFIG_FILE=""
if [ -n "$ZSH_VERSION" ]; then
    SHELL_CONFIG_FILE="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_CONFIG_FILE="$HOME/.bashrc"
else
    echo "Warning: Could not detect shell type (bash or zsh). Please manually add $INSTALL_DIR to your PATH."
fi

if [ -n "$SHELL_CONFIG_FILE" ]; then
    if ! grep -q "export PATH=\"$HOME/.local/bin:\$PATH\"" "$SHELL_CONFIG_FILE"; then
        echo -e "\033[1;32mAdding $INSTALL_DIR to PATH in $SHELL_CONFIG_FILE...\033[0m" # Green and bold
        echo "" >> "$SHELL_CONFIG_FILE"
        echo "# Add yeet to PATH" >> "$SHELL_CONFIG_FILE"
        echo "export PATH=\"$HOME/.local/bin:\$PATH\"" >> "$SHELL_CONFIG_FILE"
        echo -e "\033[1;32mPATH updated in $SHELL_CONFIG_FILE.\033[0m" # Green and bold
        echo -e "\033[1;33mPlease restart your terminal or run 'source $SHELL_CONFIG_FILE' to apply changes.\033[0m" # Yellow and bold
    else
        echo -e "\033[1;32m$INSTALL_DIR is already in PATH in $SHELL_CONFIG_FILE.\033[0m" # Green and bold
    fi
fi

echo -e "\n\033[1;32myeet installation complete!\033[0m" # Green and bold
echo -e "\033[1;32mYou can now run 'yeet [options] [path]' from any directory.\033[0m" # Green and bold
echo -e "\033[1;33mRemember to restart your terminal or run 'source $SHELL_CONFIG_FILE' to apply changes.\033[0m" # Yellow and bold
