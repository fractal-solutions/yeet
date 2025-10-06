#!/bin/bash

# --- yeet server start/kill logic ---

# Extract port from arguments (assuming it's the last argument)
PORT="${!#}"

# Start yeet server in the background
zig build-exe yeet.zig &> /dev/null
./yeet "$@" &
YEET_PID=$!

# Function to kill yeet process
kill_yeet() {
    if ps -p $YEET_PID > /dev/null
    then
        kill $YEET_PID
        wait $YEET_PID 2>/dev/null
        echo "Yeet server (PID: $YEET_PID) stopped."
    else
        echo "Yeet server (PID: $YEET_PID) was not running."
    fi
}

# Ensure yeet process is killed on script exit
trap kill_yeet EXIT

# --- Launch Node.js TUI ---
# This section assumes you have bundled tui.js into a standalone executable named 'yeet-tui'
# using 'pkg' or 'nexe' and placed it in the same directory as this script.

# Check if the bundled TUI executable exists
if [ ! -f "./yeet-tui" ]; then
    echo "Error: Bundled TUI executable './yeet-tui' not found."
    echo "Please run 'npm install -g pkg' and then 'pkg . --targets node18-linux-x64' in this directory to create it."
    exit 1
fi

# Launch the bundled TUI executable, passing yeet's PID and port
./yeet-tui "$YEET_PID" "$PORT"

# The TUI script has exited, so kill the yeet server
# The trap will handle the actual killing.

exit 0
