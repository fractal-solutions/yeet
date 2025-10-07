#!/bin/bash

# --- yeet server start/kill logic ---

# Extract port from arguments (assuming it's the last argument)
PORT="${!#}"

# Start yeet server in the background
# Assuming yeet_server is in PATH after installation
yeet_server "$@" &
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
# Assuming yeet_tui is in PATH after installation

# Launch the TUI executable, passing yeet's PID and port
yeet_tui "$YEET_PID" "$PORT"

# The TUI script has exited, so kill the yeet server
# The trap will handle the actual killing.

exit 0