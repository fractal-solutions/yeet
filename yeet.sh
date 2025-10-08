#!/bin/bash

# --- Argument Parsing ---
AUTH_ENABLED=false
AUTH_SERVER_PORT=3001 # Default auth server port
NO_SIGNUP=false
YEET_ARGS=() # Arguments to pass to yeet_server

# Parse arguments. Note: This simple parsing assumes flags come before positional args.
# For more robust parsing, a library like getopt could be used.
while (( "$#" )); do
    case "$1" in
        --auth)
            AUTH_ENABLED=true
            shift
            ;;
        --auth-server-port)
            AUTH_SERVER_PORT="$2"
            shift 2
            ;;
        --no-signup)
            NO_SIGNUP=true
            shift
            ;;
        -*)
            # Unknown flag, pass to yeet_server
            YEET_ARGS+=("$1")
            shift
            ;;
        *)
            # Positional arguments (path and port)
            YEET_ARGS+=("$1")
            shift
            ;;
    esac
done

# Resolve path to absolute path
if [ -n "${YEET_ARGS[0]}" ]; then
    YEET_ARGS[0]=$(realpath "${YEET_ARGS[0]}")
fi

# --- yeet_auth server start/kill logic ---
YEET_AUTH_PID=""
if $AUTH_ENABLED; then
    echo "🚀 Starting yeet_auth server on port $AUTH_SERVER_PORT..."
    if $NO_SIGNUP; then
        YEET_SHARE_DIR=/usr/local/share/yeet yeet_auth --auth-server-port $AUTH_SERVER_PORT --no-signup &
    else
        YEET_SHARE_DIR=/usr/local/share/yeet yeet_auth --auth-server-port $AUTH_SERVER_PORT &
    fi
    YEET_AUTH_PID=$!
    echo "✅ yeet_auth server (PID: $YEET_AUTH_PID) started."
fi

# --- yeet_server start/kill logic ---
# Assuming yeet_server is in PATH after installation
echo "🚀 Starting yeet_server..."
if $AUTH_ENABLED; then
    YEET_SHARE_DIR=/usr/local/share/yeet yeet_server --auth --auth-server-port $AUTH_SERVER_PORT ${YEET_ARGS[@]} &
else
    yeet_server ${YEET_ARGS[@]} &
fi
YEET_SERVER_PID=$!
echo "✅ yeet_server (PID: $YEET_SERVER_PID) started."

# Function to kill processes
kill_processes() {
    if ps -p $YEET_SERVER_PID > /dev/null; then
        kill $YEET_SERVER_PID
        wait $YEET_SERVER_PID 2>/dev/null
        echo "Yeet server (PID: $YEET_SERVER_PID) stopped."
    fi
    if [ -n "$YEET_AUTH_PID" ] && ps -p $YEET_AUTH_PID > /dev/null; then
        kill $YEET_AUTH_PID
        wait $YEET_AUTH_PID 2>/dev/null
        echo "Yeet auth server (PID: $YEET_AUTH_PID) stopped."
    fi
}

# Ensure processes are killed on script exit
trap kill_processes EXIT

# --- Launch Node.js TUI ---
# Assuming yeet_tui is in PATH after installation
echo "🚀 Launching yeet_tui..."
TUI_CMD="yeet_tui $YEET_SERVER_PID ${YEET_ARGS[1]}" # TUI still needs yeet_server PID
if $AUTH_ENABLED; then
    TUI_CMD+=" --auth --auth-server-port $AUTH_SERVER_PORT" # Pass auth info to TUI
fi
$TUI_CMD

# The TUI script has exited, so kill the yeet server and auth server
# The trap will handle the actual killing.

exit 0
