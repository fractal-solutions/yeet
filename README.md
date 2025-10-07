# 🚀 Yeet Server

## Simple, Fast, and Interactive File Serving

Yeet is a lightweight and blazing-fast file server built with Zig, designed for quickly serving files or directories over HTTP. It comes with an interactive terminal user interface (TUI) for easy control, allowing you to start and stop your server seamlessly.

--- 

### ✨ Features

*   **Blazing Fast:** Built with Zig for optimal performance.
*   **Simple Setup:** Easy to get up and running.
*   **Interactive TUI:** Control your server with a clean, responsive terminal interface.
*   **Serve Files or Directories:** Flexible serving options.
*   **Cross-Platform:** Designed to work across various operating systems.

### 📦 Installation

Yeet provides pre-built binaries for various platforms, simplifying installation for end-users. If you wish to build from source, follow the "Building from Source" instructions below.

**For End-Users (using pre-built binaries):**

To install Yeet and make it available system-wide, follow these steps:

1.  **Clone the Repository:**
    ```bash
    git clone github.com/fractal-solutions/yeet
    cd yeet
    ```
    *(Replace `<your-repo-url>` with the actual URL of your Yeet repository.)*

2.  **Run the Installation Script (with sudo):**
    The `install.sh` script will detect your operating system and architecture, and then copy the appropriate pre-built `yeet` server, `yeet-tui` interface, and the `yeet` orchestration script to `/usr/local/bin`. Since this involves writing to system directories, you *must* run the script with `sudo`.

    ```bash
    sudo ./install.sh
    ```
    The script will require your `sudo` password to complete the installation.

**Building from Source (for Developers/Contributors):**

If you want to build Yeet from its source code for all supported platforms, you'll need Zig, Node.js, npm, and `pkg` installed.

1.  **Prerequisites:** Ensure Zig, Node.js, and npm are installed and in your PATH. You will also need `pkg` installed globally (`npm install -g pkg`).
2.  **Clone the Repository:**
    ```bash
    git clone <your-repo-url>
    cd yeet
    ```
    *(Replace `<your-repo-url>` with the actual URL of your Yeet repository.)*
3.  **Run the Build Script:**
    ```bash
    ./build.sh
    ```
    This script will compile `yeet.zig` and bundle `tui.js` for all supported operating systems and architectures, placing the resulting binaries in the `build/` directory.

### 🚀 Usage

Once installed, you can run the `yeet` server from any directory. The `yeet` command acts as an orchestrator, launching both the server and its interactive TUI.

```bash
yeet <path_to_serve> <port_number> [options]
```

**Options:**

*   `--auth`: Enables the authentication system. When enabled, users will be redirected to a login page before accessing served content.
*   `--auth-server-port <port>`: Specifies the port for the internal authentication server (default: `3001`). Only relevant when `--auth` is used.
*   `--no-signup`: Disables the user signup option on the login page. Only relevant when `--auth` is used.

**Examples:**

*   **Serve the current directory on port 9090 (no authentication):**
    ```bash
    yeet . 9090
    ```
*   **Serve a specific file (`my_document.pdf`) on port 8000 (no authentication):**
    ```bash
    yeet /path/to/my_document.pdf 8000
    ```
*   **Serve a directory (`~/my_website`) on port 3000 with authentication enabled:**
    ```bash
    yeet ~/my_website 3000 --auth
    ```
*   **Serve with authentication on a custom auth server port and no signup:**
    ```bash
    yeet . 8080 --auth --auth-server-port 4000 --no-signup
    ```
*   **Serve the current directory on port 80 (requires sudo for ports < 1024):**
    ```bash
    sudo yeet . 80
    ```
*   **Accessing from another device on your local network:**
    1.  Run `yeet` on your server machine (e.g., `yeet . 9090 --auth`).
    2.  Find your server machine's local IP address (e.g., `192.168.1.105`).
    3.  On another device connected to the *same WiFi network*, open a web browser and go to `http://192.168.1.105:9090`. You will be redirected to the login page if authentication is enabled.

#### Interactive TUI

Once the server starts, an interactive terminal interface will appear:

*   It will display the server's status and the port it's running on.
*   If authentication is enabled, a "Create User (Admin)" option will be available.
*   Use the **Up/Down arrow keys** to navigate.
*   Press **Enter** to select an option.
*   Select **"Exit Server"** to gracefully shut down the `yeet` server.

### 🔒 Authentication

When `yeet` is run with the `--auth` flag, it enables a built-in authentication system:

*   **Login/Signup UI:** Users attempting to access served content will be redirected to a web-based login page. If not disabled by `--no-signup`, a signup option will also be available.
*   **User Management:** User credentials (username and hashed password) are stored in a `users.json` file in the project's root directory.
*   **Admin User Creation:** The interactive TUI provides an "Create User (Admin)" option, allowing an administrator to create new user accounts directly from the terminal. This is useful for initial setup or managing users when signup is disabled.
*   **Session Management:** Authentication uses secure, HTTP-only cookies to manage user sessions.
*   **Security:** For production environments or public access, it is highly recommended to run `yeet` behind a reverse proxy (e.g., Nginx, Caddy) to enable HTTPS, which encrypts traffic and protects authentication credentials in transit.

**Creating an Admin User via TUI:**

1.  Start `yeet` with authentication enabled (e.g., `yeet . 9090 --auth`).
2.  In the TUI, select "Create User (Admin)".
3.  Follow the prompts to enter a username and password for the new user.
4.  This user can then log in via the web interface to access the served content.

### 📂 Project Structure

*   `yeet.zig`: The core Zig source code for the file server.
*   `yeet.sh`: The main script that orchestrates building, running, and managing the `yeet` server with the TUI.
*   `install.sh`: The script to automate the installation process.
*   `tui.js`: The Node.js source code for the interactive terminal user interface.
*   `package.json`: Node.js project configuration and dependencies for `tui.js`.
*   `yeet-tui`: The bundled standalone executable of `tui.js` (generated by `pkg`).
*   `README.md`: This file.

### 🤝 Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

### 📄 License

This project is licensed under the ISC License. See the `LICENSE` file for details.