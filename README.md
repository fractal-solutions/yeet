# yeet

A simple, fast, and modern file and directory server with a built-in terminal UI, powered by Bun.

## Features

`yeet` offers a robust and user-friendly solution for serving files and directories, packed with powerful features:

-   **High-Performance File Serving**: Experience blazing fast delivery of files and directories, powered by Bun.
-   **Optimized for Web Applications & Rapid Prototyping**: Seamlessly serve built Single Page Applications (SPAs) like those from Vite, React, Vue, or Angular. `yeet` simplifies development by providing instant serving with automatic `index.html` fallbacks. **Crucially, when authentication is enabled, `yeet` automatically provides themed login and signup pages, handling the entire authentication flow for your web application out-of-the-box.** This allows you to focus on your application logic without worrying about building or integrating authentication infrastructure.
-   **Integrated Secure Authentication & User Management**: Get built-in JWT-based authentication, user login/signup, and comprehensive user management (create, delete, change password, permissions) via an intuitive Terminal UI. This allows you to quickly scaffold and serve web projects with secure access control from day one, **without writing a single line of authentication code for your frontend.**
    *   **User Login & Signup**: Users can securely log in, and new users can sign up (configurable).
    *   **Role-Based Access Control**: Implement a path-based permission system to precisely control user access to specific directories.
-   **Interactive Terminal UI (TUI)**: A beautiful and intuitive TUI for comprehensive server and user management, including:
    *   Creating and deleting users.
    *   Changing user passwords.
    *   Managing user permissions with ease.
-   **Customizable Web Interface**:
    *   **Modern Directory Listing**: Enjoy a sleek, dark-themed, and browsable directory listing.
    *   **Theming Support**: Personalize the web interface with a variety of built-in themes.
-   **Folder Download**: Easily download entire folders as ZIP archives.

## Installation

To install `yeet` globally, download or clone this repository and run the `install.sh` script:

```bash
git clone https://github.com/fractal-solutions/yeet.git
cd yeet
chmod +x install.sh
./install.sh
```

This script will:
1.  Check for Bun runtime and install it if not found (using `npm` or `curl`).
2.  Build the `yeet` executable.
3.  Move the executable to `~/.local/bin`.
4.  Automatically add `~/.local/bin` to your shell's PATH (for bash/zsh).

After installation, please restart your terminal or run `source ~/.bashrc` (or `source ~/.zshrc`) for the changes to take effect.

## Usage

Once installed, you can run `yeet` from any directory.

```bash
yeet [options] [path]
```

### Core Options

-   `[path]`: The file or directory you want to serve. Defaults to the current directory (`.`).
-   `--port=<port_number>`: Specifies the port on which the server will listen. Defaults to `3000` or the value of the `PORT` environment variable.

### Authentication Options

These options are only relevant when `--auth` is enabled.

-   `--auth`: Enables JWT-based authentication, protecting all file serving and activating user management features in the TUI.
-   `--no-signup`: When used with `--auth`, this disables the public signup page, meaning new users can only be created via the TUI.
-   `--session=<duration>`: Sets the JWT session expiration time. Examples: `15m` (15 minutes), `1h` (1 hour), `3d` (3 days), `30s` (30 seconds). If not provided, sessions default to `1h`.

### Appearance Options

-   `--title="<Your Title>"`: Sets a custom title that will be displayed on the login, signup, and explorer pages. Defaults to `yeet`.
-   `--theme=<theme_name>`: Applies a visual theme to the web interface. Available themes:
    *   `default`: The standard dark theme.
    *   `blue`: A cool blue-toned dark theme.
    *   `green`: A calm green-toned dark theme.
    *   `dark`: A very dark, high-contrast theme.
    *   `light`: A bright, light-mode theme.
    *   `zen`: A calm, minimalist theme with soft greens and grays.
    *   `glass`: A theme with subtle transparency, giving a frosted glass effect.
    *   `aero`: A vibrant theme with gradients and a slightly metallic, modern feel.
    *   `matrix`: A dark theme with neon green accents, reminiscent of the Matrix movie.
    *   `solarized`: An eye-friendly theme with a carefully selected color palette.
    Defaults to `default`.

### Serving Web Applications

`yeet` is ideal for quickly serving static web applications, Single Page Applications (SPAs), or individual HTML files.

-   **Serving a Build Directory**: Point `yeet` to your project's build output directory (e.g., `dist`, `build`, `public`) to instantly serve your compiled Vite, React, Vue, or Angular applications. `yeet` will automatically serve `index.html` for directory requests.
    ```bash
    yeet ./dist
    ```
-   **Serving an HTML File**: Directly serve a specific HTML file.
    ```bash
    yeet ./my-app/index.html
    ```

### The Terminal UI (TUI)

When you start the server, you will be greeted by the TUI. This is your main control panel.

-   **Create User**: (Auth only) Add a new user to the system.
-   **Manage Users**: (Auth only) Enter the user management menu to edit existing users.
-   **Exit Server**: Gracefully shuts down the server process.

### Authentication & User Management

When you run with the `--auth` flag, all file serving is protected. Users accessing the server from a web browser will be redirected to a login page. The TUI becomes your admin panel.

From the **Manage Users** menu, you can select a user to perform the following actions:

-   **Manage Permissions**: Enter the permissions editor for that user.
-   **Change Password**: Update the user's password.
-   **Delete User**: Permanently remove the user from the system.

### How Permissions Work

The permission system is path-based. Each user has a list of paths they are allowed to access. A user can access a path if it or any of its parent directories are in their permission list.

**Example:**

A user with the permissions `["/docs", "/images/cats"]`:
-   ✅ **Can** access `/docs/guide.pdf`
-   ✅ **Can** access `/images/cats/fluffy.jpg`
-   ❌ **Cannot** access `/videos/funny.mp4`
-   ❌ **Cannot** access `/images/dogs/buddy.png`

By default, a new user is given permission to `/`, which grants access to everything.

**Managing Permissions in the TUI:**

1.  Navigate to `Manage Users` and select a user.
2.  Choose `Manage Permissions`.
3.  You will see a list of the user's current permissions.
4.  **Add Permission**: Prompts you to type a new path (must start with `/`).
5.  **Remove Permission**: Opens a multi-select prompt allowing you to check which paths to remove from the user's list.

## How It Works

The `bun start` command executes the `tui.ts` file. This script is the main entry point and launches the interactive terminal UI. It then spawns the actual Bun server (`index.ts`) as a background process. The TUI then acts as a controller, sending API calls to the local server to manage users and shutting down the server process when you exit.