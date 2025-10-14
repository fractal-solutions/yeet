# yeet

A simple, fast, and modern file and directory server with a built-in terminal UI, powered by Bun.

## Features

-   Blazing fast file and directory serving.
-   Optional JWT-based authentication to protect your files.
-   A beautiful, interactive Terminal UI (TUI) for managing the server and users.
-   Path-based permission system to control user access to specific directories.
-   Modern, dark-themed, and browsable directory listing.

## Installation

To install dependencies:

```bash
bun install
```

## Usage

To start the server, use the `start` script from within the `yeet` directory.

```bash
bun start [options] [path]
```

-   `[path]`: The file or directory you want to serve. Defaults to the current directory (`.`).
-   `--auth`: Enables authentication and all related features.
-   `--no-signup`: When used with `--auth`, this disables the public signup page.

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