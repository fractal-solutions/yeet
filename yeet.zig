const std = @import("std");
const posix = std.posix;

var interrupted: std.atomic.Value(u8) = std.atomic.Value(u8).init(0); // Assuming Value is the generic atomic struct

// Helper function to make an HTTP request to the auth server
fn makeHttpRequest(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    method: []const u8,
    path: []const u8,
    headers: []const struct { []const u8, []const u8 },
    body: ?[]const u8,
) !std.ArrayList(u8) {
    var client_socket = try std.net.tcpConnectToHost(allocator, host, port);
    defer client_socket.close();

    var writer = client_socket.writer();
    var reader = client_socket.reader();

    try writer.print("{s} {s} HTTP/1.1\r\n", .{ method, path });
    try writer.print("Host: {s}:{d}\r\n", .{ host, port });
    try writer.print("Connection: close\r\n", .{});

    for (headers) |header| {
        try writer.print("{s}: {s}\r\n", .{ header[0], header[1] });
    }

    if (body) |b| {
        try writer.print("Content-Length: {d}\r\n", .{b.len});
        try writer.print("\r\n", .{});
        try writer.writeAll(b);
    } else {
        try writer.print("\r\n", .{});
    }

    var response_buffer = std.ArrayList(u8).init(allocator);
    errdefer response_buffer.deinit();

    var tmp_buf: [1024]u8 = undefined;
    while (true) {
        const bytes_read = reader.read(&tmp_buf) catch |err| {
            if (err == error.EndOfStream) {
                break;
            } else {
                return err;
            }
        };
        if (bytes_read == 0) {
            break;
        }
        try response_buffer.appendSlice(tmp_buf[0..bytes_read]);
    }

    return response_buffer;
}

// Helper function to proxy a request to the auth server
fn proxyRequest(
    allocator: std.mem.Allocator,
    client_writer: anytype, // std.io.Writer
    client_reader: anytype, // std.io.Reader
    auth_server_port: u16,
    method: []const u8,
    path: []const u8,
    headers: std.ArrayList(struct { []const u8, []const u8 }),
    initial_request_body: ?[]const u8, // If we already read some body
) !void {
    var auth_server_socket = try std.net.tcpConnectToHost(allocator, "127.0.0.1", auth_server_port);
    defer auth_server_socket.close();

    var auth_writer = auth_server_socket.writer();
    var auth_reader = auth_server_socket.reader();

    // Forward request line
    try auth_writer.print("{s} {s} HTTP/1.1\r\n", .{ method, path });
    try auth_writer.print("Host: 127.0.0.1:{d}\r\n", .{auth_server_port});
    try auth_writer.print("Connection: close\r\n", .{}); // Ensure connection closes after response

    // Forward headers
    for (headers.items) |header| {
        try auth_writer.print("{s}: {s}\r\n", .{ header[0], header[1] });
    }

    // Forward body
    if (initial_request_body) |b| {
        try auth_writer.writeAll(b);
    }

    if (std.mem.eql(u8, method, "POST")) {
        // Read and forward any remaining body from client
        var client_body_buf: [1024]u8 = undefined;
        while (client_reader.read(&client_body_buf)) |bytes_read| {
            try auth_writer.writeAll(client_body_buf[0..bytes_read]);
        } else |err| {
            if (err != error.EndOfStream) return err;
        }
    }

    try auth_writer.print("\r\n", .{}); // End of request to auth server

    // Read response from auth server and relay to client
    var auth_response_buf: [4096]u8 = undefined;
    while (auth_reader.read(&auth_response_buf)) |bytes_read| {
        try client_writer.writeAll(auth_response_buf[0..bytes_read]);
    } else |err| {
        if (err != error.EndOfStream) return err;
    }
}

fn signalHandler(signum: c_int) callconv(.C) void {
    if (signum == posix.SIG.INT) {
        interrupted.store(1, std.builtin.AtomicOrder.release); // Store 1 for true
        std.log.info("Caught SIGINT, setting interrupted to true.", .{});
    }
}


pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const args = try std.process.argsAlloc(allocator);
    defer allocator.free(args);

    var auth_enabled: bool = false;
    var auth_server_port: u16 = 0; // Default to 0, will be set if --auth is used

    var path_arg: []const u8 = "";
    var port_arg: []const u8 = "";

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--auth")) {
            auth_enabled = true;
        } else if (std.mem.eql(u8, args[i], "--auth-server-port")) {
            i += 1;
            if (i >= args.len) {
                std.io.getStdErr().writer().print("Error: --auth-server-port requires a port number.\n", .{}) catch return;
                return;
            }
            auth_server_port = std.fmt.parseInt(u16, args[i], 10) catch |err| {
                std.log.err("Invalid auth server port number: {s} ({})", .{ args[i], err });
                return;
            };
        } else if (path_arg.len == 0) { // First non-flag argument is path
            path_arg = args[i];
        } else if (port_arg.len == 0) { // Second non-flag argument is port
            port_arg = args[i];
        } else {
            std.io.getStdErr().writer().print("Error: Unrecognized argument: {s}\n", .{args[i]}) catch return;
            return;
        }
    }

    if (path_arg.len == 0 or port_arg.len == 0) {
        std.io.getStdErr().writer().print("Usage: {s} [folder|file] [port] [--auth] [--auth-server-port <port>]\n", .{args[0]}) catch return;
        return;
    }

    const port = std.fmt.parseInt(u16, port_arg, 10) catch |err| {
        std.log.err("Invalid port number: {s} ({})", .{ port_arg, err });
        return;
    };

    if (@import("builtin").target.os.tag == .linux or @import("builtin").target.os.tag == .macos) {
        const action = posix.Sigaction{
            .handler = .{
                .handler = signalHandler,
            },
            .mask = posix.empty_sigset,
            .flags = 0,
        };
        posix.sigaction(posix.SIG.INT, &action, null);
    }

    const address = try std.net.Address.parseIp("0.0.0.0", port);
    const listener_fd = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(listener_fd);

    try posix.setsockopt(listener_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

    try posix.bind(listener_fd, &address.any, address.getOsSockLen());
    try posix.listen(listener_fd, 10);

    const stat = std.fs.cwd().statFile(path_arg) catch |err| {
        std.log.err("Failed to stat {s}: {}", .{ path_arg, err });
        return;
    };

    const stdout = std.io.getStdOut().writer();

    var poll_fds = [_]posix.pollfd{
        .{ .fd = listener_fd, .events = posix.POLL.IN, .revents = 0 },
    };

    switch (stat.kind) {
        .directory => {
            try stdout.print("Serving folder {s} at http://localhost:{d}\n", .{ path_arg, port });
            while (interrupted.load(std.builtin.AtomicOrder.acquire) == 0) { // Check if 0 (false)
                std.log.info("Interrupted flag (start of loop): {}", .{interrupted.load(std.builtin.AtomicOrder.acquire) == 1}); // Log as bool
                const event_count_result = posix.poll(&poll_fds, -1);
                if (interrupted.load(std.builtin.AtomicOrder.acquire) == 1) break; // Explicitly break if interrupted after poll returns
                if (event_count_result) |event_count| {
                    if (event_count == 0) continue;

                    if (poll_fds[0].revents & posix.POLL.IN != 0) {
                        const conn_fd = posix.accept(listener_fd, null, null, 0) catch |err| {
                            if (err == error.WouldBlock) continue;
                            return err;
                        };
                        if (std.Thread.spawn(.{}, handleConnection, .{ allocator, conn_fd, path_arg, auth_enabled, auth_server_port })) |_| {} else |err| {
                            std.log.err("Spawn failed: {}", .{err});
                        }
                    }
                } else |err| {
                    if (err != error.Interrupted) {
                        return error.PollFailed;
                    }
                }
            }
        },
        .file => {
            try stdout.print("Serving file {s} at http://localhost:{d}\n", .{ path_arg, port });
            while (interrupted.load(std.builtin.AtomicOrder.acquire) == 0) { // Check if 0 (false)
                std.log.info("Interrupted flag (start of loop): {}", .{interrupted.load(std.builtin.AtomicOrder.acquire) == 1}); // Log as bool
                const event_count_result = posix.poll(&poll_fds, -1);
                if (interrupted.load(std.builtin.AtomicOrder.acquire) == 1) break; // Explicitly break if interrupted after poll returns
                if (event_count_result) |event_count| {
                    if (event_count == 0) continue;

                    if (poll_fds[0].revents & posix.POLL.IN != 0) {
                        const conn_fd = posix.accept(listener_fd, null, null, 0) catch |err| {
                            if (err == error.WouldBlock) continue;
                            return err;
                        };
                        if (std.Thread.spawn(.{}, handleFileConnection, .{ allocator, conn_fd, path_arg, auth_enabled, auth_server_port })) |_| {} else |err| {
                            std.log.err("Spawn failed: {}", .{err});
                        }
                    }
                } else |err| {
                    if (err != error.Interrupted) {
                        return error.PollFailed;
                    }
                }
            }
        },
        else => {
            std.log.err("{s} is not a file or a directory", .{path_arg});
            return;
        },
    }
}

fn handleConnection(allocator: std.mem.Allocator, conn_fd: posix.fd_t, base_dir: []const u8, auth_enabled: bool, auth_server_port: u16) !void {
    defer posix.close(conn_fd);
    const conn_file = std.fs.File{ .handle = conn_fd };
    const reader = conn_file.reader();
    const writer = conn_file.writer();
    var buffer: [1024]u8 = undefined;
    const bytes_read = reader.read(&buffer) catch |err| {
        std.log.err("Failed to read request: {}", .{err});
        return;
    };

    var request_buffer = std.ArrayList(u8).init(allocator);
    defer request_buffer.deinit();
    try request_buffer.appendSlice(buffer[0..bytes_read]);

    var lines = std.mem.splitSequence(u8, request_buffer.items, "\r\n");
    const first_line = lines.next() orelse return;
    var parts = std.mem.splitScalar(u8, first_line, ' ');
    const method = parts.next() orelse return; // GET, POST, etc.
    const path = parts.next() orelse "/";

    var headers = std.ArrayList(struct { []const u8, []const u8 }).init(allocator);
    defer headers.deinit();

    var cookie_header: ?[]const u8 = null;

    while (lines.next()) |line| {
        if (line.len == 0) break; // End of headers

        var header_parts = std.mem.splitScalar(u8, line, ':');
        const name = std.mem.trim(u8, header_parts.next() orelse continue, " ");
        const value = std.mem.trim(u8, header_parts.next() orelse continue, " ");

        if (std.mem.eql(u8, name, "Cookie")) {
            cookie_header = value;
        }
        try headers.append(.{ name, value });
    }

    // Extract request body if any (after headers)
    const body_start_index = std.mem.indexOf(u8, request_buffer.items, "\r\n\r\n") orelse request_buffer.items.len;
    const request_body = if (body_start_index + 4 < request_buffer.items.len) request_buffer.items[body_start_index + 4 ..] else null;

    // --- Authentication and Reverse Proxy Logic ---
    if (auth_enabled) {
        const auth_routes = [_][]const u8{"/login", "/signup", "/logout", "/auth/check", "/admin/users"};
        var is_auth_route = false;
        for (auth_routes) |route| {
            if (std.mem.startsWith(u8, path, route)) {
                is_auth_route = true;
                break;
            }
        }

        if (is_auth_route) {
            std.log.info("Proxying auth route: {s}", .{path});
            proxyRequest(allocator, writer, reader, auth_server_port, method, path, headers, request_body) catch |err| {
                std.log.err("Failed to proxy auth request: {}", .{err});
                _ = writer.writeAll("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n500 Internal Server Error") catch {};
            };
            return;
        }

        // For non-auth routes, check authentication
        std.log.info("Checking authentication...", .{});
        var auth_headers = std.ArrayList(struct { []const u8, []const u8 }).init(allocator);
        defer auth_headers.deinit();
        if (cookie_header) |cookie| {
            try auth_headers.append(.{ "Cookie", cookie });
        }

        const auth_check_response_raw = makeHttpRequest(allocator, "127.0.0.1", auth_server_port, "GET", "/auth/check", auth_headers.items, null) catch |err| {
            std.log.err("Failed to make auth check request: {}", .{err});
            _ = writer.writeAll("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n500 Internal Server Error") catch {};
            return;
        };
        defer auth_check_response_raw.deinit();
        std.log.info("Auth check response: {s}", .{auth_check_response_raw.items});

        // Parse auth check response (simplified: just check for 200 OK and 'authenticated: true')
        var auth_check_lines = std.mem.splitSequence(u8, auth_check_response_raw.items, "\r\n");
        const auth_status_line = auth_check_lines.next() orelse { 
            std.log.err("Auth check response empty.", .{});
            _ = writer.writeAll("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n500 Internal Server Error") catch {};
            return;
        };

        if (!std.mem.startsWith(u8, auth_status_line, "HTTP/1.1 200 OK")) {
            // Not authenticated, redirect to login
            std.log.info("Auth check failed, redirecting to /login.", .{});
            _ = writer.writeAll("HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n") catch {};
            return;
        }

        // Further check for 'authenticated: true' in body (simplified for now)
        // In a real scenario, you'd parse JSON. For now, assume 200 OK means authenticated.
        // This is a simplification; proper JSON parsing would be needed here.
        var authenticated = false;
        while (auth_check_lines.next()) |line| {
            if (std.mem.indexOf(u8, line, "\"authenticated\":true") != null) {
                authenticated = true;
                break;
            }
        }

        if (!authenticated) {
            std.log.info("Auth check body indicates not authenticated, redirecting to /login.", .{});
            _ = writer.writeAll("HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n") catch {};
            return;
        }
    }

    // --- Original File Serving Logic (if authenticated or auth not enabled) ---
    var file_path_buf: [512]u8 = undefined;
    const file_path = blk: {
        if (std.mem.eql(u8, path, "/")) {
            break :blk std.fmt.bufPrint(&file_path_buf, "{s}/index.html", .{base_dir}) catch |err| {
                std.log.err("Failed to create file path: {}", .{err});
                return;
            };
        } else {
            break :blk std.fmt.bufPrint(&file_path_buf, "{s}{s}", .{base_dir, path}) catch |err| {
                std.log.err("Failed to create file path: {}", .{err});
                return;
            };
        }
    };

    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        if (err == error.FileNotFound and std.mem.eql(u8, path, "/")) {
            // index.html not found, generate directory listing
            const html = generateDirectoryListingHTML(allocator, base_dir) catch |e| {
                std.log.err("Failed to generate directory listing: {}", .{e});
                const internalError = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nInternal Server Error";
                _ = writer.write(internalError) catch return;
                return;
            };
            defer allocator.free(html);

            _ = writer.print("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{s}", .{html}) catch return;
            return;
        }

        std.log.err("Failed to open file {s}: {}", .{ file_path, err });
        const notFound = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 Not Found";
        _ = writer.write(notFound) catch return;
        return;
    };
    defer file.close();

    const mime = getMimeType(file_path);
    std.log.info("Serving {s} with mime type {s}", .{ file_path, mime });

    _ = writer.print("HTTP/1.1 200 OK\r\nContent-Type: {s}\r\n\r\n", .{mime}) catch return;
    var buf: [4096]u8 = undefined;
    while (file.reader().read(&buf)) |n| {
        _ = writer.write(buf[0..n]) catch return;
    } else |err| {
        if (err != error.EndOfStream) {
            std.log.err("Failed to read file: {}", .{err});
        }
    }
}

fn handleFileConnection(allocator: std.mem.Allocator, conn_fd: posix.fd_t, file_path: []const u8, auth_enabled: bool, auth_server_port: u16) !void {
    defer posix.close(conn_fd);
    const conn_file = std.fs.File{ .handle = conn_fd };
    const reader = conn_file.reader();
    const writer = conn_file.writer();
    var buffer: [1024]u8 = undefined;
    const bytes_read = reader.read(&buffer) catch |err| {
        std.log.err("Failed to read request: {}", .{err});
        return;
    };

    var request_buffer = std.ArrayList(u8).init(allocator);
    defer request_buffer.deinit();
    try request_buffer.appendSlice(buffer[0..bytes_read]);

    var lines = std.mem.splitSequence(u8, request_buffer.items, "\r\n");
    const first_line = lines.next() orelse return;
    var parts = std.mem.splitScalar(u8, first_line, ' ');
    _ = parts.next() orelse return; // method: GET, POST, etc.
    _ = parts.next() orelse "/"; // path

    var headers = std.ArrayList(struct { []const u8, []const u8 }).init(allocator);
    defer headers.deinit();

    var cookie_header: ?[]const u8 = null;

    while (lines.next()) |line| {
        if (line.len == 0) break; // End of headers

        var header_parts = std.mem.splitScalar(u8, line, ':');
        const name = std.mem.trim(u8, header_parts.next() orelse continue, " ");
        const value = std.mem.trim(u8, header_parts.next() orelse continue, " ");

        if (std.mem.eql(u8, name, "Cookie")) {
            cookie_header = value;
        }
        try headers.append(.{ name, value });
    }

    // --- Authentication Check for Protected Resources ---
    if (auth_enabled) {
        var auth_headers = std.ArrayList(struct { []const u8, []const u8 }).init(allocator);
        defer auth_headers.deinit();
        if (cookie_header) |cookie| {
            try auth_headers.append(.{ "Cookie", cookie });
        }

        const auth_check_response_raw = makeHttpRequest(allocator, "127.0.0.1", auth_server_port, "GET", "/auth/check", auth_headers.items, null) catch |err| {
            std.log.err("Failed to make auth check request: {}", .{err});
            _ = writer.writeAll("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n500 Internal Server Error") catch {};
            return;
        };
        defer auth_check_response_raw.deinit();

        // Parse auth check response (simplified: just check for 200 OK and 'authenticated: true')
        var auth_check_lines = std.mem.splitSequence(u8, auth_check_response_raw.items, "\r\n");
        const auth_status_line = auth_check_lines.next() orelse { 
            std.log.err("Auth check response empty.", .{});
            _ = writer.writeAll("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n500 Internal Server Error") catch {};
            return;
        };

        if (!std.mem.startsWith(u8, auth_status_line, "HTTP/1.1 200 OK")) {
            // Not authenticated, redirect to login
            std.log.info("Auth check failed, redirecting to /login.", .{});
            _ = writer.writeAll("HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n") catch {};
            return;
        }

        // Further check for 'authenticated: true' in body (simplified for now)
        // In a real scenario, you'd parse JSON. For now, assume 200 OK means authenticated.
        // This is a simplification; proper JSON parsing would be needed here.
        var authenticated = false;
        while (auth_check_lines.next()) |line| {
            if (std.mem.indexOf(u8, line, "\"authenticated\":true") != null) {
                authenticated = true;
                break;
            }
        }

        if (!authenticated) {
            std.log.info("Auth check body indicates not authenticated, redirecting to /login.", .{});
            _ = writer.writeAll("HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n") catch {};
            return;
        }
    }

    // --- Original File Serving Logic (if authenticated or auth not enabled) ---
    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        std.log.err("Failed to open file {s}: {}", .{ file_path, err });
        const notFound = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n404 Not Found";
        _ = writer.write(notFound) catch return;
        return;
    };
    defer file.close();

    const mime = getMimeType(file_path);
    std.log.info("Serving {s} with mime type {s}", .{ file_path, mime });

    _ = writer.print("HTTP/1.1 200 OK\r\nContent-Type: {s}\r\n\r\n", .{mime}) catch return;
    var buf: [4096]u8 = undefined;
    while (file.reader().read(&buf)) |n| {
        _ = writer.write(buf[0..n]) catch return;
    } else |err| {
        if (err != error.EndOfStream) {
            std.log.err("Failed to read file: {}", .{err});
        }
    }
}

fn getMimeType(path: []const u8) []const u8 {
    if (std.mem.endsWith(u8, path, ".html")) return "text/html";
    if (std.mem.endsWith(u8, path, ".js")) return "application/javascript";
    if (std.mem.endsWith(u8, path, ".css")) return "text/css";
    if (std.mem.endsWith(u8, path, ".json")) return "application/json";
    if (std.mem.endsWith(u8, path, ".png")) return "image/png";
    if (std.mem.endsWith(u8, path, ".jpg")) return "image/jpeg";
    if (std.mem.endsWith(u8, path, ".ico")) return "image/x-icon";
    return "text/plain";
}

fn generateDirectoryListingHTML(allocator: std.mem.Allocator, dir_path: []const u8) ![]const u8 {
    var html = std.ArrayList(u8).init(allocator);
    defer html.deinit();

    try html.writer().print("<!DOCTYPE html>\n", .{});
    try html.writer().print("<html>\n", .{});
    try html.writer().print("<head>\n", .{});
    try html.writer().print("<title>File Explorer - {s}</title>\n", .{dir_path});
    try html.writer().print("<style>\n", .{});
    try html.writer().print("body {{ font-family: sans-serif; }}\n", .{});
    try html.writer().print("table {{ border-collapse: collapse; width: 100%; }}\n", .{});
    try html.writer().print("th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}\n", .{});
    try html.writer().print("tr:hover {{ background-color: #f5f5f5; }}\n", .{});
    try html.writer().print("</style>\n", .{});
    try html.writer().print("</head>\n", .{});
    try html.writer().print("<body>\n", .{});
    try html.writer().print("<h1>File Explorer - {s}</h1>\n", .{dir_path});
    try html.writer().print("<table>\n", .{});
    try html.writer().print("<tr><th>Name</th><th>Type</th><th>Size</th></tr>\n", .{});

    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        const entry_path = try std.fs.path.join(allocator, &.{ dir_path, entry.basename });
        defer allocator.free(entry_path);

        const stat = std.fs.cwd().statFile(entry_path) catch continue;

        const entry_type = if (entry.kind == .directory) "Directory" else "File";
        const size_str = if (entry.kind == .directory) "-" else try std.fmt.allocPrint(allocator, "{}", .{stat.size});
        defer if (entry.kind != .directory) allocator.free(size_str);

        try html.writer().print("<tr><td><a href=\"{s}\">{s}</a></td><td>{s}</td><td>{s}</td></tr>\n", .{
            entry.basename,
            entry.basename,
            entry_type,
            size_str,
        });
    }

    try html.writer().print("</table>\n", .{});
    try html.writer().print("</body>\n", .{});
    try html.writer().print("</html>\n", .{});

    return html.toOwnedSlice();
}