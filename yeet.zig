const std = @import("std");
const posix = std.posix;

var interrupted: std.atomic.Value(u8) = std.atomic.Value(u8).init(0); // Assuming Value is the generic atomic struct

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

    if (args.len != 3) {
        std.io.getStdErr().writer().print("Usage: {s} [folder|file] [port]\n", .{args[0]}) catch return;
        return;
    }

    const path_arg = args[1];
    const port_arg = args[2];

    const port = std.fmt.parseInt(u16, port_arg, 10) catch |err| {
        std.log.err("Invalid port number: {s} ({})", .{ port_arg, err });
        return;
    };

    const action = posix.Sigaction{
        .handler = .{
            .handler = signalHandler,
        },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &action, null);

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
                        if (std.Thread.spawn(.{}, handleConnection, .{ conn_fd, path_arg })) |_| {} else |err| {
                            std.log.err("Spawn failed: {}", .{err});
                        }
                    }
                } else |err| {
                    if (err != error.Interrupted) {
                        return error.PollFailed;
                    }
                }
            }
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
                        if (std.Thread.spawn(.{}, handleFileConnection, .{ conn_fd, path_arg })) |_| {} else |err| {
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

fn handleConnection(conn_fd: posix.fd_t, base_dir: []const u8) void {
    defer posix.close(conn_fd);
    const conn_file = std.fs.File{ .handle = conn_fd };
    const reader = conn_file.reader();
    const writer = conn_file.writer();
    var buffer: [1024]u8 = undefined;

    _ = reader.read(&buffer) catch return;

    // Parse request
    var lines = std.mem.splitSequence(u8, buffer[0..], "\r\n");
    const first_line = lines.next() orelse return;
    var parts = std.mem.splitScalar(u8, first_line, ' ');
    _ = parts.next(); // GET
    const path = parts.next() orelse "/";

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

fn handleFileConnection(conn_fd: posix.fd_t, file_path: []const u8) void {
    defer posix.close(conn_fd);
    const conn_file = std.fs.File{ .handle = conn_fd };
    const reader = conn_file.reader();
    const writer = conn_file.writer();
    var buffer: [1024]u8 = undefined;

    _ = reader.read(&buffer) catch return;

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