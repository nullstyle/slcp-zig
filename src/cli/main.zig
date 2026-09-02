//! `slcp` — process entry for the CLI (plan R5). All behavior lives in
//! `cli.zig`'s `run` / `runAndFlush`; this file only collects argv, wraps
//! stdout/stderr in buffered writers, and turns the returned code into the
//! exit status.

const std = @import("std");
const cli = @import("cli.zig");

pub fn main(init: std.process.Init) !void {
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next(); // argv[0]
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(init.gpa);
    while (it.next()) |arg| try args.append(init.gpa, arg);

    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    var err_buf: [4096]u8 = undefined;
    var err_out = std.Io.File.stderr().writerStreaming(init.io, &err_buf);

    std.process.exit(cli.runAndFlush(init.gpa, init.io, args.items, &out.interface, &err_out.interface));
}

test {
    _ = cli;
}
