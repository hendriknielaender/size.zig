//! Generates `output.html` with a JavaScript treemap for macOS Mach-O symbols.
const std = @import("std");

/// Represents a symbol in the compiled binary.
pub const SymbolInfo = struct {
    name: []const u8,
    size_bytes: usize,
};

/// Naive store for up to 1000 symbols (artificially limited).
var g_symbols: [1000]SymbolInfo = undefined;
var g_symbol_count: usize = 0;

pub fn main() !void {
    // Setup a small arena for argument parsing, etc.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 3) {
        std.log.err("Usage: {s} [input-binary] [output-html]", .{args[0]});
        return;
    }

    const input_path = args[1];
    const output_path = args[2];

    const absolute_path = try std.fs.realpathAlloc(alloc, input_path);
    defer alloc.free(absolute_path);

    var file_handle = try std.fs.openFileAbsolute(absolute_path, .{});
    defer file_handle.close();

    const stat_info = try file_handle.stat();

    // Artificial maximum, just to ensure we don't blow memory in this sample.
    if (stat_info.size > 128 * 1024 * 1024) {
        return error.TooBig;
    }

    // Read the entire file into a fixed buffer.
    const file_storage = try alloc.alloc(u8, 128 * 1024 * 1024);
    defer alloc.free(file_storage);
    var buffer_allocator = std.heap.FixedBufferAllocator.init(file_storage);
    const contents_allocator = buffer_allocator.allocator();

    const file_contents = try contents_allocator.alloc(u8, @intCast(stat_info.size));
    defer contents_allocator.free(file_contents);

    _ = try file_handle.readAll(file_contents);

    // Parse Mach-O. Populate g_symbols.
    try parse_mach_o_symbols(file_contents);

    // Generate a treemap HTML file from the symbol info.
    try write_html_treemap(output_path);
}

/// Naive Mach-O parser:
/// 1) Reads the Mach-O magic.
/// 2) Reads load commands to find LC_SYMTAB if present.
/// 3) Fills up g_symbols with some "name + size" data.
fn parse_mach_o_symbols(file_data: []const u8) !void {
    // 1) Basic size check for 64-bit Mach-O header (32 bytes).
    if (file_data.len < 32) {
        return error.InvalidMachO;
    }

    // 2) Print magic bytes
    const magic = file_data[0..4];
    std.debug.print("magic = {x} {x} {x} {x}\n", .{
        magic[0], magic[1], magic[2], magic[3],
    });

    // MH_MAGIC_64 (0xfeedfacf) or MH_CIGAM_64 (0xcffaedfe).
    // Not strictly required, but let's assert we see those combos:
    // std.debug.assert((magic[0] == 0xfe and magic[1] == 0xed and magic[2] == 0xfa and magic[3] == 0xcf) or (magic[0] == 0xcf and magic[1] == 0xfa and magic[2] == 0xed and magic[3] == 0xfe), "Not a recognized 64-bit Mach-O magic.");

    // 3) Read ncmds, sizeofcmds from Mach-O header at offsets 16 and 20.
    const ncmds_offset = 16;
    const sizeofcmds_offset = 20;

    const ncmds = read_u32_le(file_data[ncmds_offset .. ncmds_offset + 4]) catch {
        return error.InvalidMachO;
    };
    const sizeof_cmds = read_u32_le(file_data[sizeofcmds_offset .. sizeofcmds_offset + 4]) catch {
        return error.InvalidMachO;
    };

    std.debug.print("ncmds={d}, sizeof_cmds={d}, file_data.len={d}\n", .{ ncmds, sizeof_cmds, file_data.len });

    // 4) The load commands start immediately after the 32-byte Mach-O header
    const load_commands_start = 32;
    const load_commands_end = load_commands_start + @as(usize, sizeof_cmds);

    // Validate that we don't exceed file_data
    if (load_commands_end > file_data.len) {
        std.debug.print("load_commands_end={d}, file_data.len={d}\n", .{ load_commands_end, file_data.len });
        return error.InvalidMachO;
    }

    var offset: usize = load_commands_start;

    // Single pass through ncmds
    var cmd_i: u32 = 0;
    while (cmd_i < ncmds) : (cmd_i += 1) {
        std.debug.print(
            "\ncmd_i={d}, offset={d} (file_data.len={d})\n",
            .{ cmd_i, offset, file_data.len },
        );

        // Validate we have at least space for the command's first 8 bytes (cmd, cmdsize).
        if (offset + 8 > file_data.len) {
            std.debug.print("Not enough bytes for cmd + cmdsize\n", .{});
            return error.InvalidMachO;
        }

        const cmd = read_u32_le(file_data[offset .. offset + 4]) catch {
            std.debug.print("Could not read cmd at offset={d}\n", .{offset});
            return error.InvalidMachO;
        };
        const cmdsize = read_u32_le(file_data[offset + 4 .. offset + 8]) catch {
            std.debug.print("Could not read cmdsize at offset={d}\n", .{offset + 4});
            return error.InvalidMachO;
        };

        std.debug.print("  cmd={x}, cmdsize={d}\n", .{ cmd, cmdsize });

        // Validate cmdsize
        if (cmdsize < 8) {
            std.debug.print("cmdsize < 8 is invalid.\n", .{});
            return error.InvalidMachO;
        }

        // Make sure offset + cmdsize won't exceed file_data
        const cmd_end = offset + @as(usize, cmdsize);
        if (cmd_end > file_data.len) {
            std.debug.print("cmd_end={d} out of range\n", .{cmd_end});
            return error.InvalidMachO;
        }

        // Check if LC_SYMTAB (value = 0x2)
        if (cmd == 0x2) {
            std.debug.print("  Found LC_SYMTAB at offset={d}\n", .{offset});

            // The symtab_command struct is 24 bytes after cmd + cmdsize fields:
            //   uint32_t symoff, uint32_t nsyms, uint32_t stroff, uint32_t strsize
            if (offset + 24 > file_data.len) {
                std.debug.print("Not enough bytes for symtab_command.\n", .{});
                return error.InvalidMachO;
            }
            const symoff = read_u32_le(file_data[offset + 8 .. offset + 12]) catch {
                return error.InvalidMachO;
            };
            const nsyms = read_u32_le(file_data[offset + 12 .. offset + 16]) catch {
                return error.InvalidMachO;
            };
            const stroff = read_u32_le(file_data[offset + 16 .. offset + 20]) catch {
                return error.InvalidMachO;
            };
            const strsize = read_u32_le(file_data[offset + 20 .. offset + 24]) catch {
                return error.InvalidMachO;
            };

            std.debug.print(
                "  symoff={d}, nsyms={d}, stroff={d}, strsize={d}, file_data.len={d}\n",
                .{ symoff, nsyms, stroff, strsize, file_data.len },
            );

            // Check bounds for symbol table + string table
            if (@as(usize, symoff) + (@as(usize, nsyms) * 16) > file_data.len) {
                std.debug.print("Symbol table extends beyond file size.\n", .{});
                return error.InvalidMachO;
            }
            if (@as(usize, stroff) + @as(usize, strsize) > file_data.len) {
                std.debug.print("String table extends beyond file size.\n", .{});
                return error.InvalidMachO;
            }

            // Now parse each nlist_64 (16 bytes).
            g_symbol_count = 0;

            var sym_idx: u32 = 0;
            while (sym_idx < nsyms and g_symbol_count < g_symbols.len) : (sym_idx += 1) {
                const entry_offset = @as(usize, symoff) + (@as(usize, sym_idx) * 16);
                if (entry_offset + 16 > file_data.len) {
                    std.debug.print("nlist_64 extends beyond file size.\n", .{});
                    return error.InvalidMachO;
                }
                std.debug.print("    sym_idx={d}, entry_offset={d}\n", .{ sym_idx, entry_offset });

                // n_strx (4 bytes)
                const n_strx = read_u32_le(file_data[entry_offset .. entry_offset + 4]) catch {
                    std.debug.print("Could not read n_strx.\n", .{});
                    return error.InvalidMachO;
                };
                // n_value (8 bytes) starts at entry_offset + 8
                const n_value = read_u64_le(file_data[entry_offset + 8 .. entry_offset + 16]) catch {
                    std.debug.print("Could not read n_value.\n", .{});
                    return error.InvalidMachO;
                };
                std.debug.print("      n_strx={d}, n_value={d}\n", .{ n_strx, n_value });

                // The name is at (stroff + n_strx) in the string table.
                const name_offset = @as(usize, stroff) + @as(usize, n_strx);
                if (name_offset >= file_data.len) {
                    std.debug.print("name_offset={d} out of range\n", .{name_offset});
                    return error.InvalidMachO;
                }

                const sym_name = extract_c_string(file_data, name_offset, 256);
                std.debug.print("      sym_name='{s}'\n", .{sym_name});

                // In real code, n_value is an address, not necessarily a "size".
                // But for demonstration, we store it as size_bytes.
                g_symbols[g_symbol_count] = .{
                    .name = sym_name,
                    .size_bytes = @intCast(n_value),
                };
                g_symbol_count += 1;
            }
        }

        // Move to next command
        offset = cmd_end;
    }
}

/// Writes out an HTML file with an inline JSON array of symbols for a rudimentary treemap.
fn write_html_treemap_into_buffer() ![]const u8 {
    var scratch_buffer: [2048]u8 = undefined;

    // Wrap scratch_buffer in a "fixed buffer" stream for writing.
    var out_stream = std.io.fixedBufferStream(&scratch_buffer);

    // Create a JSON writer on top of that stream.
    var jstream = std.json.writeStream(out_stream.writer(), .{
        // optional JSON formatting choices:
        .whitespace = .minified,
    });

    // Start writing JSON tokens:
    try jstream.beginArray();

    // For example, write a small JSON object:
    try jstream.beginObject();
    try jstream.objectField("symbol");
    try jstream.write("main");
    try jstream.objectField("size");
    try jstream.write(1024);
    try jstream.endObject();

    // Possibly more objects here...
    try jstream.endArray();

    // Now we get the sub-slice of bytes actually written.
    const json_slice = out_stream.getWritten();

    // Return this sub-slice (lives until function returns).
    return json_slice;
}

fn write_html_treemap(output_path: []const u8) !void {
    var out_file = try std.fs.cwd().createFile(output_path, .{});

    defer out_file.close();

    // 1) Get JSON as a slice in memory.
    const json_slice = try write_html_treemap_into_buffer();

    // 2) Build an HTML template that includes the JSON.
    const html_template =
        \\<!DOCTYPE html>
        \\<html>
        \\<head><title>Zig Treemap</title></head>
        \\<body>
        \\  <h1>Treemap</h1>
        \\  <div id="chart"></div>
        \\  <script>
        \\    const data = REPLACE_JSON;
        \\    console.log(data);
        \\    // Insert treemap logic here...
        \\  </script>
        \\</body>
        \\</html>
    ;

    // 3) Insert the JSON into the HTML.
    const replaced_html = replace_placeholder(html_template, "REPLACE_JSON", json_slice);

    // 4) Write HTML to file.
    try out_file.writeAll(replaced_html);
}

fn replace_placeholder(
    html: []const u8,
    placeholder: []const u8,
    replacement: []const u8,
) []const u8 {
    // naive single-pass placeholder replacement
    var result_buf: [4096]u8 = undefined;
    var ri: usize = 0;
    var i: usize = 0;
    while (i < html.len) : (i += 1) {
        if (match_placeholder(html, i, placeholder)) {
            var r: usize = 0;
            while (r < replacement.len) : (r += 1) {
                result_buf[ri] = replacement[r];
                ri += 1;
            }
            i += placeholder.len - 1;
        } else {
            result_buf[ri] = html[i];
            ri += 1;
        }
    }
    return result_buf[0..ri];
}

fn match_placeholder(html: []const u8, start: usize, placeholder: []const u8) bool {
    if (start + placeholder.len > html.len) return false;
    var k: usize = 0;
    while (k < placeholder.len) : (k += 1) {
        if (html[start + k] != placeholder[k]) return false;
    }
    return true;
}

/// Reads a 32-bit little-endian integer from `data`.
fn read_u32_le(data: []const u8) !u32 {
    if (data.len < 4) return error.OutOfBounds;

    // This casts the first 4 bytes of `data` to a pointer `*const [4]u8`.
    // We have already checked `data.len >= 4`, so it’s safe.
    const arr_4_ptr: *const [4]u8 = @ptrCast(data[0..4].ptr);

    return std.mem.readInt(u32, arr_4_ptr, .little);
}

fn read_u64_le(data: []const u8) !u64 {
    if (data.len < 8) return error.OutOfBounds;

    const arr_8_ptr: *const [8]u8 = @ptrCast(data[0..8].ptr);

    return std.mem.readInt(u64, arr_8_ptr, .little);
}

/// Naive function to extract up to `max_len` bytes as a C string (null-terminated).
fn extract_c_string(data: []const u8, start: usize, max_len: usize) []const u8 {
    var end: usize = start;
    while (end < data.len and end < start + max_len) {
        if (data[end] == 0) {
            break;
        }
        end += 1;
    }
    return data[start..end];
}
