use std::path::PathBuf;
use std::process::Command;

/// Compiles the eBPF program to `xdp/minecraft_filter.o`, which `loader/ebpf.rs`
/// embeds into the loader binary at compile time.
fn main() {
    // explicit file list on purpose: watching the whole xdp/ directory would
    // also watch the generated .o and recompile on every build
    for source in [
        "xdp/minecraft_filter.c",
        "xdp/common.h",
        "xdp/config.h",
        "xdp/protocol.h",
        "xdp/stats.h",
        "xdp/varint.h",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }

    let mut command = Command::new(std::env::var("CLANG").unwrap_or_else(|_| "clang".into()));
    command.args([
        "-Wall",
        "-Wextra",
        "-Wno-language-extension-token",
        "-O2",
        "-g",
        "-target",
        "bpf",
        "-mcpu=v3",
    ]);
    for path in multiarch_include_paths() {
        command.arg("-idirafter").arg(path);
    }
    let output = command
        .args(["-c", "minecraft_filter.c", "-o", "minecraft_filter.o"])
        .current_dir("xdp")
        .output()
        .expect("failed to run clang, is LLVM/clang installed?");

    if !output.status.success() {
        panic!(
            "clang compilation failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Directories that must be added to the include search path for the BPF
/// target on multiarch distributions (Debian/Ubuntu): the kernel uapi headers
/// include `<asm/types.h>`, which lives in e.g. `/usr/include/x86_64-linux-gnu`
/// - a directory clang only adds for native targets, not for `-target bpf`.
///
/// The directory is added with `-idirafter` so it can never shadow the
/// architecture independent headers (only fills in what is missing).
fn multiarch_include_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for root in ["/usr/include", "/usr/local/include"] {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with("-linux-gnu") && path.is_dir() {
                paths.push(path);
            }
        }
    }
    // keep the output deterministic
    paths.sort();
    if paths.is_empty() {
        eprintln!("note: no *-linux-gnu include directory found (non-multiarch system?)");
    }
    paths
}
