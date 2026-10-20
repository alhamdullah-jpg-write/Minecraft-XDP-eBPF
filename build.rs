use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Compiles the eBPF program to `xdp/minecraft_filter.o`, which `loader/ebpf.rs`
/// embeds into the loader binary at compile time, and derives the drop-reason
/// metric labels from `xdp/stats.h`.
fn main() {
    // changing either of these must retrigger the build
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=XDP_BPF_INCLUDE");

    // explicit file list on purpose: watching the whole xdp/ directory would
    // also watch the generated .o and recompile on every build
    for source in [
        "xdp/minecraft_filter.c",
        "xdp/blocklist.h",
        "xdp/common.h",
        "xdp/config.h",
        "xdp/egress.h",
        "xdp/flow.h",
        "xdp/limits.h",
        "xdp/maps.h",
        "xdp/protocol.h",
        "xdp/rate.h",
        "xdp/rules.h",
        "xdp/stats.h",
        "xdp/talkers.h",
        "xdp/udp.h",
        "xdp/varint.h",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }

    generate_drop_reason_names();

    // the bpf helpers come from libbpf's development headers, which are not
    // part of the kernel uapi and therefore not guaranteed to be installed:
    // fail with the install command before clang fails with a bare
    // "bpf_helpers.h file not found"
    let Some(extra_includes) = bpf_include_dirs() else {
        panic!("{}", missing_bpf_headers_hint());
    };

    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let mut command = Command::new(&clang);
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
    // only added when the headers are *not* in clang's default search path,
    // and as system headers so -Wall never reports warnings from libbpf itself
    for path in &extra_includes {
        command.arg("-isystem").arg(path);
    }
    let output = match command
        .args(["-c", "minecraft_filter.c", "-o", "minecraft_filter.o"])
        .current_dir("xdp")
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!(
            "failed to run '{clang}': {error}\n\
             install LLVM/clang (at least version 14; -mcpu=v3 needs it) or set \
             the CLANG environment variable to the binary to use"
        ),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let hint = if stderr.contains("bpf_helpers.h")
            || stderr.contains("bpf_helper_defs.h")
            || stderr.contains("'bpf/")
        {
            format!("\n{}", missing_bpf_headers_hint())
        } else {
            String::new()
        };
        panic!(
            "clang compilation failed:\nstdout: {}\nstderr: {stderr}{hint}",
            String::from_utf8_lossy(&output.stdout),
        );
    }
}

/// Include roots that provide libbpf's `bpf/bpf_helpers.h`, as `-isystem`
/// arguments. `None` means the headers were not found anywhere: the caller
/// must fail with an install hint, because clang would fail with a bare
/// "file not found".
///
/// `/usr/include` and `/usr/local/include` are already searched by clang, so
/// they are checked (to decide whether the build can work at all) but not
/// returned - adding them as `-isystem` would only change the warning
/// classification of unrelated headers. Anything listed in `XDP_BPF_INCLUDE`
/// (colon separated) is returned, so a from-source or relocated libbpf can be
/// used without touching the system.
fn bpf_include_dirs() -> Option<Vec<PathBuf>> {
    let mut found_in_default_path = false;
    let mut extra = Vec::new();
    if let Some(value) = std::env::var_os("XDP_BPF_INCLUDE") {
        for part in std::env::split_paths(&value) {
            if part.join("bpf/bpf_helpers.h").is_file() {
                extra.push(part);
            } else {
                eprintln!(
                    "note: XDP_BPF_INCLUDE entry '{}' has no bpf/bpf_helpers.h",
                    part.display()
                );
            }
        }
    }
    for root in ["/usr/include", "/usr/local/include"] {
        if Path::new(root).join("bpf/bpf_helpers.h").is_file() {
            found_in_default_path = true;
        }
    }
    if found_in_default_path || !extra.is_empty() {
        Some(extra)
    } else {
        None
    }
}

/// The message shown when the libbpf headers are missing: one install command
/// per distribution plus the escape hatches.
fn missing_bpf_headers_hint() -> String {
    "bpf/bpf_helpers.h was not found, so the eBPF object can not be compiled.\n\
     \n\
     It ships in libbpf's development headers, not in the kernel headers:\n\
       Ubuntu/Debian:  apt-get install -y libbpf-dev\n\
       Fedora/RHEL:    dnf install -y libbpf-devel\n\
       Arch:           pacman -S libbpf\n\
       openSUSE:       zypper install libbpf-devel\n\
       from source:    https://github.com/libbpf/libbpf (install to /usr/local)\n\
     \n\
     If they are installed in a non-standard prefix, add that prefix:\n\
       XDP_BPF_INCLUDE=/opt/libbpf/include cargo build --release\n\
     \n\
     You do not need any of this to *run* the filter: the release archives and\n\
     the prebuilt/ directory of the source zip ship a statically linked loader\n\
     with the compiled object already embedded."
        .to_string()
}


/// Generates `drop_reasons.rs` in OUT_DIR from the `enum drop_reason` in
/// `xdp/stats.h`: the Prometheus label of every reason, indexed by its enum
/// value (which is also the index into `struct statistics.reason[]`).
///
/// The C enum is the single source of truth for names and values; keeping the
/// Rust side generated means the metric labels can not drift apart from the
/// counters the kernel actually increments. The human-readable description of
/// every reason lives in docs/drop-reasons.md.
fn generate_drop_reason_names() {
    let text = std::fs::read_to_string("xdp/stats.h").expect("failed to read xdp/stats.h");
    let mut in_enum = false;
    let mut entries: Vec<(u32, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("enum drop_reason") {
            in_enum = true;
            continue;
        }
        if !in_enum {
            continue;
        }
        if line.starts_with('}') {
            break;
        }
        if !line.starts_with("DROP_") {
            continue;
        }
        // DROP_NAME = 12, // comment
        let (name, rest) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("enum entry without a value: {line}"));
        let value: u32 = rest
            .trim_start()
            .split(',')
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("enum entry with a non-numeric value: {line}"));
        let label = name.trim().trim_start_matches("DROP_").to_ascii_lowercase();
        entries.push((value, label));
    }
    assert!(
        !entries.is_empty(),
        "parsed no reasons from enum drop_reason in xdp/stats.h"
    );
    entries.sort_by_key(|(value, _)| *value);
    for (index, (value, label)) in entries.iter().enumerate() {
        assert_eq!(
            *value as usize, index,
            "enum drop_reason must be contiguous starting at 0 \
             (value {value} of '{label}' is at index {index}); gaps would \
             silently mislabel every counter behind them"
        );
    }

    let mut generated = String::from(
        "// @generated by build.rs from `enum drop_reason` in xdp/stats.h.\n\
         // Do not edit; edit the C enum and rebuild.\n\
         /// Metric label of every drop reason, indexed by enum value.\n",
    );
    let _ = writeln!(
        generated,
        "pub const DROP_REASON_NAMES: [&str; {}] = [",
        entries.len()
    );
    for (_, label) in &entries {
        let _ = writeln!(generated, "    \"{label}\",");
    }
    generated.push_str("];\n");

    let out_dir = std::env::var_os("OUT_DIR").expect("OUT_DIR not set");
    let target = PathBuf::from(out_dir).join("drop_reasons.rs");
    std::fs::write(&target, generated).expect("failed to write drop_reasons.rs");
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
