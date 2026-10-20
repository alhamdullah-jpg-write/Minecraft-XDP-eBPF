#!/usr/bin/env bash
#
# Loads the compiled eBPF object into the running kernel with generic XDP.
#
# `cargo build` only proves that clang accepted the C sources: the verifier
# only runs at load time. Historically every non-trivial change to the packet
# parsing bounds checks broke the load while compiling fine, so this script is
# the real gate for verifier regressions (bounds checks, variable-length
# skips, per-CPU maps, bpf_timer usage, ...).
#
# Usage:
#   sudo xdp/tests/verifier_load.sh
#
# Exit codes:
#   0  the kernel verifier accepted the program
#   1  clang could not compile the program
#   2  the kernel verifier rejected the program (log is printed)
#   3  environment cannot run the check (not root, no clang/ip, no XDP)
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
obj="$tmpdir/minecraft_filter.o"
log="$tmpdir/verifier.log"

cleanup() {
    ip link set dev lo xdpgeneric off 2>/dev/null || true
    rm -rf "$tmpdir"
}
trap cleanup EXIT

if [ "$(id -u)" != 0 ]; then
    echo "SKIP: must run as root (needs CAP_NET_ADMIN + CAP_BPF)"
    exit 3
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "SKIP: iproute2 (ip) not found"
    exit 3
fi
if ! command -v clang >/dev/null 2>&1; then
    echo "SKIP: clang not found"
    exit 3
fi

# Same flags as build.rs (keep in sync); the *-linux-gnu include directory is
# needed for <asm/types.h> because the BPF target has no default sysroot.
extra=()
for dir in /usr/include/*-linux-gnu; do
    [ -d "$dir" ] && extra+=("-idirafter" "$dir")
done
# relocated libbpf headers, exactly like build.rs honours them
if [ -n "${XDP_BPF_INCLUDE:-}" ]; then
    while IFS= read -r dir; do
        [ -d "$dir" ] && extra+=("-isystem" "$dir")
    done < <(printf '%s' "$XDP_BPF_INCLUDE" | tr ':' '\n')
fi

if ! clang -Wall -Wextra -Wno-language-extension-token -O2 -g -target bpf -mcpu=v3 \
    "${extra[@]}" -c "$root/xdp/minecraft_filter.c" -o "$obj"; then
    echo "FAIL: clang could not compile the eBPF program"
    exit 1
fi

# generic (skb mode) XDP works on any interface, including lo, and runs the
# same verifier as native mode
if ! ip link set dev lo xdpgeneric obj "$obj" sec xdp 2>"$log"; then
    echo "FAIL: the kernel verifier rejected the program:"
    sed 's/^/  /' "$log"
    exit 2
fi

ip link set dev lo xdpgeneric off
echo "OK: the kernel verifier accepted the program (generic XDP on lo)"
