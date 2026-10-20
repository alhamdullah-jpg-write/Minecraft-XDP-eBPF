#!/usr/bin/env bash
#
# autobuild.sh - one command from a fresh download to a built filter.
#
# What it does, in order:
#   1. checks for everything the build needs: clang (>= 14), the libbpf
#      development headers (bpf/bpf_helpers.h) and the kernel uapi headers
#      (linux/bpf.h) - the three things a fresh server usually misses
#   2. installs whatever is missing with your distribution's package manager
#      and installs Rust with rustup if there is no cargo yet
#   3. builds the release loader (target/release/xdp-loader)
#   4. loads the filter into the running kernel once (the verifier check) and
#      prints the exact command to attach it for real
#
# Re-running it is safe: everything already present is skipped, and the build
# itself is incremental.
#
# Environment:
#   NOINSTALL=1           never install packages, only report what is missing
#   AUTOBUILD_VERBOSE=1   stream the compiler output instead of a log file
#   XDP_BPF_INCLUDE=...   extra include prefix that holds bpf/bpf_helpers.h
#
# Nothing here touches your firewall: attaching the filter is always an
# explicit step that this script only *prints* (plus the harmless verifier
# load on the loopback interface).
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
cd "$ROOT"
LOG="$ROOT/autobuild.log"

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    BOLD=; GREEN=; YELLOW=; RED=; RESET=
fi
say()  { printf '%s\n' "${BOLD}==>${RESET} $*"; }
ok()   { printf '%s\n' "${GREEN}  ok${RESET} $*"; }
warn() { printf '%s\n' "${YELLOW}warn${RESET} $*" >&2; }
die()  { printf '%s\n' "${RED}fail${RESET} $*" >&2; exit 1; }

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "${BASH_SOURCE[0]}"
    exit 0
fi

echo "${BOLD}Minecraft XDP filter - automatic build${RESET}"

# --------------------------------------------------------------- privileges
if [[ "$(id -u)" == 0 ]]; then
    SUDO=()
    ok "running as root"
elif command -v sudo >/dev/null 2>&1; then
    SUDO=(sudo)
    ok "not root: using sudo where needed"
else
    SUDO=()
    warn "not root and no sudo: this script can not install packages"
fi
can_root() { [[ "$(id -u)" == 0 || "${#SUDO[@]}" -gt 0 ]]; }

# --------------------------------------------------------- package manager
PM=""
for tool in apt-get dnf pacman zypper; do
    if command -v "$tool" >/dev/null 2>&1; then PM="$tool"; break; fi
done
case "$PM" in
    apt-get) PKG_CLANG=clang;      PKG_BPF=libbpf-dev;    PKG_KHDR=linux-libc-dev; PKG_NET=iproute2 ;;
    dnf)     PKG_CLANG=clang;      PKG_BPF=libbpf-devel;  PKG_KHDR=kernel-headers; PKG_NET=iproute ;;
    pacman)  PKG_CLANG=clang;      PKG_BPF=libbpf;        PKG_KHDR=linux-api-headers; PKG_NET=iproute2 ;;
    zypper)  PKG_CLANG=clang;      PKG_BPF=libbpf-devel;  PKG_KHDR=linux-glibc-devel; PKG_NET=iproute2 ;;
    *)       PKG_CLANG=clang;      PKG_BPF=libbpf-devel;  PKG_KHDR=kernel-headers; PKG_NET=iproute2 ;;
esac

install_pkg() {
    local what="$1"; shift
    if [[ "${NOINSTALL:-0}" == 1 ]]; then
        die "$what is missing and NOINSTALL=1 forbids installing it. As root, run: $*"
    fi
    can_root || die "$what is missing and there is no way to install it here. As root, run: $*"
    say "installing $what: $*"
    local rc=0
    case "$PM" in
        apt-get) "${SUDO[@]}" apt-get update -qq >>"$LOG" 2>&1
                 "${SUDO[@]}" apt-get install -y "$@" >>"$LOG" 2>&1 ;;
        dnf)     "${SUDO[@]}" dnf install -y "$@" >>"$LOG" 2>&1 ;;
        pacman)  "${SUDO[@]}" pacman -Sy --noconfirm --needed "$@" >>"$LOG" 2>&1 ;;
        zypper)  "${SUDO[@]}" zypper --non-interactive install "$@" >>"$LOG" 2>&1 ;;
        *)       die "unknown package manager: install manually and re-run: $*" ;;
    esac || rc=$?
    if (( rc != 0 )); then
        warn "installing $what failed; last lines of $LOG:"
        tail -15 "$LOG" | sed 's/^/    /'
        die "install it manually and re-run: $*"
    fi
    ok "installed $what"
}

# ------------------------------------------------------------ requirements
have_bpf_headers() {
    local prefix
    if [[ -n "${XDP_BPF_INCLUDE:-}" ]]; then
        while IFS= read -r prefix; do
            [[ -f "$prefix/bpf/bpf_helpers.h" ]] && return 0
        done < <(printf '%s' "$XDP_BPF_INCLUDE" | tr ':' '\n')
    fi
    [[ -f /usr/include/bpf/bpf_helpers.h || -f /usr/local/include/bpf/bpf_helpers.h ]]
}

have_kernel_headers() {
    [[ -f /usr/include/linux/bpf.h ]] || return 1
    [[ -f /usr/include/asm/types.h ]] && return 0
    local glob=(/usr/include/*-linux-gnu/asm/types.h)
    [[ -e "${glob[0]}" ]]
}

# clang: present and new enough for -mcpu=v3 (LLVM 14)
clang_ok() {
    command -v clang >/dev/null 2>&1 || return 1
    local v
    v="$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    [[ -n "$v" ]] || return 0
    [[ "${v%%.*}" -ge 14 ]]
}

say "checking build requirements"

clang_ok || install_pkg "a recent clang (the eBPF compiler)" "$PKG_CLANG"
ok "clang: $(clang --version | head -1)"

have_bpf_headers || install_pkg "the libbpf development headers (bpf/bpf_helpers.h)" "$PKG_BPF"
ok "libbpf headers found"

have_kernel_headers || install_pkg "the kernel uapi headers (linux/bpf.h)" "$PKG_KHDR"
ok "kernel headers found"

command -v ip >/dev/null 2>&1 || install_pkg "iproute2 (the 'ip' tool)" "$PKG_NET"
ok "network tools found"

# Rust: use the system cargo when there is one, otherwise rustup
if ! command -v cargo >/dev/null 2>&1; then
    if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env" 2>/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
    fi
fi
if ! command -v cargo >/dev/null 2>&1; then
    command -v curl >/dev/null 2>&1 || install_pkg "curl (needed to install Rust)" curl
    if [[ "${NOINSTALL:-0}" == 1 ]]; then
        die "Rust is missing and NOINSTALL=1 forbids installing it. Install: https://rustup.rs"
    fi
    say "installing Rust (rustup, minimal profile - this takes a minute)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env" 2>/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
fi
command -v cargo >/dev/null 2>&1 || die "cargo is still not on PATH; open a new shell and re-run"
ok "rust: $(cargo --version)"

# ------------------------------------------------------------------- build
say "building (the first run compiles all dependencies and can take a few minutes)"
if [[ "${AUTOBUILD_VERBOSE:-0}" == 1 ]]; then
    cargo build --release
else
    say "compiler output goes to $LOG"
    if ! cargo build --release >"$LOG" 2>&1; then
        echo
        warn "the build failed. Last lines of $LOG:"
        tail -25 "$LOG" | sed 's/^/    /'
        echo
        die "full log: $LOG  (re-run with AUTOBUILD_VERBOSE=1 to watch it live)"
    fi
fi

BIN="$ROOT/target/release/xdp-loader"
[[ -x "$BIN" ]] || die "the build finished but $BIN is missing; please report this with $LOG"
ok "built $( "$BIN" --version )  ->  $BIN"

# ------------------------------------------------------- verifier self-check
if [[ -x "$ROOT/xdp/tests/verifier_load.sh" ]]; then
    if can_root; then
        say "checking that your kernel accepts the filter (loads it on lo for one second)"
        if "${SUDO[@]}" "$ROOT/xdp/tests/verifier_load.sh" >/dev/null 2>&1; then
            ok "your kernel accepted the filter"
        else
            warn "the verifier check failed - run it yourself to see why:"
            warn "  sudo $ROOT/xdp/tests/verifier_load.sh"
        fi
    else
        warn "verifier check skipped (needs root): sudo $ROOT/xdp/tests/verifier_load.sh"
    fi
fi

# ------------------------------------------------------------- next steps
if [[ -x "$ROOT/prebuilt/xdp-loader" ]]; then
    echo
    say "note: this download already contains a prebuilt static loader."
    say "      building was only needed if you want to change the code; to just run it:"
    say "      sudo $ROOT/prebuilt/xdp-loader <interface>"
fi

echo
echo "${BOLD}Done. What now?${RESET}"
if command -v ip >/dev/null 2>&1; then
    IFACES="$(ip -br link show 2>/dev/null | awk '$1 != "lo" {print $1}' | head -5 | paste -sd' ' - || true)"
fi
echo "  1. attach the filter to your public network interface:"
echo "       sudo $BIN ${IFACES:-<interface>}"
echo "     (your interfaces: ${IFACES:-none detected})"
echo "  2. the first run writes a commented config.toml into the current directory;"
echo "     leave dry_run = true until real players connect cleanly"
echo "  3. optional: [metrics] enabled = true + addr, then:"
echo "       curl -s http://127.0.0.1:1999/metrics"
echo "  4. documented setup, verification checklist and troubleshooting:"
echo "       $ROOT/docs/deployment.md"
echo "       $ROOT/docs/drop-reasons.md   (what each drop counter means)"
