# Minecraft XDP Filter using eBPF – L7 DDoS Protection

This project offers a high-performance XDP-based firewall utilizing eBPF, specifically designed for Minecraft Java Edition servers.  
It effectively mitigates L7 DDoS attacks by filtering malicious packets at the kernel level (before they reach the network stack).  
Currently, the filter is available for IPv4 and supports Minecraft versions 1.8 - 26.3    
The default filtered port is 25565.

💬 Questions, feedback or help needed? Join the Discord: https://discord.gg/JnBJPgV4GW

Documentation: [threat model & scope](docs/threat-model.md) ·
[deployment guide](docs/deployment.md) ·
[benchmark & test plan](docs/benchmark-test-plan.md) ·
[roadmap](docs/roadmap.md).

## Features
- **Protocol Analysis**: Analyzes Minecraft handshakes, status, ping, and login requests.
- **Deep Packet Inspection**: Drops invalid packets, bad VarInts, and protocol violations.
- **Connection Throttle**: Integrated SYN rate limiting (default: 10 SYNs per 3 seconds per IP).
- **Spoof/Sanity Filtering**: Drops reserved and (optionally) private source addresses, malformed headers, impossible TCP flag combinations and fragmented traffic aimed at the protected port.
- **Verified Fast Path**: A connection that completes the inspected handshake is remembered in-kernel; its packets then skip the parser entirely. Per-entry `bpf_timer` cleanup means no userspace process touches the hot path.
- **Allowlist**: Source addresses/CIDRs in an LPM trie bypass all checks; re-read on `SIGHUP` without detaching the program. See the spoofing caveat below.
- **Dry Run**: `dry_run = true` counts and logs every would-be drop while letting all packets through, so rules can be tuned against live traffic first.
- **Observability**: Opt-in per-CPU statistics with a Prometheus endpoint, one counter per drop reason (`minecraft_drop_reason{reason="..."}`) plus connection/traffic totals.
- **Zero-Copy Dropping**: Malicious traffic is dropped at the driver level (XDP_DROP) for maximum performance.

What it does, what it cannot do and the residual risks are documented in
[`docs/threat-model.md`](docs/threat-model.md); read that before relying on it
against a real attack.

## Installation (Linux)

### Download from releases

https://github.com/Outfluencer/Minecraft-XDP-eBPF/releases

You can download the latest build from the Releases Tab  
Then just run the executable in sudo mode or via root

### Prerequisites
- Rust toolchain (stable)
- **System Dependencies**:
  ```bash
  sudo apt update
  sudo apt install -y gcc-multilib wget gnupg software-properties-common git libbpf-dev
  ```
  If software-properties-common was not found remove it from the command.
- **LLVM/Clang Toolchain**:
  The build requires a recent LLVM version (CI uses LLVM 21).
  ```bash
  wget https://apt.llvm.org/llvm.sh
  chmod +x llvm.sh
  sudo ./llvm.sh 21 all
  ```

### Build & Run
1.  **Build the project**:
    ```bash
    ./build.sh
    ```
    The compiled binary will be at `target/release/xdp-loader`.

2.  **Run the tests** (optional):
    ```bash
    cargo test
    ```
    Besides the Rust unit tests this compiles the eBPF parsing code (VarInt
    reader, packet inspectors) natively with ASan/UBSan and runs its C unit
    tests (see `xdp/tests/protocol_test.c`).

3.  **Run the firewall**:
    ```bash
    sudo ./target/release/xdp-loader <network_interface>
    # Example:
    sudo ./target/release/xdp-loader eth0
    ```

    To enable Prometheus metrics export, set `enabled = true` and an `addr`
    in the `[metrics]` section of `config.toml` (see
    [Configuration](#configuration)), then run the loader normally. With
    `addr = "127.0.0.1:1999"` the metrics are available at:
    `http://127.0.0.1:1999/metrics`

4.  **Verifier check** (recommended after changing anything under `xdp/`):
    ```bash
    sudo ./xdp/tests/verifier_load.sh
    ```
    `cargo test` compiles the eBPF program and runs its parser unit tests
    natively, but only this script loads the object into the running kernel,
    where the eBPF verifier re-validates every packet access. A program that
    compiles cleanly can still be rejected at load time, so run this before
    deploying. See [Benchmark & test plan](docs/benchmark-test-plan.md) for how
    to test it under load.

**Note:** This project uses a persistent XDP loader. The userspace program must stay running to keep the filter attached; all map state (throttle windows, verified connections) is managed in-kernel via `bpf_timer`. Stopping the loader will unload the firewall. Requires Linux kernel 5.15 or newer.

## Configuration

Runtime behavior is controlled by a `config.toml` file next to the binary.
On first run it is created automatically with documented defaults; edit it and
restart the loader. Use `--config <path>` to point at a different file.

**`[filter]`** — what traffic is filtered and how strictly:

| Option         | Type   | Default | Description |
|----------------|--------|---------|-------------|
| `start_port`   | int    | 25565   | First port of the inclusive filtered range. |
| `end_port`     | int    | 25565   | Last port of the inclusive filtered range. |
| `hit_count`    | int    | 10      | Max SYNs per source IP per throttle window (`0` disables throttling). |
| `hit_count_reset_secs` | int | 3   | Throttle window length in seconds; each IP's SYN counter resets in-kernel once its window expires. |
| `player_idle_timeout_secs` | int | 60 | Idle timeout for verified connections; an idle entry is removed in-kernel after one to two intervals, requiring a new handshake. |
| `online_names` | bool   | true    | Enforce online-mode usernames (≤16 chars). |
| `dry_run`      | bool   | false   | Count and log the drops the filter would make, but let every packet through. `minecraft_would_drop_reason` is published instead of `minecraft_drop_reason` while active. |
| `drop_reserved_sources` | bool | true | Drop packets sourced from addresses that can never be a real client (0/8, 169.254/16, 224/4 multicast, 240/4). |
| `drop_private_sources` | bool | false | Additionally drop RFC1918, loopback (127/8) and CGNAT (100.64/10) sources. Leave off when same-host proxies, LAN monitoring or other servers legitimately connect to the protected port. |

**`[xdp]`** — how the program attaches and the capacity of its in-kernel tables
(the maps are preallocated, so higher limits cost kernel memory up front):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mode` | string | `"auto"` | XDP attach mode: `"auto"` (native if the NIC supports it, automatic fallback to generic), `"driver"` (force native, fails when unsupported) or `"skb"` (force generic; works everywhere, slower). |
| `max_pending_connections` | int | 16384 | Concurrent connections mid-handshake; the least-recently-used entry is evicted when full. |
| `max_player_connections` | int | 65535 | Concurrent verified player connections; size well above the expected player count. |
| `max_throttled_ips` | int | 65535 | Source IPs tracked by the SYN throttle; new SYNs are dropped while full (fail closed), until expired windows are reclaimed in-kernel. |
| `allowlist_file` | string | (unset) | Text file with source addresses that skip all inspection: one IPv4 address or CIDR per line (`#` comments allowed). Read at start, re-read on `SIGHUP`. **Only for hosts you control** — source addresses can be spoofed unless the upstream filters them (uRPF/BCP38). |
| `max_allowlist_entries` | int | 4096 | Capacity of the allowlist LPM trie; a file with more entries is rejected instead of truncated. |

**`[metrics]`** — statistics collection and the Prometheus endpoint:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | false | Collect packet statistics inside the eBPF program. |
| `addr` | string | (unset) | Address for the Prometheus HTTP endpoint (requires `enabled = true`). |
| `poll_secs` | int | 10 | How often the in-kernel statistics are read and published. |

**`[logging]`** — console and file logging:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | string | `"info"` | Verbosity: `"off"`, `"error"`, `"warn"`, `"info"`, `"debug"` or `"trace"`. Overridden by the `RUST_LOG` env variable. |
| `file_max_mb` | int | 100 | Rotate `xdp-loader.log` once it grows past this size; the 5 newest rotated files are kept. |

The `[filter]` values and map capacities are pushed into the eBPF program at
load time (via `.rodata` globals and map definitions), so changing them only
requires a restart — **not a rebuild**.  

## Operating it

**Tuning with dry run.** Start with `dry_run = true` and watch
`minecraft_would_drop_reason{reason=...}` while real players connect. Reasons
that should stay at zero on a healthy server are listed in
[`docs/deployment.md`](docs/deployment.md) together with what each one means.
Turn dry run off once the counters look right.

**Allowlist.** Sources listed in `allowlist_file` bypass the throttle and the
inspection entirely (useful for proxies, monitoring and other servers you run).
After editing the file, apply it without dropping the program:

```bash
sudo kill -HUP "$(pgrep -x xdp-loader)"
```

A failed reload leaves the previous entries in place and logs the error. Only
allowlist addresses you really control: without upstream source-address
filtering (uRPF/BCP38) an attacker can spoof an allowlisted address.

**Metrics.** With `enabled = true` and an `addr` set:

```
minecraft_verified_connections          verified players since start
minecraft_verified_packets              packets that took the verified fast path
minecraft_syn_packets                   SYNs seen on the filtered ports
minecraft_dropped_packets/bytes         drops and dropped volume
minecraft_incoming_bytes                all bytes seen on the filtered ports
minecraft_ipv6_packets                  IPv6 traffic passed unfiltered (see below)
minecraft_drop_reason{reason="..."}     one counter per drop reason
minecraft_dry_run                      1 while dry run is active
minecraft_allowlist_entries            entries currently in the allowlist
```

## Scope and limitations

Honest summary; details and residual risks in
[`docs/threat-model.md`](docs/threat-model.md):

- **IPv4 TCP only.** IPv6, UDP, fragments and non-TCP traffic pass through
  unfiltered (IPv6 is counted so this is visible). Bedrock/RakNet, Simple Voice
  Chat and other UDP services are **not** protected yet — see
  [`docs/roadmap.md`](docs/roadmap.md).
- **Single host.** XDP filters what reaches *this* machine's NIC. It cannot
  absorb a volumetric flood that saturates the uplink; that needs upstream
  scrubbing, anycast or provider-side filtering. It *can* keep a saturated
  uplink's attack traffic from reaching the Java server, and it does the L7
  work (handshake validation, per-IP limits, verified fast path) that
  network-layer filters cannot.
- **No egress visibility.** Login/auth server spam (a valid login from a bot to
  Mojang) cannot be stopped here; combine with Velocity/Paper
  `connection-throttle` and online-mode auth.
- **Generic (`skb`) mode** sees coalesced GRO segments, so only the first
  segment of a burst is inspected; prefer native mode on the server NIC.
- Stopping the loader detaches the filter (fail open). Run it under systemd.

## Troubleshooting

### Non-root / Permission Errors
Please always check if you are running as root if any error occurred. If you are not, try again with `sudo`.  

⭐ **Don't forget to star the project on GitHub!**  
