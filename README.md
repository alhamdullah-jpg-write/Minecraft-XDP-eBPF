# Minecraft XDP Filter using eBPF – L7 DDoS Protection

This project offers a high-performance XDP-based firewall utilizing eBPF, specifically designed for Minecraft servers
(Java, Bedrock and the Simple Voice Chat plugin) and the UDP/TCP ports they use.  
It effectively mitigates L7 DDoS attacks by filtering malicious packets at the kernel level (before they reach the network stack).  
It runs on IPv4 and IPv6, on native XDP, generic (`skb`) or offloaded XDP, and the parser validates *framing* rather than
hardcoded protocol versions, so releases, snapshots and forks that keep the vanilla framing work unchanged.
The default filtered port is 25565 (Java); Bedrock (`19132/udp`) and voice (`24454/udp`) are opt-in.

💬 Questions, feedback or help needed? Join the Discord: https://discord.gg/JnBJPgV4GW

Documentation: [threat model & scope](docs/threat-model.md) ·
[deployment guide](docs/deployment.md) ·
[drop reasons & counters](docs/drop-reasons.md) ·
[benchmark & test plan](docs/benchmark-test-plan.md) ·
[roadmap](docs/roadmap.md).

## Features
- **Minecraft protocol inspection**: parses handshakes, status, ping and login requests of the Java protocol
  (framing, VarInts, bounds) plus the Bedrock/RakNet offline handshake and Simple Voice Chat packet shape.
- **Stateful, not just stateless**: connections are tracked in-kernel, and the loader's `tc egress` hook records what the
  host itself sent so inbound packets can be matched against real flows (stateful UDP pinhole, optional default-deny
  ingress for every port that is not explicitly opened).
- **Rate limiting with cheap filters first**: per-source, per-subnet (/24, /64) and global token windows, per-flow UDP
  limits, a rule engine for arbitrary ports (magic/length/rate) and an opt-in abuse cap for the verified fast path.
- **Verified fast path**: a connection that completes the inspected handshake is remembered in-kernel; its packets then
  skip the parser entirely. Per-entry `bpf_timer` cleanup means no userspace process touches the hot path.
- **Escalating auto-blocklist**: repeated per-source abuse raises strikes and blocks the source for a doubling TTL,
  exported to a file; separate `autoblock` counters and a dry-run mode keep it auditable.
- **Observability & operations**: Prometheus endpoint with one counter per drop reason
  ([documented registry](docs/drop-reasons.md)), sampled top-talkers, a sizing/NIC advisor, an optional auto-tuner for
  the limits (bounded, damped, persisted) and an optional userspace ML scorer (shadow by default).
- **Zero-copy dropping**: malicious traffic is dropped at the driver level (XDP_DROP) for maximum performance,
  with an allowlist that bypasses all checks and reloads on `SIGHUP`.

What it does, what it cannot do and the residual risks are documented in
[`docs/threat-model.md`](docs/threat-model.md); read that before relying on it
against a real attack. Every control that can affect legitimate traffic has a
dry-run or shadow mode; use it before arming things.

## Installation (Linux)

### Download from releases

https://github.com/Outfluencer/Minecraft-XDP-eBPF/releases

You can download the latest build from the Releases Tab  
Then just run the executable in sudo mode or via root

### Prerequisites
- Rust toolchain (stable) — `autobuild.sh` installs it with rustup when missing
- clang/LLVM **14 or newer** (the eBPF program is built with `-mcpu=v3`)
- libbpf development headers (`bpf/bpf_helpers.h`)
- kernel uapi headers (`linux/bpf.h`, `asm/types.h`)

The one-command way — checks all of the above, installs what is missing,
builds the release loader and verifies that your kernel accepts the filter:

```bash
./autobuild.sh
```

It works with apt (Debian/Ubuntu), dnf (Fedora/RHEL), pacman (Arch) and
zypper (openSUSE). `NOINSTALL=1 ./autobuild.sh` only reports what is missing
instead of installing anything, and `XDP_BPF_INCLUDE=/prefix/include` points
the build at libbpf headers in a non-standard location.

Manual install (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y clang libbpf-dev linux-libc-dev git
```

`bpf/bpf_helpers.h` comes from libbpf's **development** package
(`libbpf-dev`, `libbpf-devel`, `libbpf` on Arch), not from the kernel headers.
If your distribution ships clang older than 14, install it from
[apt.llvm.org](https://apt.llvm.org) (CI uses LLVM 21):

```bash
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 21 all
```

### Build & Run
1.  **Build the project**:
    ```bash
    ./autobuild.sh          # friendly: installs what is missing, builds, verifies
    # or, with the dependencies already installed:
    ./build.sh              # = cargo build --release
    ```
    The compiled binary will be at `target/release/xdp-loader`.

2.  **Run the tests** (optional):
    ```bash
    cargo test
    ```
    Besides the Rust unit tests this compiles the eBPF parsing code (VarInt
    reader, packet inspectors) natively with ASan/UBSan and runs its C unit
    tests (see `xdp/tests/protocol_test.c`). The privileged end-to-end test
    (`sudo ./tests/e2e_loader.sh`) additionally loads the real object with
    every feature enabled and drives real traffic through it in a network
    namespace.

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
On first run it is created automatically with **every key documented inline and
all defaults shown**; that generated file is the reference. Use
`--config <path>` to point at a different file.

| Section | What it controls |
|---|---|
| `[filter]` | What is inspected: port range, per-source/subnet/global connection windows, the verified-path abuse caps, username/version strictness, dry run, source-address policy. |
| `[xdp]` | Attach mode (`"auto"`/`"driver"`/`"skb"`/`"offload"`) and the capacity of every in-kernel map (preallocated, so capacity is kernel memory). |
| `[bedrock]` / `[voice]` | The opt-in UDP protocols: port, validation strictness (protocol/MTU windows) and the voice gate (verified-IP requirement). |
| `[ingress]` | Optional default-deny for every port that is not explicitly opened, the `tc egress` flow tracking that backs the stateful pinhole, and the ICMP policy. |
| `[blocklist]` | Manual blocklist file, the escalating auto-blocker (strikes, base/max TTL, decay) and the export file. |
| `[[rules]]` | Declarative rules for arbitrary ports: TCP/UDP, allow/drop/rate, length bounds, magic bytes at an offset, stateful flag. `open_tcp_ports`/`open_udp_ports` sugar feeds the same engine. |
| `[autotune]` | The optional limit auto-tuner: bounds, damping thresholds, interval, dry run (default on) and the state file. |
| `[ml]` | The optional userspace risk scorer: mode `"off"`/`"shadow"`/`"enforce"`, threshold, model file, training. |
| `[advisor]`, `[metrics]`, `[logging]` | Sizing/NIC recommendations, the Prometheus endpoint, log level and rotation. |

Every limit that can drop legitimate traffic has a mode that only counts
(`dry_run`, `[autotune] dry_run`, `[ml] mode = "shadow"`), and the shipped
defaults do not change the behavior of the filter for normal players: the new
detections (`reject_proxy_header` aside) are opt-in.

The `[filter]` values and map capacities are pushed into the eBPF program at
load time (via `.rodata` globals and map definitions), so changing them only
requires a restart — **not a rebuild**.  

## Operating it

**Tuning with dry run.** Start with `dry_run = true` and watch
`minecraft_would_drop_reason{reason=...}` while real players connect. Reasons
that should stay at zero on a healthy server are listed in
[`docs/deployment.md`](docs/deployment.md) together with what each one means;
which reasons this build actually emits (the rest are reserved registry slots
that no code path increments) is in
[`docs/drop-reasons.md`](docs/drop-reasons.md).
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

**Network namespaces and tests.** `tests/e2e_loader.sh` builds a veth pair in a
network namespace, loads the *real* object with every feature enabled, drives
real traffic through it (valid players, status queries, Bedrock/voice, stateful
pinhole, crafted attack shapes) and asserts on both what arrived and the drop
reasons that moved:

```bash
cargo build --release && sudo ./tests/e2e_loader.sh
```

**Metrics.** With `enabled = true` and an `addr` set:

```
minecraft_verified_connections          verified players since start
minecraft_verified_packets              packets that took the verified fast path
minecraft_syn_packets                   SYNs seen on the filtered ports
minecraft_udp_packets                   UDP packets seen on the bedrock/voice ports
minecraft_dropped_packets/bytes         drops and dropped volume
minecraft_dropped_connections           connections killed by the filter
minecraft_incoming_bytes                all bytes seen on the filtered ports
minecraft_state_switches                handshake state transitions
minecraft_tcp_bypass                    SYNs that carried payload
minecraft_egress_flows                  tracked egress flows (stateful pinhole)
minecraft_egress_errors                 egress tracking/parse errors
minecraft_ipv6_packets                  IPv6 traffic (also inspected, see the threat model)
minecraft_drop_reason{reason="..."}     one counter per drop reason
minecraft_would_drop_reason{...}        the same counters while dry run is active
minecraft_dry_run                       1 while dry run is active
minecraft_allowlist_entries             entries currently in the allowlist
minecraft_blocklist_entries             manual blocklist entries
minecraft_autoblock_entries             currently auto-blocked sources
minecraft_limit_host_connections        live per-source connection limit
minecraft_limit_subnet_connections      live per-subnet connection limit
minecraft_limit_global_connections      live global connection limit
minecraft_limit_udp_packets             live per-source UDP limit
minecraft_limit_rule_packets            live rule-engine UDP limit
minecraft_limit_strike_threshold        live strikes before auto-block
minecraft_autotune_changes_total        limits actually changed by the auto-tuner
minecraft_ml_top_score                  highest ML score in the last pass
minecraft_ml_blocks_total               blocks applied by the ML enforcement pass
```

## Scope and limitations

Honest summary; details and residual risks in
[`docs/threat-model.md`](docs/threat-model.md):

- **Coverage is per port, not per host.** The Java range (default 25565) is
  inspected on IPv4 and IPv6; Bedrock, voice and arbitrary ports are covered
  only when enabled (`[bedrock]`, `[voice]`, `[[rules]]`, `[ingress]`). Every
  other port passes untouched unless you turn on default-deny ingress.
  Fragments aimed at an inspected port are dropped rather than reassembled, so
  the fragments never carry uninspected data into the backend.
- **Single host.** XDP filters what reaches *this* machine's NIC. It cannot
  absorb a volumetric flood that saturates the uplink; that needs upstream
  scrubbing, anycast or provider-side filtering. It *can* keep a saturated
  uplink's attack traffic from reaching the server, and it does the L7 work
  (handshake validation, per-IP/subnet/global limits, verified fast path) that
  network-layer filters cannot.
- **No authentication visibility.** A bot with a valid account that logs in
  slowly still reaches your auth server: XDP sees the packets, not Mojang's
  verdict. Combine with Velocity/Paper `connection-throttle`, online-mode auth
  and per-account checks. The egress hook gives flow state, not identity.
- **Default-deny is opt-in and depends on the egress hook.** With
  `[ingress] default_deny = true` you must also enable `egress_tracking = true`
  (the loader refuses the combination otherwise): a port is only reachable if
  it is opened in the config or the host talked first. Test it with real
  players, game consoles and monitoring before trusting it.
- **Generic (`skb`) mode** sees coalesced GRO segments, so only the first
  segment of a burst is inspected; prefer native mode on the server NIC.
- **ML is a heuristic, shadow by default.** The scorer is optional, trains on
  this host's own labels and never blocks anything unless you set
  `mode = "enforce"`; treat its output as a hint, not proof.
- Stopping the loader detaches the filter (fail open). Run it under systemd.

## Troubleshooting

### Non-root / Permission Errors
Please always check if you are running as root if any error occurred. If you are not, try again with `sudo`.  

⭐ **Don't forget to star the project on GitHub!**  
