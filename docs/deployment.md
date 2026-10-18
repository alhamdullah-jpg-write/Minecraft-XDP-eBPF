# Deployment guide

Target: a single Minecraft Java host (Paper/Velocity/…), IPv4, Linux 5.15+,
XDP attached to the public interface before the Java port.

## 1. Requirements

| Component | Minimum | Notes |
|---|---|---|
| Kernel | 5.15 | `bpf_timer` requires BTF; 6.x recommended (better verifier, XDP metadata) |
| clang/LLVM | 14+ (`-mcpu=v3`) | only needed to build or to run the verifier check script |
| Rust | stable, edition 2024 | only needed to build from source |
| Privileges | root / CAP_BPF + CAP_NET_ADMIN | loading the program, reading maps, SIGHUP target |
| NIC | any | native XDP needs driver support; generic works everywhere |

## 2. Build and install

```bash
# from source
cargo build --release               # builds xdp/minecraft_filter.o via build.rs
sudo install -m755 target/release/xdp-loader /usr/local/bin/xdp-loader
sudo ./xdp/tests/verifier_load.sh   # loads the object into the running kernel
```

`cargo test` also runs the C parser unit tests. The verifier script is the
stronger gate: it is the only thing that catches verifier rejections.

Deploy the config and allowlist:

```bash
sudo install -d /etc/minecraft-xdp
sudo install -m600 config.toml /etc/minecraft-xdp/config.toml   # created on first run with defaults
sudo install -m600 allowlist.txt /etc/minecraft-xdp/allowlist.txt
```

## 3. Attach modes

| `mode` | Behaviour | When to use |
|---|---|---|
| `auto` (default) | native if the NIC driver supports it, otherwise generic | most hosts |
| `driver` | force native; fails to load when unsupported | you want a hard guarantee (no silent slow path) |
| `skb` | force generic (skb) mode | virtual NICs, testing, kernels where native XDP is broken |

Notes and caveats:

- Native mode runs in the driver RX path: cheapest, drops before `sk_buff`
  allocation. **Preferred.**
- Generic mode runs after `sk_buff` allocation and, on most NICs, *after GRO*:
  coalesced segments are seen as one large frame, so only the first Minecraft
  packet of a burst gets inspected. Correctness is unaffected (the state
  machine still requires the handshake), but rate-limit accuracy drops.
- Check what you actually got in the log: native logs
  `BPF program attached ... in native mode`, otherwise
  `... does not support native XDP ..., using generic skb mode`.

## 4. systemd unit

`/etc/systemd/system/xdp-filter.service`:

```ini
[Unit]
Description=Minecraft XDP filter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xdp-loader --config /etc/minecraft-xdp/config.toml eth0
Restart=always
RestartSec=1
# load/attach needs these; drop the rest
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON
LimitMEMLOCK=infinity
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
# the loader writes xdp-loader.log and rotated files here
WorkingDirectory=/var/log/minecraft-xdp
ReadWritePaths=/var/log/minecraft-xdp

[Install]
WantedBy=multi-user.target
```

Replace `eth0` and create `/var/log/minecraft-xdp` (owned by root). Restarting
the service briefs a fail-open window (program detached for ~1 s); the filter is
stateless across restarts (throttle windows and verified connections are
rebuilt as traffic flows).

## 5. NIC and kernel tuning

The XDP program removes junk before the stack, but legitimate traffic still
goes through the kernel, so the network stack must be sized for the goodput you
expect.

**Single-queue vs RSS.** Native XDP runs on the RX queue that received the
packet, so the packet rate is spread across queues/CPUs automatically. Give the
NIC one queue per CPU that should process traffic:

```bash
ethtool -L eth0 combined 8            # adjust to the number of cores you dedicate
```

**Ring sizes.** Larger RX rings absorb bursts from the NIC to memory:

```bash
ethtool -G eth0 rx 4096 tx 4096
```

**Offloads.** Keep GRO/TSO on for native mode (GRO happens after XDP). In
generic mode GRO coalescing hides segments from the filter; if you must use
generic mode and need precise rate limiting, disable GRO on that interface
(`ethtool -K eth0 gro off`) and accept the throughput hit.

**IRQ/queue affinity.** Pin RSS queues to dedicated CPUs
(`/proc/interrupts`, `smp_affinity`) if the host also runs the JVM, so the JVM
is not starved by interrupt storms.

**Kernel backstops** (these still apply after the filter):

```bash
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w net.core.somaxconn=65535
sysctl -w net.core.netdev_max_backlog=65535
sysctl -w net.ipv4.tcp_syn_retries=3          # shorter client-side timeouts
sysctl -w net.ipv4.tcp_abort_on_overflow=1    # fail fast instead of dropping ACKs silently
```

Persist them in `/etc/sysctl.d/99-xdp-filter.conf`.

**JVM/application.** The filter only protects the TCP port range. Also set
Velocity `connection-throttle` and Paper's
`settings.max-joins-per-tick`/`max-players`; the filter cannot see or stop
login/auth abuse (T5 in `docs/threat-model.md`).

## 6. Tuning the filter

| Symptom | Knob |
|---|---|
| Legit players occasionally time out in the connect phase | raise `hit_count` or `hit_count_reset_secs`; check `minecraft_drop_reason{reason="throttle_limit"}` |
| Bots hold connections open without completing the handshake | lower `player_idle_timeout_secs` (verified only) — half-open junk is already bounded by `max_pending_connections` |
| `throttle_state` growing | `max_throttled_ips` too small for the flood; raise it (memory cost ~24 B/entry + hash overhead) |
| `verify_map_full` growing | `max_player_connections` below real concurrency (raise to ≥ 2× player count) |
| `empty_ack` climbing | **normal**: it is the finishing ACK of every legitimate connection |
| `private_source`/`reserved_source` climbing while players complain | you enabled `drop_private_sources` and something behind a proxy/NAT is connecting; disable it or allowlist the proxy |

Map sizing rule of thumb: `max_pending_connections` ≈ 2× the expected
simultaneous connecting players (LRU protects the rest);
`max_player_connections` ≥ players (never let it be evicted: eviction forces a
re-handshake).

## 7. Allowlist operations

```bash
/etc/minecraft-xdp/allowlist.txt:
# management + monitoring
203.0.113.10
198.51.100.0/24
```

```bash
sudo kill -HUP "$(pgrep -x xdp-loader)"   # re-read without detaching
grep -i allowlist /var/log/...            # "Allowlist reloaded: N entries"
```

Failed reloads keep the previous content and log the parse error with line
numbers. Remember T8: allowlisting is only safe for sources your upstream
provider prevents others from spoofing.

## 8. Monitoring

Scrape `http://127.0.0.1:1999/metrics` (Prometheus config snippet):

```yaml
scrape_configs:
  - job_name: minecraft-xdp
    static_configs:
      - targets: ["127.0.0.1:1999"]
```

Alert ideas:

| Alert | Expression | Meaning |
|---|---|---|
| Filter down | `absent(minecraft_syn_packets)` (for the scrape interval) | loader stopped; the host is unprotected (fail-open) |
| SYN flood | `rate(minecraft_syn_packets[1m]) > 200` | sustained connect flood |
| Throttle active | `rate(minecraft_drop_reason{reason="throttle_limit"}[1m]) > 5` | per-IP limit is being hit; check whether legit players are in it |
| Map pressure | `rate(minecraft_drop_reason{reason=~"throttle_state\|verify_map_full"}[5m]) > 0` | raise the corresponding map capacity |
| Dry run left on | `minecraft_dry_run == 1` | filter is not dropping anything |
| Private drops | `rate(minecraft_drop_reason{reason="private_source"}[5m]) > 0` | possible self-inflicted outage |

Drop reasons that should stay at zero on a healthy public server:
`eth_malformed`, `ip_malformed`, `ip_fragment`, `tcp_malformed`,
`reserved_source`, `tcp_flags`, `syn_payload`, `throttle_state`, `track_state`,
`not_tracked`, `bad_ack`, `sequence_mismatch`, `out_of_order_limit`,
`handshake_invalid`, `status_invalid`, `ping_invalid`, `login_invalid`,
`verify_failed`, `verify_map_full`. `empty_ack` is expected once per
connection; `empty_segment` and `ping_extra` indicate odd clients or scans.

## 9. Verification checklist before going live

1. `sudo ./xdp/tests/verifier_load.sh` → `OK`.
2. Start with `dry_run = true`, restart the loader, connect with a real client
   (all supported versions you host) and confirm every would-drop counter stays
   at zero except `empty_ack`.
3. Join through any proxy (Bungee/Velocity/Geyser) and modded clients; watch
   `would_drop_reason` again.
4. Turn dry run off, restart, and repeat one real join per client type.
5. Attack yourself from a test host (`hping3 -S`, `trafgen`, see
   `docs/benchmark-test-plan.md`), confirm drops appear and the real client
   keeps playing.
6. Wire the alerts above and confirm `absent()` fires when you stop the loader.

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Operation not permitted` / `-EPERM` on start | run as root or grant CAP_BPF+CAP_NET_ADMIN (systemd unit above) |
| `program load failed: ... invalid access to packet` | the verifier rejected the object; run the verifier script to see the log. Report with the log |
| `does not support native XDP ..., using generic skb mode` | NIC driver lacks native XDP; performance will be lower, correctness unaffected |
| Filter loads but no drops | check `mode`, the port range, and that traffic really targets the filtered ports (`minecraft_incoming_bytes`) |
| Players time out right after "Connecting to…" | throttle too strict for shared/NAT egress; raise `hit_count` or allowlist the proxy |
| Everything works but metrics are empty | `[metrics] enabled = true` and a reachable `addr`; counters are per-CPU and only summed on scrape |
| Loader log stops growing | log rotation (`file_max_mb`, 5 files kept) |
