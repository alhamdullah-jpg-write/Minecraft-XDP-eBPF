# Benchmark & test plan

Purpose: produce numbers that are (a) reproducible by a third party on the
same hardware, (b) honest about what a single host can and cannot do, and
(c) directly comparable with other filters (nftables/iptables rate limiting,
another XDP program, a commercial scrubbing service).

**Rule for all reporting: no claim without the measurement setup, raw numbers
and the baseline it was measured against.** "Better" is only meaningful as:
higher legitimate-player success under the same attack, at the same cost.

## 1. What can and cannot be compared

| Dimension | Comparable on one host? | How |
|---|---|---|
| Packets/s dropped per core, drop before/after `sk_buff` | yes | run the attacker and victim on the same host/NIC pair |
| Legit join success rate during attack | yes | real clients (or a scripted client) + attack in parallel |
| Added latency on the legit path | yes | `tcpdump`/`tc` timestamps or client-perceived join time |
| False positives per client type/version | yes | the S9 matrix below |
| L7 Minecraft awareness | yes | compare with a stateless L3/L4 filter which cannot do it |
| **Volumetric absorption** (Tbps anycast, Magic Transit-class) | **no** | requires upstream capacity; a single 1/10/25 GbE host cannot absorb a 1 Tbps flood. Any test here measures *what arrives*, not what is filtered upstream |
| Provider-side outage/latency effects | no | needs a provider test window |

If a provider (e.g. Cloudflare Magic Transit, AWS Shield, OVH/Path, or a
Minecraft-specific vendor like DonutShield) is part of the comparison, the only
fair statement is: same server, same hardware, same attack from the same
sources, provider path vs. this filter, identical client workloads. That is the
"CF/MT baseline" row in §6 and can only be filled in by someone who has access
to that service. Without those rows, the honest claim is: *"single-host XDP
filter with first packet + per-flow state; absorbs up to the NIC/CPU limit and
keeps players connected; it does not replace upstream scrubbing."*

## 2. Environment and fairness rules

- Same host, kernel, NIC, MTU, driver, CPU governor (`performance`), SMT setting,
  and Minecraft server build/plugins for every arm of a comparison.
- Attack generator and victim on different machines connected through a real
  switch (never `lo`); record the switch/NIC max pps for the attack direction.
- Disable the JVM warmup problem: pre-generate chunks, disable backups during
  the run, use the same world seed, run each configuration ≥ 5 times, report
  median and p95, discard a one-minute warmup.
- Record CPU utilization per core (`mpstat -P ALL`), softirq time, NIC counters
  (`ethtool -S`), `/proc/net/dev`, XDP metrics, JVM TPS (Minecraft tick time),
  and client-observed success/timeout counts.
- Attack tools may lie: always cross-check the injected packet rate against the
  victim's NIC RX counters. A generator that cannot produce the rate is not
  evidence of success.
- `mode` must be recorded: `driver` (native) or `skb` (generic). Never mix rows.

## 3. Tools

| Tool | Use |
|---|---|
| `trafgen` (netsniff-ng) | cheap high-pps stateless floods (SYN, ACK, UDP, malformed) |
| `pktgen` / `pktgen-dpdk` / TRex | line-rate stateless and stateful floods; DPDK variants bypass the sender's kernel |
| `hping3 --flood -S -p 25565` | quick sanity SYN flood (with `--rand-source` to spoof, from a test network that permits it) |
| `scapy` | crafted L7: bad VarInts, 0x00-only floods, oversized host, fragmented first bytes, TFO-with-data SYNs |
| `mineflayer` / `mcstatus` / a small Rust/Go client | legitimate clients: status, login, offline-mode joins, version matrix |
| `wrk`/`hey` against the metrics port | metrics endpoint overhead (must not affect the hot path) |
| `perf top` / `bpftool prog profile` (if available) | per-instruction cost of the XDP program |

## 4. Metrics to capture

| Group | Metrics |
|---|---|
| Throughput | attack pps at the NIC RX counter, dropped pps (XDP reasons), passed pps |
| Application | successful joins/min, failed joins (timeout/refused/kicked), TPS, GC pauses, open connections |
| Efficiency | pps per core at 100 % drop, bytes dropped before `sk_buff` (native) |
| Precision | false positives: legit success rate with attack vs. without, per client type |
| Cost | added latency per packet (p99), CPU % at idle and under attack, memory of maps (see `bpftool map` or sizing) |
| Correctness | `minecraft_drop_reason` counters vs. what the generator actually sent (e.g. count of malformed packets) |

## 5. Test cases

### S1 — Volumetric SYN flood, single source
`hping3 --flood -S -p 25565 <victim>`. Expect: most SYNs dropped by the
throttle after `hit_count`; kernel stays healthy; a real client joining during
the flood succeeds after the throttle window (or is dropped — record which).
Pass criteria: at least one topology (native mode) sustaining > 3 Mpps SYN
with < 10 % dropped *legit* joins and JVM TPS ≥ 18.

### S2 — Spoofed SYN flood, many sources
`hping3 --rand-source` (or `trafgen` with a config generating random sources).
Expect: stateless checks plus per-source throttle; `max_throttled_ips` may be
exhausted → fail-closed `throttle_state`. Record the pps at which that starts
and the client-visible effect. This is the test that separates host filters
from scrubbing networks: it measures how gracefully the filter degrades.

### S3 — Malformed / crafted floods
Bad VarInt lengths, packet ID floods, empty-payload streams, TFO-with-data,
first-fragment flood, impossible TCP flags (NULL/FIN+SYN/XMAS), ACK-only floods
to the port with no tracked flow. Every category must map to a specific
`minecraft_drop_reason`; a counter that does not move means a gap in the code
(*this is the regression test for the parser*).

### S4 — Valid-handshake / bot-join flood
Script N clients (mineflayer with random offline names, or a raw-socket client
that replays captured handshakes) joining as fast as possible from M source
IPs. Measure: connections accepted per second, verified connections, JVM
impact, and how many *real* player slots are consumed. Expect: the throttle
caps per-IP joins; with many IPs the JVM is the bottleneck — that is T5, by
design not solvable here.

### S5 — Login-flood (auth spam) *impact* test
Bots with real accounts logging in slowly. This documents the residual risk:
the filter should not be blamed for it. Record JVM/backend behavior with and
without the filter to show the filter neither helps nor hurts.

### S6 — Mixed traffic (e.g. 95 % attack / 5 % legit)
The realistic case. Run S1 + a continuous stream of legit joins/reconnects.
Report legit success rate, join latency p50/p95/p99, and JVM TPS.
This is the headline number for a Minecraft host owner.

### S7 — Ramp / knee detection
Start at 1 % of the NIC's line rate and increase in steps; find the knee where
legit joins degrade, the pps at that point, and which resource saturates first
(single CPU core? softirq? NIC queue? conntrack?). Document the curve.

### S8 — Map exhaustion
Pre-fill `connection_throttle` to `max_throttled_ips` (spoofed sources),
then test: (a) new SYNs are dropped via `throttle_state` (fail closed);
(b) verified players keep playing; (c) capacity recovers after
`hit_count_reset_secs` when the flood stops.

### S9 — False-positive / compatibility matrix
Each row: connect, list pings, join, play 30 s, disconnect — with the filter in
dry-run first (expect zero `would_drop_reason` except `empty_ack`) then live.

- Versions: 1.8 … 1.21.x plus the versions the README claims (`1.8 - 26.3`),
  including the legacy-ping path.
- Modes: online-mode and offline-mode; long reason strings (status), SRV
  hostnames, `host` containing `\0FML\0` (Forge), Fabric, modded handshakes.
- Proxies: BungeeCord, Velocity (modern forwarding), Geyser (Java client →
  Java port), TCPShield-style PROXY protocol (helps only if the filter sits
  behind it — record it).
- Networking: MTU 1500 and 9000, VLAN tag present, fragmented *other* traffic
  must still pass (course, e.g. a large `ping -s 3000` to a different port),
  two clients behind one NAT (per-IP throttle fairness!), mobile client
  reconnecting repeatedly, IPv6-only client (expected: unprotected → must be
  documented and, if the host has AAAA records, resolved by upstream or the
  roadmap).
- Environment: server restart mid-run, loader restart mid-run (players keep
  connected? they must re-handshake), metrics scrape during attack.

Pass criteria: 0 false positives on all Java/TCP rows; any false positive is a
bug with a reproduction attached.

### S10 — Metrics accuracy
Generate known counts per category (e.g. exactly 500 malformed packets,
500 SYNs, 2 full handshakes) and compare with the scraped counters.
Pass: counters within the expected semantics (per-CPU sums; `empty_ack` = 1 per
connection; `incoming_bytes` = Σ frame lengths on the filtered port).

### S11 — Overhead at idle
`perf stat`/`mpstat` with the filter attached and only keepalive traffic:
expect < 1 % of one core; scrape overhead of the metrics endpoint measurable
but independent of the hot path.

## 6. Comparison arms

| Arm | How | What it shows |
|---|---|---|
| A. No filter | server exposed | baseline damage numbers |
| B. Kernel-only rate limit | `iptables/nftables` `hashlimit`-style rules for SYN and per-IP connection rate | what a competent sysadmin gets without XDP |
| C. This filter, native (`mode = "driver"`) | §5 | XDP + L7 awareness |
| D. This filter, generic (`mode = "skb"`) | §5 | cost of the fallback |
| E. Another XDP/eBPF filter (if available) | same scripts | head-to-head |
| F. Commercial protection / scrubbing (e.g. Magic Transit, DonutShield, OVH Game) | **operator-supplied**, same attack sources, same client workload | the only honest "us vs. them" row |

Fill in F only with a real service window; a synthetic comparison is not valid
because the provider's edge is not on your hardware. When F exists, use the
same S-numbered cases and report per-service caveats (their edge location,
plan limits, and whether they filter Minecraft UDP).

## 7. Reporting template

```
Date / git revision:            <sha>
Host:                           CPU model, cores, RAM, NIC model+driver, kernel
Filter config:                  mode, start/end port, hit_count/window, map sizes, dry_run
Attack:                         tool, packets/s (victim NIC counter), sources, duration
Legit workload:                 clients/version/proxy, joins per minute
Results:                        per test case S1..S11
  - dropped pps by reason
  - legit success rate + join latency p50/p95/p99
  - TPS min/median, CPU% per core, softirq%
  - map pressure (throttle_state, verify_map_full)
Raw data:                       tar of counters dumps + scripts
Caveats:                        anything the operator could not control
```

## 8. Acceptance criteria (suggested for this project)

1. Native mode: 3 Mpps spoofed SYN (S2) with legit join success ≥ 90 % and
   JVM TPS ≥ 18 on a modern 8-core host.
2. Zero false positives across the S9 matrix.
3. `throttle_state`/`verify_map_full` never increment at the configured player
   count (S11).
4. Idle overhead < 1 % of one core (S11).
5. All drop reasons exercised and verified by S3/S10.
6. Numbers reproducible by a third party using this document and the scripts in
   `scripts/` (to be added with the first published run).
