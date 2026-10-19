# Roadmap

Ordered by (a) risk closed per unit of work, (b) measurable effect on the
numbers in `docs/benchmark-test-plan.md`. Each phase is independently
deployable and testable with the S-cases.

The list below is the actual state of the tree, not an aspiration: completed
items name the file or test that proves them, and every remaining item is
still open. Nothing is called "done" without either a unit test or a stage in
`tests/e2e_loader.sh`.

## Delivered

### Phase 1 — stateless filtering and the verified fast path

- IPv4 TCP L3/L4 sanity checks (IP/TCP header validation, strict `tot_len`,
  impossible flag combinations).
- Spoof filtering: reserved sources (default on), private sources (opt-in).
- Bounded connection tracking with in-kernel expiry (`conntrack_map`,
  `player_connection_map`, `host_throttle` + `bpf_timer`).
- Minecraft protocol inspection with a VarInt/bounds-hardened parser
  (`xdp/protocol.h`, `xdp/varint.h`).
- Allowlist LPM trie with SIGHUP reload, dry-run mode, per-reason drop
  counters, Prometheus endpoint.

### Phase 2 — protocol and scale gaps

- **IPv6 inspection** — one 16-byte address representation and a tagged flow
  key (`xdp/flow.h`), so the state machine covers IPv4 and IPv6 without a
  second code path; IPv6 accounting kept (`minecraft_ipv6_packets`).
- **Bedrock/RakNet (`19132/udp`, opt-in)** — stateless offline-handshake
  validation with a strict protocol/MTU window (`xdp/udp.h`), a provable
  rejection for malformed handshakes (`bedrock_invalid`), and the stateful
  pinhole for connected game traffic (`bedrock_untracked`).
- **Simple Voice Chat (`24454/udp`, opt-in)** — shape check plus the
  verified-IP gate fed by the Java login (`voice_unverified`, `voice_invalid`).
- **Custom rule engine** — `[[rules]]` matches protocol/ports, length bounds,
  magic at an offset and an allow/drop/rate action, compiled into `rule_map`
  at load time (`xdp/rules.h`, loader validation rejects rules that target the
  dedicated protocol ports).
- **Per-subnet (/24, /64) and global token windows** — `subnet_throttle` and
  `global_rate` bound what a spoofed flood can buy; the per-source window is
  extrapolated with a sliding estimate so a window boundary no longer doubles
  the burst.

### Phase 3 — operational depth

- **Sampled top-talkers** — `talkers_map` (LRU, per-source packets/bytes/SYNs/
  drops) feeds the metrics endpoint, the sizing advisor and the ML scorer.
- **Egress hook** — a `tc egress` program (`xdp/egress.h`, same object) tracks
  what the host itself sent, keyed by the reverse 5-tuple.
- **Stateful pinhole + default-deny ingress** — the egress-tracked flows back a
  TCP-sequence/ICMP-ident checked pinhole, and `[ingress] default_deny = true`
  turns "not explicitly opened" into a drop (`unsolicited`, `proto_deny`).
- **Integration test harness** — `tests/e2e_loader.sh` builds a veth pair in a
  network namespace, loads the object with every feature enabled, drives real
  traffic (`tests/e2e_traffic.py`: valid clients, the pinhole across a punch,
  crafted attack shapes, flood/lockout stages) and asserts on both the traffic
  that arrived and the reason counters; it runs in CI (`rust.yml`).
- **Escalating auto-blocklist** — strikes on per-source limits, doubling TTLs,
  decay, dry-run, an export file and its own counters (`xdp/blocklist.h`).
- **Auto-tuner** — bounded, damped userspace control loop for the limits that
  were explicitly configured, dry-run by default, state persisted to TOML
  (`loader/autotune.rs`).
- **ML risk scoring** — userspace logistic regression over talker features,
  trained from this host's own labels, shadow mode by default
  (`loader/ml.rs`).
- **Documented drop-reason registry** — 345 stable values, 46 emitted by this
  build, with generated tables and a `--check` mode
  (`docs/drop-reasons.md`, `xdp/tests/gen_drop_reason_docs.py`).

### Phase 4 (partial)

- **XDP offload support** — `mode = "offload"` is wired through the loader
  (attach mode plus a clear error when the driver does not support it); the
  performance claims still need the S-cases on offloading hardware, so the
  numbers in `docs/benchmark-test-plan.md` remain the acceptance gate.
- **Cheap filters first** — the packet path checks allowlist, stateless
  headers, the blocklists and the fail-closed map state before it touches the
  parser or the rate tables (see the ordering in `xdp/minecraft_filter.c`).

## Open

### Next: correctness and confidence

1. **Fuzzing** — libFuzzer/AFL on the parsers in `xdp/tests/protocol_test.c`
   (already ASan/UBSan-clean), seeded from real client captures per version.
2. **Loader robustness** — pin the maps (`BPF_F_MMAPABLE`/pinned paths) so a
   loader restart can reuse state; optional `--keep-attached` watchdog mode;
   structured logs; OTLP parity.
3. **Egress tracking for UDP replies (beyond the pinhole)** — today the
   pinhole is what protects stateful UDP; a richer tracker would let the rule
   engine express "reply-only" ports without either opening a port or
   default-deny.

### Then: performance headroom

4. **XDP metadata (`xdp_hints`)** for fragmented/GRO cases where the driver
   supports it; skip the header re-parse.
5. **Map tuning measured, not assumed** — `BPF_F_NO_PREALLOC` vs. prealloc
   trade-offs (S7 knee), per-CPU LRU structures where the global spinlock
   shows up in `bpftool prog profile`.
6. **Instruction budget** — keep each path under ~1 k insns and verify the
   per-core cost with `bpftool prog profile` (S1/S7); publish the numbers next
   to the claims.

### Later

7. **Version matrix automation** — the S9 rows (1.8 … 1.21.x, Forge/Fabric,
   proxies, snapshots) as a scheduled job against a disposable server.
8. **Geo/ASN-aware buckets** — only if the S-cases show per-subnet buckets are
   not enough; needs an offline prefix table and stays opt-in.

## Explicitly not planned

- Competing with anycast scrubbing on volumetric capacity — buy upstream
  scrubbing; this filter complements it.
- Inspecting encrypted login traffic or "detecting bots" heuristically beyond
  the documented shadow-mode scorer: unreliable, high false-positive risk, and
  out of protocol.
- Rewriting the whole thing in Rust/eBPF (aya) for a marginal safety gain at a
  large cost in verifier surprises.

## How to decide what's next

Run `docs/benchmark-test-plan.md` S-cases against the current build; the item
that removes the first failing acceptance criterion gets done first. In most
deployments that is now the fuzzing/loader-robustness pair (the protocol gaps
that used to be listed here are closed).
