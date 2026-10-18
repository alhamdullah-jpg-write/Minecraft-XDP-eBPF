# Roadmap

Ordered by (a) risk closed per unit of work, (b) measurable effect on the
numbers in `docs/benchmark-test-plan.md`. Each phase is independently
deployable and testable with the S-cases.

## Phase 1 — done (this revision)

- IPv4 TCP L3/L4 stateless sanity checks (IP/TCP header validation, strict
  `tot_len` check, impossible TCP flag combinations).
- Spoof filtering: reserved sources (default on), private sources (opt-in).
- Bounded connection tracking with in-kernel expiry (`conntrack_map`,
  `player_connection_map`, `connection_throttle` + `bpf_timer`).
- Minecraft protocol inspection with varint/bounds-hardened parser.
- Allowlist LPM trie with SIGHUP reload, dry-run mode, per-reason drop
  counters, Prometheus endpoint.
- Verifier load-test script + native C parser unit tests + Rust unit tests.

## Phase 2 — close the protocol gaps (highest user-visible value)

1. **IPv6 inspection** (TCP). The stateless checks and the state machine are
   address-family agnostic; the work is parsers and map key changes:
   - new `ipv6_flow_key` (`struct in6_addr` × 2, ports) + separate maps, or a
     tagged common key (branch per family to keep the fast path cheap);
   - extend the allowlist trie to IPv6 (two tries or a 16-byte key);
   - keep IPv6 accounting so operators can prove coverage.
   Effort: medium. Test: S9 IPv6 rows move from "documented gap" to covered.
2. **UDP: Bedrock / RakNet (`19132/udp`)**. Stateless RakNet validation is
   cheap and highly effective against the common reflection and junk floods:
   verify the RakNet magic (`...00ffff00fefefefefdfdfdfd12345678`), the
   datagram type (Unconnected Ping `0x01`/`0x02`, Open Connection Request
   1/2 `0x05`/`0x07`, online `0x08`), MTU bounds, protocol version, and reply
   statelessly for the ping (the standard RakNet offline-message defense);
   track `Open Connection Reply 1/2` + cookie (`0x09` cookie handshake in
   recent versions) per source IP with the existing throttle pattern.
   Effort: medium. Test: S3/S4 equivalents for RakNet.
3. **Simple Voice Chat (`24454/udp`, plugin-configurable)**. Validate the
   plugin's packet shape (magic bytes/type/secret), bind it to the same
   verified-IP map from the Java connection where possible, and allow per-IP
   rate limits. Effort: low-medium (protocol is documented and small).
4. **Custom rule engine** (YAML/TOML): compile declarative rules
   (`protocol`, ports, `len min/max`, magic at offset, rate, action) into BPF
   maps that a *generic* matcher in the program consults; hot reload like the
   allowlist. This replaces "write a C patch per protocol" for operators.
   Effort: high, but the only way to cover the long tail (mods, other
   services) without unbounded C growth. Must stay verifier-friendly
   (bounded loops over map entries).
5. **Per-subnet (e.g. /24) and global token buckets**: a spoofed flood with
   millions of addresses defeats per-IP limits; add a second-level bucket per
   /24 and one global "new connections/s" allowance so the filter degrades
   gracefully instead of exhausting maps. Also upgrade the per-IP window to a
   sliding/token-bucket window to remove the 2× boundary burst.

## Phase 3 — operational depth

1. **Top-talkers / sampled forensics**: a ring buffer with the first N packets
   of dropped flows (headers only, sampled 1:1000) plus userspace decoding, so
   operators can see *what* the attack looked like. Never on the hot path
   unguarded (bounded ring, per-CPU).
2. **Egress hook** (`tc` egress / XDP egress on capable NICs): drop reflections
   from other local services, and observe the server's outbound SYN-ACKs to
   correlate Y (verified) with reality; can also feed a "real unique player IPs"
   list for smarter allowlisting.
3. **Integration test harness**: netns + veth pair + crafted packet suites
   asserting `minecraft_drop_reason` per case (the S3/S10 cases automated).
   Run in CI where privileged, otherwise nightly.
4. **Fuzzing**: libFuzzer/AFL on `xdp/tests/protocol_test.c`'s parsers with
   ASan (already sanitized), seeded from real client captures per version.
5. **Loader robustness**: pin the maps (`BPF_F_MMAPABLE`/pinned paths) so a
   loader restart can reuse state; optional `--keep-attached` watchdog mode;
   structured logs; OTLP/metrics-txt parity.

## Phase 4 — performance headroom

1. **XDP hardware offload** where supported (`mode = "offload"`), for line-rate
   filtering at 10/25/40 GbE without consuming host CPU.
2. **XDP metadata (`xdp_hints`)** for fragmented/GRO cases where the driver
   supports it; skip the header re-parse.
3. **Map tuning**: `BPF_F_NO_PREALLOC` vs. prealloc trade-offs measured
   (S7 knee), per-CPU LRU for conntrack to avoid global spinlocks.
4. **Instruction budget**: keep the program < 1 k insns per path, verify with
   `bpftool prog profile` per-core cost (S1/S7).

## Explicitly not planned

- Competing with anycast scrubbing on volumetric capacity — buy upstream
  scrubbing; this filter complements it.
- Inspecting encrypted login traffic or "detecting bots" heuristically:
  unreliable, high false-positive risk, and out of protocol.
- Rewriting the whole thing in Rust/eBPF (aya) for a marginal safety gain at a
  large cost in verifier surprises.

## How to decide what's next

Run `docs/benchmark-test-plan.md` S-cases against the current build; the phase
that removes the first failing acceptance criterion gets done first. In most
deployments that is Phase 2.1 (IPv6) if the server publishes AAAA records, or
Phase 2.2 (Bedrock) if the host runs Geyser.
