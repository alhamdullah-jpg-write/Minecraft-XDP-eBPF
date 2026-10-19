# Threat model

Scope: `minecraft-ebpf-xdp` as deployed on a single Minecraft host, filtering
the ports it is configured for — the Java TCP range (default 25565) on IPv4 and
IPv6, plus whatever the operator opts into: Bedrock/RakNet (`19132/udp`), Simple
Voice Chat (`24454/udp`), arbitrary TCP/UDP ports via the rule engine, and an
optional default-deny policy for everything else, backed by a `tc egress` hook
that records which flows the host itself started.

This document states what the filter protects, against whom, and — just as
importantly — what it does not protect against. It is written for operators,
not for marketing: every "protected" claim below maps to code in `xdp/`, and
every residual risk has a mitigation section. Nothing here claims to be
*better* than another product; `docs/benchmark-test-plan.md` defines how to
measure this filter against its alternatives on your own hardware, with your
own traffic mix.

## 1. Deployment model

```
 attacker(s)                operator                     protected host
 ──────────                 ────────                     ──────────────
 internet ──▶ upstream router / ISP ──▶ NIC ──▶ [XDP filter] ──▶ kernel TCP/IP
                     │                              │  ▲           │
                     │                              │  │           ▼
                 scrubbing?                    stats_map  │    Paper / Velocity /
                 uRPF/BCP38?                  (per-cpu)   │    Geyser / SVC plugin
                                                         │           │
                                                  [tc egress tracker] JVM threads
```

Trust boundaries:

| Boundary | Trusted | Untrusted |
|---|---|---|
| Upstream → NIC | nothing | everything: source addresses may be spoofed unless the provider filters them |
| XDP → kernel stack | only packets that passed inspection are *inspected*; ports and protocols the operator did not configure are passed untouched unless default-deny is on | — |
| XDP → JVM | packets that completed the inspected handshake are forwarded without further filtering (the opt-in per-connection abuse cap is the exception) | — |
| `tc egress` → `egress_flows` map | the host's own outbound traffic creates pinholes; the map is keyed by the reverse 5-tuple | anything that can guess a tracked flow and its TCP sequence space |
| Loader → maps | loader (root) | — |

## 2. Assets

1. **Player experience**: legitimate clients can complete the handshake and play.
2. **JVM/NETTY capacity**: connections, threads, memory, GC pressure.
3. **Backend slots**: Minecraft accepts a bounded number of logins; junk logins
   consume them.
4. **Uplink bandwidth** and, secondarily, host CPU.
5. **Filter state**: map capacity (conntrack, throttle, verified connections)
   must not be exhaustible by an attacker.

## 3. Adversary capabilities

| Capability | Realistic? | Consequence |
|---|---|---|
| Spoofed source IPs | only where the attacking network does not filter (uRPF/BCP38) | defeats per-IP throttles; needs stateless checks and fail-closed behaviour |
| Reflection/amplification (UDP DNS/NTP/memcached, TCP SYN-ACK) | yes | volumetric; must be absorbed upstream |
| Botnet of real hosts | yes (Comcast/OVH/…) | per-IP throttles work, but each IP gets its own budget |
| Crafted/valid-looking Minecraft handshakes | yes, trivially automatable | the filter cannot distinguish a bot from a player; only rate limits help |
| Valid accounts logging in slowly | yes | not stoppable at XDP: authentication is on Mojang's side, and the egress hook gives flow state, not identity |
| Resource exhaustion of the filter itself | yes | map pressure must degrade gracefully (fail closed for junk, keep verified players) |

## 4. Threats and mitigations

### T1 — Volumetric L3/L4 flood (saturate the uplink)

**Out of scope for a single host.** If the pipe is full, packets are lost
before the NIC, and no amount of XDP can help. Mitigations are upstream:
provider scrubbing, anycast, BGP flowspec. What the filter guarantees is that
whatever *does* arrive is processed at line rate and that the application stays
usable: attack traffic is dropped in the driver, before `sk_buff` allocation
where possible (native mode).

### T2 — SYN flood / half-open exhaustion

- Stateless checks first: `xdp/minecraft_filter.c` drops non-TCP, malformed IP
  and TCP headers, impossible flag combinations
  (`tcp_flags_are_plausible()`), SYNs carrying payload (TFO abuse) and
  fragments aimed at the protected port.
- Per-source-IP limits: `host_throttle` (hash, `bpf_timer`-expired windows, default 10 new connections per 1 s window per source) plus a
  per-subnet bucket (/24, /64) and a global admission bucket, so one abusive
  block can not buy unlimited connections. Above a limit, SYNs are dropped in
  the XDP path (`DROP_THROTTLE_LIMIT`, `DROP_SUBNET_LIMIT`,
  `DROP_GLOBAL_LIMIT`). The window counters are extrapolated with a sliding
  estimate, so the raw window boundary no longer doubles the burst budget.
- Every accepted SYN is tracked in `conntrack_map` (LRU hash) with the expected
  TCP sequence, so junk that never completes the handshake is evicted rather
  than accumulated.
- Repeated per-source violations raise strikes and can auto-block the source
  (T12) — a sustained SYN flood from one address ends with that address
  blocked.
- Backstop: the kernel's SYN cookies / backlog are still there because the
  packets that pass are ordinary TCP.
- **Residual**: a spoofed flood from millions of addresses still costs one map
  insert each (bounded by `max_throttled_ips`/`max_throttled_subnets`, then
  fail closed — see T7), and the subnet/global buckets are the control that
  keeps a spoofed flood from exhausting the per-source budget of real players
  in the same neighborhood.

### T3 — Protocol junk aimed at the backend

Dropped before reaching the JVM: invalid VarInts and truncations
(`xdp/varint.h`, `xdp/protocol.h`), invalid packet IDs/lengths/state
transitions, legacy-ping abuse, non-matching TCP sequences/ACKs
(`DROP_SEQUENCE_MISMATCH`, `DROP_OUT_OF_ORDER_LIMIT`), and empty segments in
states that require the handshake. Only one provably-in-order byte stream
reaches the backend.

The crafted shapes that plugins and wrappers are probed with are rejected
explicitly and cheaply, before any map lookup:

| Shape | Result |
|---|---|
| Hostname length above the protocol cap (765 B), frame lengths above the handshake cap, unterminated/overlong VarInts, frames whose declared length disagrees with the body | `DROP_HANDSHAKE_INVALID`, connection killed |
| `next_state = 3` (the 1.20.5+ transfer state) with a legacy protocol number | `DROP_HANDSHAKE_INVALID` — only a wrapper-probing client can send that combination |
| `PROXY` protocol header (text v1 or the binary v2 signature) as the first payload | `DROP_PROXY_UNTRUSTED` (`reject_proxy_header`, default on) — a real proxy belongs on the allowlist, a backend that trusts forwarding headers must not be reachable directly |
| Legacy pre-1.7 ping (`0xFE`) | `DROP_LEGACY_PING` |
| Garbage/malformed RakNet offline handshake (wrong magic, truncated body, bogus MTU) | `DROP_BEDROCK_INVALID`, stateless |
| RakNet/game traffic that is neither a valid offline handshake nor a tracked flow | `DROP_BEDROCK_UNTRACKED` |
| Voice packet with an out-of-range type byte / wrong size | `DROP_VOICE_INVALID` |
| Non-TCP/UDP-ICMP protocol on an inspected port when default-deny is on | `DROP_PROTO_DENY` |

The proxy-header check cannot reject a legitimate player: an allowlisted proxy
is let through before it is even inspected, and no vanilla client frame starts
with the `PROXY ` text or the v2 signature.

### T4 — Handshake/status flood with plausible-looking traffic

Mitigated by the same per-source (and subnet/global) limit plus the
requirement that each tracked connection completes a real handshake to reach
the verified fast path. Status and ping flows are tracked with their own state
machine and dropped when they misbehave (`DROP_STATUS_INVALID`,
`DROP_PING_INVALID`, `DROP_PING_EXTRA`).

The "nullping" shape — a connection per join that completes the handshake and
Login Start and then idles until the server's login timeout — is bounded the
same way, because every such connection costs a SYN that the per-source window
counts. Above the limit the extra SYNs are dropped (`DROP_THROTTLE_LIMIT`) and
repeated abuse escalates into an auto-block (T12). The measured behaviour is in
`tests/e2e_loader.sh` (`login_burst` stage): 30 rapid logins from one source
are shed to the configured budget and the source is struck.

### T5 — Login/auth spam, "join bots" that are valid players

**Not stoppable here, with two partial exceptions.** Authentication happens
between the client and Mojang; the XDP filter sees only the encrypted/TCP
stream, so a distributed botnet with one login per IP looks like normal
traffic. The partial exceptions are (a) the per-source connection window, which
caps how many *simultaneous* unauthenticated login slots one address can hold,
and (b) the optional verified-path abuse caps (T13), which catch a connection
that authenticates and then floods. Both are volume controls, not
authentication: they cannot tell a bot from a player who is simply joining.
Mitigations belong to the application: Velocity/Paper `connection-throttle`,
`max-players`, queue plugins, online-mode, and account age/UUID checks. The
filter's contribution is that the network layer is not the bottleneck while
that happens.

### T6 — Amplification via the server (status/ping)

Status responses and pings are small; the state machine at least prevents using
the server as a reflector for crafted payloads. Upstream egress filtering is
the real control.

### T7 — Exhausting filter state

| Map | Type | Behaviour when full |
|---|---|---|
| `conntrack_map` | LRU hash | least-recently-used half-open flow evicted; the flow's next packet is dropped as `not_tracked` and must restart the handshake |
| `host_throttle` | hash + `bpf_timer`, fail closed | new SYNs are dropped (`DROP_THROTTLE_STATE`) until the 100 ms per-CPU insert backoff (`rate_insert_backoff`) elapses or windows expire; verified traffic is unaffected |
| `subnet_throttle` | hash + `bpf_timer`, fail closed | same as above (`DROP_THROTTLE_STATE`); sized by `max_throttled_subnets` |
| `global_rate` | hash + `bpf_timer`, fail closed | same as above (`DROP_THROTTLE_STATE`); one bucket for all sources |
| `player_connection_map` | hash | insert failure drops the verification step (`DROP_VERIFY_MAP_FULL`); the connection falls back to the tracked path |
| `udp_throttle` | hash, fail closed | the UDP packet is dropped as `DROP_RATE_STATE` instead of being tracked |
| `rule_rates` | hash, fail closed | rule-matched packets are dropped as `DROP_RATE_STATE` (fail closed keeps a rate rule honest) |
| `verified_sources` | hash | voice packets are dropped (`DROP_VOICE_UNVERIFIED`) until a login refreshes the map; Java traffic is unaffected |
| `talkers_map` | LRU hash | least-active talkers are recycled; only the metrics/ML sampling loses detail |
| `egress_flows` | LRU hash | the oldest flow's pinhole is forgotten; the flow re-establishes on its next outbound packet |
| `autoblock_map` | LRU hash | an armed block can be evicted early, i.e. the source gets unblocked sooner |
| `blocklist_map` / `allowlist_map` | LPM trie | the loader refuses to load more entries than configured (a too-large file is an error, not a truncation) |

Sizing guidance and the advisor that checks it are in `docs/deployment.md` §5;
`sizing` warnings tell you which map is under-provisioned. Deliberate choice:
under pressure, *unverified* traffic is sacrificed so verified players keep
playing.

### T8 — Spoofing an allowlisted source

If an attacker spoofs an allowlisted IP, it bypasses everything. This is
irreducible without upstream source-address validation; the filter therefore
records allowlisted passes (`minecraft_allowlist_entries`, `ALLOWLIST_PASS`
statistics bit) so operators can see unexpected volume. Only allowlist
addresses whose traffic cannot be spoofed (same-LAN with uRPF, provider-
filtered ranges).

### T9 — IPv6, UDP (Bedrock/RakNet, Simple Voice Chat), other protocols

- **IPv6** is inspected by the same state machine as IPv4 (`minecraft_ipv6_packets`
  counts it): same parsers, same per-source/subnet limits, same verified fast
  path. IPv6 fragments aimed at an inspected port are dropped
  (`DROP_IPV6_FRAGMENT`), the IPv4 equivalent is `DROP_IP_FRAGMENT`.
- **Bedrock/RakNet** (`[bedrock] enabled = true`) gets stateless offline
  handshake validation (`DROP_BEDROCK_INVALID`), an opt-in strict protocol/MTU
  window for operators who know their clients, and the stateful pinhole for
  everything else (`DROP_BEDROCK_UNTRACKED`) — connected RakNet traffic is
  version-dependent and encrypted, so guessing at its shape would break forks.
- **Simple Voice Chat** (`[voice] enabled = true`) validates only the packet
  type/shape and then requires that the source IP has a verified Java login
  (`DROP_VOICE_UNVERIFIED`, `DROP_VOICE_INVALID`), which is what ties voice
  traffic to real players.
- **Everything else** passes untouched *unless* the operator configures rules
  or `[ingress] default_deny = true`; then unmatched flows are dropped as
  `DROP_UNSOLICITED`/`DROP_PROTO_DENY` and ports are opened either statically
  (`open_tcp_ports`/`open_udp_ports`/`[[rules]]`) or dynamically by the
  egress-tracked stateful pinhole.

The residual risk here is configuration, not parsing: enabling a protocol you
do not actually run, or a strict version window that your clients fall outside
of, will drop legitimate traffic. Both are opt-in and both are exercised by the
netns e2e test (`tests/e2e_traffic.py`).

### T10 — Loader crash / OOM / manual stop

Dropping the loader detaches the program: the filter fails **open**. Mitigate
with systemd (`Restart=always`, `RestartSec=1`) and alerting on the
`minecraft_*` series disappearing. A crash loop means unprotected but running
service, which is the safer direction for a game server.

### T11 — Misconfiguration (dry run left on, private sources off/on)

- `dry_run` is visible as the `minecraft_dry_run` gauge and as would-drop
  metrics named `minecraft_would_drop_reason`; the loader logs a warning at
  startup.
- `drop_private_sources` defaults to `false` so same-host proxies and LAN
  monitoring keep working; turning it on can cut off legitimate infrastructure —
  check `minecraft_drop_reason{reason="private_source"}` first (in dry run).

### T12 — The auto-blocker and the ML scorer as a self-inflicted outage

Escalating blocks and the optional ML enforcement are the two controls that
can take out a *legitimate* source, so both are layered:

- The auto-blocker only arms on enabled per-source limits (a banned source
  needs repeated violations; subnet/global drops do not strike), with
  `strike_threshold`, a base/doubling/max TTL and decay; every armed block is
  exported to `blocklist_export_file` with its reason and strike count.
- Verify it before trusting it: run with the export file pointed at a test
  path, watch `minecraft_autoblock_entries`, and confirm your monitoring
  ranges are in the allowlist. An allowlisted source is never struck.
- The ML scorer is `mode = "shadow"` by default (it logs and exports
  `minecraft_ml_top_score`, it never blocks), trains only on this host's own
  labels, and in `enforce` mode is bounded by the same block/TTL machinery.
  Treat it as a hint and watch `minecraft_ml_blocks_total` before arming.
- **Residual**: a shared NAT (school, cafe, hosting proxy) that trips the
  per-source limit will have its *whole* address blocked. That is the correct
  tradeoff for a game server vs. a distributed flood, but it is why the
  allowlist, the strike counters and the dry-run of both systems exist; the
  e2e test asserts the block is exported (`tests/e2e_loader.sh`).

### T13 — Post-handshake packet flood on a verified connection

A client that passed the handshake can still spam the play state (swing
packets, chat spam, oversized packet floods) — by design the verified fast
path does not parse those packets, because the play protocol is where forks
and mods differ the most. Controls, in increasing order of intervention:

1. **Visibility**: `talkers_map` samples per-source packet/byte rates and the
   ML scorer (shadow) flags sources whose rate/drop/SYN profile stands out.
2. **Per-flow abuse cap** (opt-in, `verified_pps_limit`/`verified_bps_limit`):
   above the configured per-second budget the *packets* on that one flow are
   dropped (`DROP_MC_PACKET_RATE`) while the flow stays verified, so a
   legitimate burst (chunk loading, a plugin push) recovers by itself in the
   next window and never triggers a strike/auto-block.
3. **Application level**: Paper's packet limits, per-player chat/reach
   plugins, and a real anticheat — the filter cannot see into the encrypted
   play stream, so this is where the actual work belongs.

The cap is off by default (`0`) and refuses values below a sane floor
(50 pkt/s, 4 kB/s) so it can not be configured to fight normal gameplay; the
e2e `verified_packet_flood` stage proves the drop and the `flooder` login
proves valid traffic is only capped, not disconnected.

## 5. Assumptions

- Linux ≥ 5.15 with BTF (for `bpf_timer`), root/CAP_BPF+CAP_NET_ADMIN to load.
- The loader runs on the same host and is restarted by systemd.
- The protected Minecraft application additionally implements the protocol
  checks it needs; the filter is a shield, not a replacement for a patched
  server.
- Prometheus scraping, if enabled, is reachable from the monitoring host.

## 6. Explicit non-goals

- Absorbing volumetric floods (upstream job).
- **By default**, protecting ports and protocols the operator did not
  configure: only the configured Java range (plus opt-in Bedrock, voice and
  rules) is inspected. The rule engine and `[ingress] default_deny` exist to
  extend that coverage, but they are opt-in on purpose — turning them on
  without testing will drop legitimate traffic.
- Filtering *egress* to other services: the `tc egress` hook exists to record
  flow state for the inbound pinhole, not to police what the host sends. Anti-
  reflection/anti-spoofing on egress is an upstream job.
- Antivirus-like payload inspection: the filter validates *framing*, not
  content (it never decrypts anything).
- Authenticating players or judging identity: XDP sees packets, not Mojang
  sessions. The ML scorer is a traffic-shape heuristic and never a proof.
