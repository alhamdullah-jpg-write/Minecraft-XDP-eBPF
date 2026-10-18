# Threat model

Scope: `minecraft-ebpf-xdp` as deployed on a single Minecraft Java host,
filtering IPv4 TCP traffic on the configured port range (default 25565)
between the NIC and the kernel network stack.

This document states what the filter protects, against whom, and — just as
importantly — what it does not protect against. It is written for operators,
not for marketing: every "protected" claim below maps to code in `xdp/`, and
every residual risk has a mitigation section.

## 1. Deployment model

```
 attacker(s)                operator                     protected host
 ──────────                 ────────                     ──────────────
 internet ──▶ upstream router / ISP ──▶ NIC ──▶ [XDP filter] ──▶ kernel TCP/IP
                     │                              │              │
                     │                              │              ▼
                 scrubbing?                    stats_map      Paper / Velocity /
                 uRPF/BCP38?                  (per-cpu)      Geyser / SVC plugin
                                                                  │
                                                              JVM threads
```

Trust boundaries:

| Boundary | Trusted | Untrusted |
|---|---|---|
| Upstream → NIC | nothing | everything: source addresses may be spoofed unless the provider filters them |
| XDP → kernel stack | only packets that passed inspection are *inspected*; everything else on other ports is passed untouched | — |
| XDP → JVM | packets that completed the inspected handshake are forwarded without further filtering | — |
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
| Valid accounts logging in slowly | yes | not stoppable at XDP (no egress visibility, authentication is on Mojang's side) |
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
- Per-source-IP throttle: `connection_throttle` (hash, `bpf_timer`-expired
  windows, default 10 SYNs/3 s per IP). Above the limit, SYNs are dropped in
  the XDP path (`DROP_THROTTLE_LIMIT`).
- Every accepted SYN is tracked in `conntrack_map` (LRU hash) with the expected
  TCP sequence, so junk that never completes the handshake is evicted rather
  than accumulated.
- Backstop: the kernel's SYN cookies / backlog are still there because the
  packets that pass are ordinary TCP.
- **Residual**: fixed-window throttle allows up to 2× the limit across a
  window boundary; GPU-less (spoofed) floods from millions of addresses still
  cost one map insert each (bounded by `max_throttled_ips`, then fail closed —
  see T7).

### T3 — Protocol junk aimed at the backend

Dropped before reaching the JVM: invalid VarInts and truncations
(`xdp/varint.h`, `xdp/protocol.h`), invalid packet IDs/lengths/state
transitions, legacy-ping abuse, non-matching TCP sequences/ACKs
(`DROP_SEQUENCE_MISMATCH`, `DROP_OUT_OF_ORDER_LIMIT`), and empty segments in
states that require the handshake. Only one provably-in-order byte stream
reaches the backend.

### T4 — Handshake/status flood with plausible-looking traffic

Mitigated by the same per-IP throttle plus the requirement that each tracked
connection completes a real handshake to reach the verified fast path. Status
and ping flows are tracked with their own state machine and dropped when they
misbehave (`DROP_STATUS_INVALID`, `DROP_PING_INVALID`, `DROP_PING_EXTRA`).

### T5 — Login/auth spam, "join bots" that are valid players

**Not stoppable here.** Authentication happens between the client and Mojang;
the XDP filter sees only the encrypted/TCP stream. It can rate-limit *new
connections* per IP, but a distributed botnet with one login per IP looks like
normal traffic. Mitigations belong to the application: Velocity/Paper
`connection-throttle`, `max-players`, queue plugins, online-mode, and account
age/UUID checks. The filter's contribution is that the network layer is not the
bottleneck while that happens.

### T6 — Amplification via the server (status/ping)

Status responses and pings are small; the state machine at least prevents using
the server as a reflector for crafted payloads. Upstream egress filtering is
the real control.

### T7 — Exhausting filter state

| Map | Type | Behaviour when full |
|---|---|---|
| `conntrack_map` | LRU hash | least-recently-used half-open flow evicted; the flow's next packet is dropped as `not_tracked` and must restart the handshake |
| `connection_throttle` | hash, fail closed | new SYNs are dropped (`DROP_THROTTLE_STATE`) until the 100 ms per-CPU insert backoff elapses or windows expire; verified traffic is unaffected |
| `player_connection_map` | hash | insert failure drops the verification step (`DROP_VERIFY_MAP_FULL`); the connection falls back to the tracked path |
| `allowlist_map` | LPM trie | loader refuses to load more entries than configured |

Deliberate choice: under pressure, *unverified* traffic is sacrificed so
verified players keep playing.

### T8 — Spoofing an allowlisted source

If an attacker spoofs an allowlisted IP, it bypasses everything. This is
irreducible without upstream source-address validation; the filter therefore
records allowlisted passes (`minecraft_allowlist_entries`, `ALLOWLIST_PASS`
statistics bit) so operators can see unexpected volume. Only allowlist
addresses whose traffic cannot be spoofed (same-LAN with uRPF, provider-
filtered ranges).

### T9 — IPv6, UDP (Bedrock/RakNet, Simple Voice Chat), other protocols

Passed through **unfiltered**; IPv6 is counted
(`minecraft_ipv6_packets`) so this is visible in monitoring. Do not run a
public Bedrock or voice-chat port on a host protected only by this filter
without an upstream filter — see `docs/roadmap.md` for the planned phases.

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

## 5. Assumptions

- Linux ≥ 5.15 with BTF (for `bpf_timer`), root/CAP_BPF+CAP_NET_ADMIN to load.
- The loader runs on the same host and is restarted by systemd.
- The protected Minecraft application additionally implements the protocol
  checks it needs; the filter is a shield, not a replacement for a patched
  server.
- Prometheus scraping, if enabled, is reachable from the monitoring host.

## 6. Explicit non-goals

- Absorbing volumetric floods (upstream job).
- Protecting other services on the host (only the configured TCP port range is
  inspected; everything else is passed).
- Egress filtering/anti-reflection for other services.
- Antivirus-like payload inspection: the filter validates *framing*, not
  content (it never decrypts anything).
