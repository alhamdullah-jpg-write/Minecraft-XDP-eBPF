#ifndef CONFIG_H
#define CONFIG_H

#include <linux/types.h>

/*
 * Runtime configuration.
 *
 * The Rust loader patches these values into the BPF .rodata section via
 * aya's override_global() (with must_exist) before the program is loaded,
 * so all of them are always overridden; the zeros are only placeholders.
 * The types must match the override_global() calls in loader/ebpf.rs
 * exactly. Loaded standalone (without the loader), the all-zero config
 * filters nothing.
 *
 * Every flag below is `volatile const`: the loader decides the value at
 * load time, and the compiled code contains the feature but never takes
 * the branch when the feature is off. Limits that have to change at
 * runtime (auto-tuning) live in the tunables map (see maps.h) instead.
 *
 * Defining (not just declaring) these in a header is safe because the BPF
 * program is a single translation unit; the test build replaces this
 * header entirely via its include guard.
 */

/* ------------------------------------------------------------------ */
/* core filter                                                          */
/* ------------------------------------------------------------------ */

volatile const __u8 PROMETHEUS = 0;            // collect statistics in stats_map
volatile const __u8 ONLINE_NAMES = 0;          // enforce online-mode usernames (max 16 chars)
volatile const __u8 DRY_RUN = 0;               // count would-be drops but pass the packets instead
volatile const __u8 DROP_RESERVED_SOURCES = 0; // drop 0/8, 169.254/16, 224/4, 240/4 sources
volatile const __u8 DROP_PRIVATE_SOURCES = 0;  // also drop RFC1918, loopback and CGNAT sources
volatile const __u8 ALLOWLIST_ENABLED = 0;     // consult allowlist_map for filtered traffic
volatile const __u32 START_PORT = 0;          // first TCP port of the inspected range (inclusive)
volatile const __u32 END_PORT = 0;            // last TCP port of the inspected range (inclusive)
volatile const __u64 PLAYER_IDLE_NS = 0;      // idle check interval for verified connections in nanoseconds;
                                              // entries are removed after one to two intervals without packets

/* ------------------------------------------------------------------ */
/* rate limiting + auto-tuning (limits live in the tunables map)        */
/* ------------------------------------------------------------------ */

// master switch for the per-source/subnet/global rate limit code paths.
// When off, no limit is ever read and the throttle maps stay empty.
volatile const __u8 RATE_LIMITS_ENABLED = 0;

// master switch for the blocklist/auto-block code paths (see blocklist.h)
volatile const __u8 BLOCKLIST_ENABLED = 0;     // consult the operator blocklist (LPM, CIDRs)
volatile const __u8 AUTOBLOCK_ENABLED = 0;     // kernel inserts auto-blocks on repeated violations

/* ------------------------------------------------------------------ */
/* egress state tracking (tc program) + ingress default-deny            */
/* ------------------------------------------------------------------ */

// the ingress program consults the egress flow map as a pinhole: replies
// to flows the host itself sent are punched through, everything else on
// non-open ports is dropped by default_deny.
volatile const __u8 EGRESS_TRACK_ENABLED = 0;
volatile const __u8 DEFAULT_DENY = 0;          // drop untracked ports/protocols (see rules)
volatile const __u64 EGRESS_TIMEOUT_NS = 0;    // pinhole idle lifetime in nanoseconds
volatile const __u64 EGRESS_WINDOW_NS = 0;     // reserved: sequence check slack (kept for api stability)
volatile const __u8 ICMP_MODE = 0;             // 0 allow everything, 1 smart (errors + tracked echo), 2 drop

/* ------------------------------------------------------------------ */
/* rule engine (ports/protocols outside the minecraft range)            */
/* ------------------------------------------------------------------ */

volatile const __u8 RULES_ENABLED = 0;         // consult rule_map for non-minecraft traffic

/* ------------------------------------------------------------------ */
/* top talkers (sampled per-source counters, read by the loader/ML)     */
/* ------------------------------------------------------------------ */

volatile const __u8 TALKERS_ENABLED = 0;
volatile const __u32 TALKER_SAMPLE_MASK = 0;   // 2^n - 1: sample one packet in (mask+1)

/* ------------------------------------------------------------------ */
/* bedrock (raknet) udp path                                            */
/* ------------------------------------------------------------------ */

volatile const __u8 BEDROCK_ENABLED = 0;
volatile const __u32 BEDROCK_PORT = 0;              // host byte order
volatile const __u8 BEDROCK_STRICT_VERSION = 0;     // enforce protocol version range below
volatile const __u32 BEDROCK_PROTO_MIN = 0;         // inclusive, only read in strict mode
volatile const __u32 BEDROCK_PROTO_MAX = 0;         // inclusive, only read in strict mode
volatile const __u32 BEDROCK_MTU_MIN = 0;           // plausible raknet mtu lower bound
volatile const __u32 BEDROCK_MTU_MAX = 0;           // plausible raknet mtu upper bound

/* ------------------------------------------------------------------ */
/* simple voice chat udp path                                           */
/* ------------------------------------------------------------------ */

volatile const __u8 VOICE_ENABLED = 0;
volatile const __u32 VOICE_PORT = 0;                // host byte order
volatile const __u8 VOICE_REQUIRE_VERIFIED = 0;     // source ip must have a verified java connection
volatile const __u32 VOICE_MAX_TYPE = 0;            // shape bound for the first payload byte

/* ------------------------------------------------------------------ */
/* verified source ip map (feeds the voice gate and the ML labels)      */
/* ------------------------------------------------------------------ */

volatile const __u8 VERIFIED_SOURCES_ENABLED = 0;
volatile const __u64 VERIFIED_SOURCES_TTL_NS = 0;   // entry lifetime, refreshed while playing

/* ------------------------------------------------------------------ */
/* abuse caps                                                           */
/* ------------------------------------------------------------------ */

// drop a PROXY protocol header (v1 "PROXY ..." / the v2 signature) seen at
// the start of a connection on an inspected port. A real proxy in front of
// the filter is allowlisted and never reaches the check, so the only
// source of these bytes is a client trying to poison a backend that trusts
// forwarding headers. See looks_like_proxy_header() in protocol.h.
volatile const __u8 REJECT_PROXY_HEADER = 0;

// per-connection abuse cap on the *verified* fast path, in packets and
// bytes per rate window (window_ms in the tunables map). 0 = off. Sized
// well above real client rates: this catches post-handshake packet floods
// (spam bots which passed the handshake) without touching normal play.
volatile const __u32 VERIFIED_PPS_LIMIT = 0;
volatile const __u32 VERIFIED_BPS_LIMIT = 0;

#endif
