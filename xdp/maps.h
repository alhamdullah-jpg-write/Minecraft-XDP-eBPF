#ifndef MAPS_H
#define MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "config.h"
#include "flow.h"
#include "stats.h"

/*
 * Every BPF map of the object, in one place: the ingress XDP program and
 * the egress tc program share all of them, and the inline logic headers
 * (rate.h, blocklist.h, ...) reference these maps by name.
 *
 * The max_entries values are placeholders; the loader overrides each one
 * via map_max_entries() before the program is loaded. The placeholder
 * sizes are the documented defaults.
 *
 * Per-source state is deliberately spread over per-cpu structures or
 * keyed hashes: there is no global counter on the packet path, only
 * per-entry atomics and node-local stats.
 */

/* --------------------------------------------------------------------- */
/* runtime-tunable limits (auto-tune writes these at runtime)              */
/* --------------------------------------------------------------------- */

/*
 * Sliding-window limits, all in the single window below. The auto-tuner
 * updates this map from userspace; the packet path only reads it (one
 * pointer for the whole packet).
 *
 * window_ms must stay <= 4000: the sliding estimate multiplies the
 * previous window's counter with the remaining nanoseconds, and both have
 * to fit in u64/u32 respectively (see rate.h).
 */
struct tunables
{
    __u32 host_limit;       // per-source new-connection limit per window (0 disables)
    __u32 subnet_limit;     // per-subnet (/24 v4, /64 v6) new-connection limit (0 disables)
    __u32 global_limit;     // host-wide new-connection limit per window (0 disables)
    __u32 udp_limit;        // per-source udp packet limit on the bedrock/voice ports (0 disables)
    __u32 rule_limit;       // fallback per-source limit for rate rules without max_rate
    __u32 window_ms;        // sliding window length, capped at 4000 by the loader
    __u32 strike_threshold; // violations before an auto-block starts (0 disables auto-block)
    __u32 block_base_ttl_s; // first auto-block duration
    __u32 block_max_ttl_s;  // auto-block duration ceiling
    __u32 strike_decay_s;   // idle time after which strikes are forgotten
};
_Static_assert(sizeof(struct tunables) == 40, "tunables size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunables);
} tunables_map SEC(".maps");

/* --------------------------------------------------------------------- */
/* statistics                                                              */
/* --------------------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
} stats_map SEC(".maps");

/*
 * Returns the current cpu's statistics slot, or NULL when metrics are off.
 * Index 0 of a per-cpu array always exists, so a NULL return only happens
 * when PROMETHEUS is off and every caller folds away.
 */
static __always_inline struct statistics *get_stats(void)
{
    if (!PROMETHEUS)
    {
        return NULL;
    }
    const __u32 zero = 0;
    return bpf_map_lookup_elem(&stats_map, &zero);
}

// the tunables slot always exists; NULL is only possible before the map is
// created (never at runtime) and is handled defensively by the callers
static __always_inline struct tunables *get_tunables(void)
{
    const __u32 zero = 0;
    return bpf_map_lookup_elem(&tunables_map, &zero);
}

/* --------------------------------------------------------------------- */
/* rate limiting                                                           */
/* --------------------------------------------------------------------- */

/*
 * One sliding window per key: a bpf_timer rotates `prev` <- `cur` every
 * window, the packet path only increments `cur` with a per-entry atomic.
 * The current rate is estimated as
 *
 *     cur + prev * (window - elapsed) / window
 *
 * which is the standard sliding-window-counter approximation and removes
 * the 2x burst a plain fixed window allows at the window boundary.
 */
struct rate_entry
{
    struct bpf_timer timer;
    __u64 window_ns;      // configured window (re-read on rotation)
    __u64 last_rotate_ns; // start of the current window
    __u32 cur;            // events in the current window
    __u32 prev;           // events in the previous window
};
_Static_assert(sizeof(struct rate_entry) == 40, "rate_entry size mismatch!");

// per-source new-connection (SYN) window. Plain HASH on purpose (no LRU):
// during a big attack the map fills up, inserts fail and ALL new
// connections from unknown sources are dropped while entries keep expiring
// through their timers. Capacity recovers in-kernel.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535); // [xdp] max_throttled_ips
    __type(key, struct host_key);
    __type(value, struct rate_entry);
} host_throttle SEC(".maps");

// per-subnet window (/24 for v4, /64 for v6): one abusive /24 with a /32
// per-source limit still gets its share, this bounds the whole block
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384); // [xdp] max_throttled_subnets
    __type(key, struct host_key);
    __type(value, struct rate_entry);
} subnet_throttle SEC(".maps");

// host-wide admission window for new connections: during a volumetric
// flood this keeps the verified fast path open while new work is shed
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_entry);
} global_rate SEC(".maps");

// per-source, per-rule packet window for rate-limit rules
struct rule_rate_key
{
    struct host_key host;
    __u32 rule_id;
};
_Static_assert(sizeof(struct rule_rate_key) == 24, "rule_rate_key size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384); // [xdp] max_rule_rate_entries
    __type(key, struct rule_rate_key);
    __type(value, struct rate_entry);
} rule_rates SEC(".maps");

// per-source udp packet window for the bedrock/voice ports
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535); // [xdp] max_throttled_ips
    __type(key, struct host_key);
    __type(value, struct rate_entry);
} udp_throttle SEC(".maps");

// while a preallocated rate map is full, only retry inserting after this
// long (per core): a failed insert on a full map scans every cpu's
// freelist under spinlocks, so during that time new keys are rejected
// without paying for another doomed insert attempt
#define RATE_BACKOFF_NS (100ULL * 1000000ULL) // 100ms

enum backoff_slot
{
    BACKOFF_HOST = 0,
    BACKOFF_SUBNET = 1,
    BACKOFF_RULE = 2,
    BACKOFF_UDP = 3,
    BACKOFF_SLOTS = 4,
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, BACKOFF_SLOTS);
    __type(key, __u32);
    __type(value, __u64); // per-cpu: no insert retry before this ktime
} rate_insert_backoff SEC(".maps");

/* --------------------------------------------------------------------- */
/* connection tracking                                                     */
/* --------------------------------------------------------------------- */

// per-connection tracking data while the handshake sequence is inspected
struct initial_state
{
    __u16 state;    // enum connection_state; u16 to keep the struct padding-free
    __u16 fails;    // out-of-order packets seen so far (see MAX_OUT_OF_ORDER)
    __s32 protocol; // minecraft protocol version (signed by protocol definition)
    __u32 expected_sequence;
};
_Static_assert(sizeof(struct initial_state) == 12, "initial_state size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384); // [xdp] max_pending_connections
    __type(key, struct flow_key);
    __type(value, struct initial_state);
} conntrack_map SEC(".maps");

static __always_inline struct initial_state gen_initial_state(const __u16 state, const __s32 protocol, const __u32 expected_sequence)
{
    const struct initial_state fresh = {
        .state = state,
        .fails = 0,
        .protocol = protocol,
        .expected_sequence = expected_sequence,
    };
    return fresh;
}

struct player_entry
{
    struct bpf_timer timer; // deletes the entry when the connection goes idle
    __u64 packets;          // incremented for every packet of this flow
    __u64 last_packets;     // snapshot taken by the idle check timer
    __u64 window_start_ns;  // start of the current abuse-cap window (0 = fresh)
    __u64 window_packets;   // packets seen in the current window
    __u64 window_bytes;     // frame bytes seen in the current window
};
_Static_assert(sizeof(struct player_entry) == 56, "player_entry size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535); // [xdp] max_player_connections
    __type(key, struct flow_key);
    __type(value, struct player_entry);
} player_connection_map SEC(".maps");

/*
 * Source addresses that had at least one connection pass the full
 * inspection and get promoted to the player map. The entry is refreshed
 * whenever another connection from the same address verifies and expires
 * by timer, so it stays a coarse "this address demonstrably speaks
 * minecraft" signal (used for the voice gate and as an ML label).
 */
struct verified_entry
{
    struct bpf_timer timer;
    __u64 last_seen_ns;
    __u64 pad;
};
_Static_assert(sizeof(struct verified_entry) == 32, "verified_entry size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384); // [xdp] max_verified_sources
    __type(key, struct host_key);
    __type(value, struct verified_entry);
} verified_sources SEC(".maps");

/* --------------------------------------------------------------------- */
/* egress state tracking (filled by the tc egress program)                 */
/* --------------------------------------------------------------------- */

/*
 * One entry per flow the host has sent traffic on. The ingress program
 * looks up the reverse key: a packet is a "reply" only if the host itself
 * opened or continued that flow recently, which kills the entire class of
 * blind reflection/amplification replies.
 *
 * base_seq/next_seq track the tcp sequence space the host sent (SYN: seq,
 * SYN+1 ... data end): an inbound segment must ack inside [base, next+1].
 * Both are 0 for udp/icmp flows.
 */
struct egress_value
{
    __u64 base_seq;
    __u64 next_seq;
    __u64 last_seen_ns;
    __u32 packets;
    __u32 pad;
};
_Static_assert(sizeof(struct egress_value) == 32, "egress_value size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536); // [xdp] max_egress_flows
    __type(key, struct flow_key);
    __type(value, struct egress_value);
} egress_flows SEC(".maps");

/* --------------------------------------------------------------------- */
/* top talkers (sampled; the loader aggregates/ML-scores them)             */
/* --------------------------------------------------------------------- */

struct talker_entry
{
    __u64 packets;       // sampled packet count
    __u64 bytes;         // sampled frame bytes
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 drops;         // sampled drops
    __u32 syns;          // sampled SYNs
};
_Static_assert(sizeof(struct talker_entry) == 40, "talker_entry size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536); // [xdp] max_talkers
    __type(key, struct host_key);
    __type(value, struct talker_entry);
} talkers_map SEC(".maps");

// per-cpu sample clock; one in TALKER_SAMPLE_MASK+1 packets updates the map
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} talker_sample SEC(".maps");

/* --------------------------------------------------------------------- */
/* allowlist / blocklist                                                   */
/* --------------------------------------------------------------------- */

// exact-match entries use prefixlen 128 over the v4-mapped/v6 address, so
// one trie serves both families (the loader converts v4 CIDRs to ::ffff:)
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024); // [xdp] max_allowlist_entries
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);
} allowlist_map SEC(".maps");

// operator blocklist: CIDRs from a file, permanent or with an expiry
struct block_entry
{
    __u64 expires_ns;     // 0 = permanent
    __u64 last_strike_ns; // last violation that touched this entry
    __u32 strikes;        // escalation level (auto-blocks only)
    __u32 reason;         // drop_reason that created/last escalated the block
};
_Static_assert(sizeof(struct block_entry) == 24, "block_entry size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536); // [xdp] max_blocklist_entries
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, struct block_entry);
} blocklist_map SEC(".maps");

// auto-blocks inserted by the kernel (repeated rate violations); the loader
// prunes expired entries, exports them and can add ML-driven blocks
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536); // [xdp] max_autoblock_entries
    __type(key, struct host_key);
    __type(value, struct block_entry);
} autoblock_map SEC(".maps");

/* --------------------------------------------------------------------- */
/* rule engine                                                             */
/* --------------------------------------------------------------------- */

// key: protocol + destination port (both match exactly)
struct rule_key
{
    __u8 proto;
    __u8 pad;
    __be16 port;
};
_Static_assert(sizeof(struct rule_key) == 4, "rule_key size mismatch!");

enum rule_action
{
    RULE_ACTION_ALLOW = 0, // pass after (optional) checks
    RULE_ACTION_DROP = 1,  // always drop
    RULE_ACTION_RATE = 2,  // per-source packet limit, then pass
};

enum rule_flags
{
    RULE_FLAG_STATEFUL = 1u << 0, // require an egress pinhole
};

/*
 * One declarative rule. The magic check is a masked 8 byte compare at a
 * fixed offset inside the L4 payload (loader builds magic/magic_mask from
 * the hex string) so there is no variable-length loop in the packet path.
 */
struct rule
{
    __u64 magic;      // expected bytes (host order: first payload byte is the low byte)
    __u64 magic_mask; // 0xff per checked byte, 0 for don't-care
    __u32 max_rate;   // per-source packets per window (0 = tunables.rule_limit)
    __u32 rule_id;
    __u16 min_len;    // inclusive bound on the L4 payload length (0 = no bound)
    __u16 max_len;    // 0 = no bound
    __u8 action;      // enum rule_action
    __u8 flags;       // enum rule_flags
    __u8 magic_off;   // offset of the magic inside the L4 payload
    __u8 pad;
};
_Static_assert(sizeof(struct rule) == 32, "rule size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256); // [xdp] max_rules
    __type(key, struct rule_key);
    __type(value, struct rule);
} rule_map SEC(".maps");

#endif
