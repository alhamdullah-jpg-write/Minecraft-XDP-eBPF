#ifndef STATS_H
#define STATS_H

#include <linux/types.h>

#include "config.h"

// selects which statistics count_stats() increments; a bitmask so related
// counters can be bumped in one call (e.g. DROPPED_PACKET | DROPPED_BYTES)
enum stats_mask
{
    VERIFIED          = 1u << 0,
    DROPPED_PACKET    = 1u << 1,
    STATE_SWITCH      = 1u << 2,
    DROP_CONNECTION   = 1u << 3,
    SYN_RECEIVE       = 1u << 4,
    TCP_BYPASS        = 1u << 5,
    INCOMING_BYTES    = 1u << 6,
    DROPPED_BYTES     = 1u << 7,
    VERIFIED_PACKET   = 1u << 8,
    IPV6_TRAFFIC      = 1u << 9,
    ALLOWLIST_PASS    = 1u << 10,
};

/*
 * Why a packet was dropped, one counter per reason in stats_map. The values
 * double as the index into `struct statistics.reason[]` and MUST stay in
 * sync with the `DROP_REASONS` name list in loader/metrics.rs (the loader
 * publishes them as the `reason` label of minecraft_drop_reason).
 *
 * DROP_EMPTY_ACK is the one expected reason: the filter always drops the
 * empty ACK that finishes the TCP handshake, so a healthy server sees a
 * boring stream of them in dry-run/debug output.
 */
enum drop_reason
{
    DROP_ETH_MALFORMED     = 0,  // frame shorter than the ethernet header / bad vlan tag
    DROP_IP_MALFORMED      = 1,  // bad version, ihl, or ip total length
    DROP_IP_FRAGMENT       = 2,  // first fragment towards a filtered port
    DROP_TCP_MALFORMED     = 3,  // tcp header truncated or doff < 5
    DROP_RESERVED_SOURCE   = 4,  // 0/8, 169.254/16, multicast, reserved
    DROP_PRIVATE_SOURCE    = 5,  // rfc1918, loopback, cgnat (optional)
    DROP_TCP_FLAGS         = 6,  // flags that clients never send
    DROP_SYN_PAYLOAD       = 7,  // SYN carrying data (tcp fast open)
    DROP_THROTTLE_LIMIT    = 8,  // per-ip SYN window exceeded
    DROP_THROTTLE_STATE    = 9,  // throttle map full / insert or timer failure
    DROP_TRACK_STATE       = 10, // conntrack insert failed (lru map full)
    DROP_NOT_TRACKED       = 11, // no state for this flow (ack/rst/fin flood)
    DROP_BAD_ACK           = 12, // payload without ACK mid-handshake
    DROP_SEQUENCE_MISMATCH = 13, // retransmission or out-of-order packet
    DROP_OUT_OF_ORDER_LIMIT= 14, // too many mismatches, whole connection dropped
    DROP_HANDSHAKE_INVALID = 15, // minecraft handshake packet invalid
    DROP_LEGACY_PING       = 16, // pre-1.7 ping (0xFE)
    DROP_STATUS_INVALID    = 17, // status request packet invalid
    DROP_PING_INVALID      = 18, // ping request packet invalid
    DROP_LOGIN_INVALID     = 19, // login start packet invalid
    DROP_PING_EXTRA        = 20, // more data after a finished ping flow
    DROP_EMPTY_ACK         = 21, // the expected drop of the empty final ACK
    DROP_EMPTY_SEGMENT     = 22, // empty segment while the handshake is pending
    DROP_VERIFY_FAILED     = 23, // player map insert or timer setup failed
    DROP_VERIFY_MAP_FULL   = 24, // player map exhausted (raise max_player_connections)
};

// size of `struct statistics.reason[]`; power of two so the index can be
// masked (the verifier needs a provably in-bounds array index)
#define DROP_REASON_SLOTS 32

// one per-cpu slot of stats_map; must match `Statistics` in loader/metrics.rs
struct statistics
{
    __u64 verified;          // connections promoted to the verified fast path
    __u64 verified_packets;  // packets passed on the verified fast path
    __u64 dropped_packets;
    __u64 state_switches;
    __u64 drop_connection;
    __u64 syn;
    __u64 tcp_bypass;
    __u64 incoming_bytes;    // frame bytes on the filtered ports
    __u64 dropped_bytes;     // frame bytes dropped
    __u64 ipv6_packets;      // not filtered, counted so the gap is visible
    __u64 reason[DROP_REASON_SLOTS];
};
_Static_assert(sizeof(struct statistics) == 336, "statistics size mismatch!");

/*
 * Adds `amount` to every counter selected by `bitmask`.
 *
 * stats_ptr is NULL whenever metrics are disabled (get_stats() returns NULL
 * and the compiler prunes this entire function at load time because
 * PROMETHEUS is a known constant). The bitmasks are compile-time constants
 * at every call site, so each call reduces to the few increments that are
 * actually selected.
 */
static __always_inline void count_stats(struct statistics *stats_ptr, const __u32 bitmask, const __u64 amount)
{
    if (!stats_ptr)
    {
        return;
    }

    if (bitmask & INCOMING_BYTES)
    {
        stats_ptr->incoming_bytes += amount;
    }

    if (bitmask & DROPPED_BYTES)
    {
        stats_ptr->dropped_bytes += amount;
    }

    if (bitmask & VERIFIED)
    {
        stats_ptr->verified += amount;
    }

    if (bitmask & VERIFIED_PACKET)
    {
        stats_ptr->verified_packets += amount;
    }

    if (bitmask & DROPPED_PACKET)
    {
        stats_ptr->dropped_packets += amount;
    }

    if (bitmask & STATE_SWITCH)
    {
        stats_ptr->state_switches += amount;
    }

    if (bitmask & DROP_CONNECTION)
    {
        stats_ptr->drop_connection += amount;
    }

    if (bitmask & SYN_RECEIVE)
    {
        stats_ptr->syn += amount;
    }

    if (bitmask & TCP_BYPASS)
    {
        stats_ptr->tcp_bypass += amount;
    }

    if (bitmask & IPV6_TRAFFIC)
    {
        stats_ptr->ipv6_packets += amount;
    }
}

#endif
