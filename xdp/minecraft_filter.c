/*
 * minecraft_filter - XDP program protecting Minecraft Java Edition servers
 * against L7 (D)DoS attacks.
 *
 * Every TCP packet for the filtered port range runs through a small state
 * machine that validates the TCP handshake and the first Minecraft packets
 * of the connection (handshake, then status+ping or login). Connections that
 * complete the sequence are promoted to a verified fast path and are no
 * longer inspected; everything else is dropped at the driver level. New
 * connections are additionally rate limited per source ip. All map cleanup
 * happens in-kernel via bpf_timer, userspace never has to touch the maps.
 *
 * The program is deliberately IPv4/TCP-only and stateless beyond the maps
 * below; see docs/roadmap.md for the IPv6/UDP plan. Every drop path goes
 * through drop_verdict() (stats.h), which counts a per-reason counter and
 * can turn the whole program into a dry-run tap that passes all traffic.
 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/time.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "config.h"
#include "protocol.h"
#include "stats.h"

// fragment bits of iphdr->frag_off (kernel-internal net/ip.h, not uapi)
#ifndef IP_MF
#define IP_MF 0x2000 // flag: "more fragments"
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF // "fragment offset" part
#endif

/* ------------------------------------------------------------------------
 * Connection tracking of unverified connections
 * --------------------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);          // placeholder, set by the loader ([xdp] max_pending_connections)
    __type(key, struct ipv4_flow_key);   // flow key
    __type(value, struct initial_state); // inspection state machine data
} conntrack_map SEC(".maps");

/* ------------------------------------------------------------------------
 * Verified connections (players)
 * --------------------------------------------------------------------- */

struct player_entry
{
    struct bpf_timer timer; // deletes the entry when the connection goes idle
    __u64 packets;          // incremented for every packet of this flow
    __u64 last_packets;     // snapshot taken by the idle check timer
};
_Static_assert(sizeof(struct player_entry) == 32, "player_entry size mismatch!");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);         // placeholder, set by the loader ([xdp] max_player_connections)
    __type(key, struct ipv4_flow_key);  // flow key
    __type(value, struct player_entry); // idle timer + packet counter
} player_connection_map SEC(".maps");

/*
 * bpf_timer callback: delete the verified connection if it was idle for a
 * full interval, otherwise snapshot the counter and check again next interval
 */
static __s32 player_connection_idle_check(void *map, struct ipv4_flow_key *key, struct player_entry *entry)
{
    const __u64 packets = entry->packets;
    if (packets == entry->last_packets)
    {
        bpf_map_delete_elem(map, key);
        return 0;
    }
    entry->last_packets = packets;
    // re-arming can only fail if this entry is concurrently being freed (map
    // delete/teardown NULLs the timer under its lock); then there is nothing
    // left to re-arm, so the result is deliberately ignored
    bpf_timer_start(&entry->timer, PLAYER_IDLE_NS, 0);
    return 0;
}

/* ------------------------------------------------------------------------
 * Per-ip connection throttle
 * --------------------------------------------------------------------- */

struct throttle_entry
{
    struct bpf_timer timer; // deletes the entry when the window expires
    __u32 hits;             // SYNs counted within the current window
    __u32 pad;
};
_Static_assert(sizeof(struct throttle_entry) == 24, "throttle_entry size mismatch!");

struct
{
    // plain HASH on purpose (no LRU): during a big attack the map fills up,
    // inserts fail and ALL unverified traffic is dropped; only verified
    // connections keep passing. Capacity recovers in-kernel as the per-entry
    // timers fire and delete the expired windows.
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);           // placeholder, set by the loader ([xdp] max_throttled_ips)
    __type(key, __u32);                   // ipv4 source address
    __type(value, struct throttle_entry); // window timer + hit counter
} connection_throttle SEC(".maps");

// while connection_throttle is full, only retry inserting after this long
// (per core): a failed insert on a full preallocated map scans every cpu's
// freelist under spinlocks, so during that time we drop without even trying
#define THROTTLE_BACKOFF_NS (100ULL * 1000000ULL) // 100ms

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); // per-cpu: no insert retry before this ktime
} throttle_insert_backoff SEC(".maps");

/*
 * bpf_timer callback: the throttle window of this ip is over. Entries that
 * saw SYNs during the window are recycled (counter reset, timer re-armed) so
 * repeat senders cause no map/timer churn; entries that were idle for the
 * whole window are deleted.
 */
static __s32 throttle_window_expired(void *map, __u32 *key, struct throttle_entry *entry)
{
    if (__sync_lock_test_and_set(&entry->hits, 0) == 0)
    {
        bpf_map_delete_elem(map, key);
        return 0;
    }
    // re-arming can only fail if this entry is concurrently being freed (map
    // delete/teardown NULLs the timer under its lock); then there is nothing
    // left to re-arm, so the result is deliberately ignored
    bpf_timer_start(&entry->timer, HIT_COUNT_RESET_NS, 0);
    return 0;
}

/* ------------------------------------------------------------------------
 * Allowlist (trusted sources that skip all inspection)
 * --------------------------------------------------------------------- */

// lpm trie key: prefix length + network-order address (matches aya's LpmTrie
// Key<u32> layout on the loader side)
struct lpm_key_v4
{
    __u32 prefixlen;
    __u32 addr;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024); // placeholder, set by the loader ([xdp] max_allowlist_entries)
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, __u8);
} allowlist_map SEC(".maps");

/* ------------------------------------------------------------------------
 * Statistics (only used when PROMETHEUS is enabled, see stats.h)
 * --------------------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
} stats_map SEC(".maps");

/*
 * Returns the current cpu's statistics slot, or NULL when metrics are off
 * (the compiler removes every caller in that case because PROMETHEUS is a
 * known constant).
 */
static __always_inline struct statistics *get_stats(void)
{
    if (!PROMETHEUS)
    {
        return NULL;
    }
    const __u32 zero = 0;
    // index 0 of a per-cpu array always exists; a NULL return is impossible
    // in practice and handled defensively by count_stats()/drop_verdict()
    return bpf_map_lookup_elem(&stats_map, &zero);
}

/*
 * Single exit point of every drop decision: accounts the drop (packets,
 * bytes, reason) and returns the verdict. In dry-run mode the packet is
 * passed instead of dropped, which is how rules can be validated against
 * live traffic before they are allowed to drop anything.
 *
 * `reason` is one of enum drop_reason; the mask keeps the array index
 * provably in bounds for the verifier (DROP_REASON_SLOTS is a power of two)
 * and is folded away by the compiler wherever the reason is a constant.
 */
static __always_inline __s32 drop_verdict(struct statistics *stats_ptr, const __u64 raw_packet_len, const __u32 reason)
{
    if (!stats_ptr)
    {
        stats_ptr = get_stats();
    }
    if (stats_ptr)
    {
        stats_ptr->dropped_packets++;
        stats_ptr->dropped_bytes += raw_packet_len;
        stats_ptr->reason[reason & (DROP_REASON_SLOTS - 1)]++;
    }
    return DRY_RUN ? XDP_PASS : XDP_DROP;
}

/* ------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

// vlan tag header; the uapi if_vlan.h only forward-declares this
struct vlan_tag_hdr
{
    __be16 tci;
    __be16 encapsulated_proto;
} __attribute__((packed));
_Static_assert(sizeof(struct vlan_tag_hdr) == 4, "vlan_tag_hdr size mismatch!");

// parses one optional 802.1q/802.1ad tag: advances l3 past it, updates the
// inner ethertype. Unrolled twice by the caller (double tagging). Without
// this an attacker that can deliver tagged frames would bypass the whole
// filter: the kernel strips the tag and hands the tcp packet to the server.
#define PARSE_VLAN_TAG(l3, proto, dend)                                          \
    do                                                                           \
    {                                                                            \
        if ((proto) == bpf_htons(ETH_P_8021Q) ||                                 \
            (proto) == bpf_htons(ETH_P_8021AD))                                  \
        {                                                                        \
            const struct vlan_tag_hdr *_tag = (const struct vlan_tag_hdr *)(l3); \
            if ((const void *)(_tag + 1) > (const void *)(dend))                 \
            {                                                                    \
                goto drop;                                                       \
            }                                                                    \
            (proto) = _tag->encapsulated_proto;                                  \
            (l3) += sizeof(struct vlan_tag_hdr);                                 \
        }                                                                        \
    } while (0)

/*
 * The connection passed the full inspection sequence: move it from the
 * conntrack map into the player map so its packets skip inspection from now
 * on, and arm the idle timer that will eventually clean the entry up.
 */
static __always_inline __s32 switch_to_verified(const __u64 raw_packet_len, struct statistics *stats_ptr, const struct ipv4_flow_key *flow_key)
{
    bpf_map_delete_elem(&conntrack_map, flow_key);
    const struct player_entry fresh = {.packets = 1, .last_packets = 0};
    const long err = bpf_map_update_elem(&player_connection_map, flow_key, &fresh, BPF_NOEXIST);
    if (err < 0)
    {
        if (err == -EEXIST)
        {
            // another cpu promoted this flow first, or an entry from an
            // earlier connection with the same 4-tuple is still around:
            // either way the flow is on the verified fast path already, so
            // this packet must pass
            count_stats(stats_ptr, VERIFIED_PACKET, 1);
            return XDP_PASS;
        }
        return drop_verdict(stats_ptr, raw_packet_len, err == -E2BIG ? DROP_VERIFY_MAP_FULL : DROP_VERIFY_FAILED);
    }
    struct player_entry *entry = bpf_map_lookup_elem(&player_connection_map, flow_key);
    if (!entry)
    {
        return drop_verdict(stats_ptr, raw_packet_len, DROP_VERIFY_FAILED);
    }
    if (bpf_timer_init(&entry->timer, &player_connection_map, CLOCK_MONOTONIC) < 0 ||
        bpf_timer_set_callback(&entry->timer, player_connection_idle_check) < 0 ||
        bpf_timer_start(&entry->timer, PLAYER_IDLE_NS, 0) < 0)
    {
        // never leak an entry that has no idle timer armed
        bpf_map_delete_elem(&player_connection_map, flow_key);
        return drop_verdict(stats_ptr, raw_packet_len, DROP_VERIFY_FAILED);
    }
    count_stats(stats_ptr, VERIFIED, 1);
    count_stats(stats_ptr, VERIFIED_PACKET, 1);
    return XDP_PASS;
}

/* ------------------------------------------------------------------------
 * XDP entry point
 * --------------------------------------------------------------------- */

SEC("xdp")
__s32 minecraft_filter(struct xdp_md *ctx)
{
    const void *data = (const void *)(long)ctx->data;
    const void *data_end = (const void *)(long)ctx->data_end;

    // frame length for the byte counters; needed on every exit path, so it
    // is computed once up front (pure register arithmetic)
    const __u64 raw_packet_len = (__u64)(data_end - data);

    // reason recorded when bailing out through the shared drop exit; the
    // initial value covers the earliest malformed-frame exits
    __u32 drop_reason = DROP_ETH_MALFORMED;
    struct statistics *stats_ptr = NULL;

    /* ---------------- layer 2 ---------------- */

    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end)
    {
        goto drop;
    }

    const __u8 *l3 = data + sizeof(struct ethhdr);
    __be16 l3_proto = eth->h_proto;
    PARSE_VLAN_TAG(l3, l3_proto, data_end);
    PARSE_VLAN_TAG(l3, l3_proto, data_end);

    if (l3_proto != bpf_htons(ETH_P_IP))
    {
        if (l3_proto == bpf_htons(ETH_P_IPV6))
        {
            // IPv6 is not inspected by this program (see README): count it,
            // so an operator with a dual-stack host sees that traffic is
            // passing the filter unprotected
            count_stats(get_stats(), IPV6_TRAFFIC, 1);
        }
        return XDP_PASS;
    }

    /* ---------------- layer 3 ---------------- */

    const struct iphdr *ip = (const struct iphdr *)l3;
    if ((const void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
    {
        drop_reason = DROP_IP_MALFORMED;
        goto drop;
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    const __u32 ip_hdr_len = ip->ihl * 4;
    if ((const void *)ip + ip_hdr_len > data_end)
    {
        drop_reason = DROP_IP_MALFORMED;
        goto drop;
    }

    // non-first fragments (fragment offset != 0) carry no tcp header, so the
    // port check below cannot run on them: pass them up the stack so other
    // services keep receiving their fragmented traffic. Safe for the filtered
    // range because the matching first fragment is dropped after the port
    // check, so reassembly never completes and the kernel discards the rest
    // after the frag timeout. The ports can not be forged via fragment
    // overlap either: they live in bytes 0-3 of the tcp header while the
    // smallest non-first offset is 8 bytes, and linux >= 4.19 drops
    // overlapping fragments outright
    if (ip->frag_off & bpf_htons(IP_OFFSET))
    {
        return XDP_PASS;
    }

    /* ---------------- layer 4 ---------------- */

    const struct tcphdr *tcp = (const void *)ip + ip_hdr_len;
    if ((const void *)(tcp + 1) > data_end)
    {
        drop_reason = DROP_TCP_MALFORMED;
        goto drop;
    }

    // everything outside the filtered port range is not our business
    const __u16 dest_port = bpf_ntohs(tcp->dest);
    if (dest_port < START_PORT || dest_port > END_PORT)
    {
        return XDP_PASS;
    }

    // trusted sources (own proxies, admin hosts, monitoring) skip all
    // checks. Off by default; the map is only consulted when the loader
    // actually installed entries, so the common case costs nothing
    if (ALLOWLIST_ENABLED)
    {
        const struct lpm_key_v4 allow_key = {
            .prefixlen = 32,
            .addr = ip->saddr,
        };
        if (bpf_map_lookup_elem(&allowlist_map, &allow_key))
        {
            count_stats(get_stats(), ALLOWLIST_PASS, 1);
            return XDP_PASS;
        }
    }

    // first fragment of a fragmented packet (MF set, offset 0) aimed at our
    // range: the remaining payload is in fragments the state machine never
    // sees, so after kernel reassembly the backend would receive uninspected
    // data. Legitimate tcp does not fragment, the MSS keeps segments below
    // the MTU. Dropping the first fragment makes reassembly impossible, the
    // kernel discards the passed non-first fragments after the frag timeout
    if (ip->frag_off & bpf_htons(IP_MF))
    {
        drop_reason = DROP_IP_FRAGMENT;
        goto drop;
    }

    if (tcp->doff < 5)
    {
        drop_reason = DROP_TCP_MALFORMED;
        goto drop;
    }

    const __u32 tcp_hdr_len = tcp->doff * 4;
    if ((const void *)tcp + tcp_hdr_len > data_end)
    {
        drop_reason = DROP_TCP_MALFORMED;
        goto drop;
    }

    /*
     * Strict IP length validation:
     *  - tot_len must not exceed the frame, otherwise the packet is
     *    truncated and the payload would contain bytes the client never sent
     *  - tot_len must cover both headers; short values are caught further
     *    down by the u16 wrap-around check on the payload slice (see the
     *    comment at tcp_payload_len)
     * Trailing bytes *after* tot_len are fine and ignored here (ethernet
     * padding of small frames, GRO/LRO coalesced segments in skb mode): the
     * ip stack ignores them as well.
     *
     * The comparison is done in scalar arithmetic on purpose: bpf_ntohs()
     * erases the scalar bounds of the u16 load, so the value itself must
     * never be added to a packet pointer (the verifier rejects a pointer
     * with unknown upper bits). Only the u16-truncated payload length
     * further down is used for pointer arithmetic; clang has to emit the
     * truncation mask there, which is exactly the bound the verifier needs.
     */
    const __u32 ip_tot_len = bpf_ntohs(ip->tot_len);
    if (ip_tot_len > (__u32)((const __u8 *)data_end - l3))
    {
        drop_reason = DROP_IP_MALFORMED; // packet truncated / tot_len beyond the frame
        goto drop;
    }

    // spoofed source addresses: dropped before any state is touched. Both
    // checks are compile-time optional, so the branches disappear when off
    if (DROP_RESERVED_SOURCES || DROP_PRIVATE_SOURCES)
    {
        const __u32 host_src = bpf_ntohl(ip->saddr);
        if (DROP_RESERVED_SOURCES && ipv4_is_reserved_src(host_src))
        {
            drop_reason = DROP_RESERVED_SOURCE;
            goto drop;
        }
        if (DROP_PRIVATE_SOURCES && ipv4_is_private_src(host_src))
        {
            drop_reason = DROP_PRIVATE_SOURCE;
            goto drop;
        }
    }

    stats_ptr = get_stats();
    count_stats(stats_ptr, INCOMING_BYTES, raw_packet_len);

    // flag combinations that no legitimate client sends
    if (!tcp_flags_are_plausible(tcp))
    {
        count_stats(stats_ptr, TCP_BYPASS, 1);
        drop_reason = DROP_TCP_FLAGS;
        goto drop;
    }

    const __u32 src_ip = ip->saddr;
    const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);

    // new connection: throttle it, then start tracking it
    if (tcp->syn)
    {
        count_stats(stats_ptr, SYN_RECEIVE, 1);

        // drop SYNs carrying payload (e.g. TCP fast open): the data would
        // reach the backend without ever passing the inspection state machine
        if (ip_tot_len > ip_hdr_len + tcp_hdr_len)
        {
            count_stats(stats_ptr, TCP_BYPASS, 1);
            drop_reason = DROP_SYN_PAYLOAD;
            goto drop;
        }

        if (HIT_COUNT)
        {
            // connection throttle, fully in kernel: every source ip gets its
            // own window of HIT_COUNT_RESET_NS, opened by its first SYN and
            // closed by the bpf_timer that deletes the entry again
            struct throttle_entry *entry = bpf_map_lookup_elem(&connection_throttle, &src_ip);
            if (entry)
            {
                if (entry->hits >= HIT_COUNT)
                {
                    drop_reason = DROP_THROTTLE_LIMIT;
                    goto drop;
                }
                __sync_fetch_and_add(&entry->hits, 1);
            }
            else
            {
                __u32 zero = 0;
                __u64 *backoff = bpf_map_lookup_elem(&throttle_insert_backoff, &zero);
                if (!backoff)
                {
                    // per-cpu array index 0 always exists, this is unreachable
                    drop_reason = DROP_THROTTLE_STATE;
                    goto drop;
                }
                const __u64 now = bpf_ktime_get_ns();
                if (now < *backoff)
                {
                    // the map was full just before: fail closed without
                    // paying for another doomed insert attempt
                    drop_reason = DROP_THROTTLE_STATE;
                    goto drop;
                }
                const struct throttle_entry fresh = {.hits = 1, .pad = 0};
                const long err = bpf_map_update_elem(&connection_throttle, &src_ip, &fresh, BPF_NOEXIST);
                if (err < 0)
                {
                    if (err != -EEXIST)
                    {
                        // map full (attack): fail closed and back off
                        *backoff = now + THROTTLE_BACKOFF_NS;
                    }
                    drop_reason = DROP_THROTTLE_STATE;
                    goto drop;
                }
                entry = bpf_map_lookup_elem(&connection_throttle, &src_ip);
                if (!entry)
                {
                    // unreachable: the insert above succeeded
                    drop_reason = DROP_THROTTLE_STATE;
                    goto drop;
                }
                if (bpf_timer_init(&entry->timer, &connection_throttle, CLOCK_MONOTONIC) < 0 ||
                    bpf_timer_set_callback(&entry->timer, throttle_window_expired) < 0 ||
                    bpf_timer_start(&entry->timer, HIT_COUNT_RESET_NS, 0) < 0)
                {
                    // never leak an entry that has no expiry timer armed
                    bpf_map_delete_elem(&connection_throttle, &src_ip);
                    drop_reason = DROP_THROTTLE_STATE;
                    goto drop;
                }
            }
        }

        // track the connection: the next packet has to be the ACK finishing
        // the TCP handshake, with the sequence number following this SYN
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, bpf_ntohl(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
        {
            drop_reason = DROP_TRACK_STATE;
            goto drop;
        }

        return XDP_PASS;
    }

    // verified connections skip all further inspection
    struct player_entry *player = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (player)
    {
        // non-atomic on purpose: racing increments (flow migrating cpus) can
        // only lose single steps, never regress the counter across a window.
        // The idle check thus only false-matches if the connection sent
        // nothing for ~a full window, and minecraft clients keepalive every
        // few seconds, so such a connection is dead anyway
        player->packets++;
        count_stats(stats_ptr, VERIFIED_PACKET, 1);
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    if (!initial_state)
    {
        drop_reason = DROP_NOT_TRACKED; // neither tracked nor verified
        goto drop;
    }

    const __u8 *tcp_payload = (const __u8 *)tcp + tcp_hdr_len;

    /*
     * ip total length - ip header - tcp header = length of the tcp payload.
     *
     * The u16 arithmetic is deliberate (and mirrors an earlier revision): if
     * tot_len is smaller than the two headers the subtraction wraps to a
     * huge u16, and the frame check below drops the packet. The truncation
     * also produces the `& 0xffff` mask in the instruction stream that gives
     * the verifier a provably bounded value for the pointer arithmetic.
     */
    const __u16 tcp_payload_len = (__u16)(ip_tot_len - ip_hdr_len - tcp_hdr_len);
    const __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    // bounds check for the payload slice, also catches the wrap-around case
    // described above; the verifier needs this relation for every later
    // payload access
    if (tcp_payload_end > (const __u8 *)data_end)
    {
        drop_reason = DROP_IP_MALFORMED;
        goto drop;
    }

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        // not an ack, or not the ack matching our SYN
        if (!tcp->ack || initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            drop_reason = DROP_SEQUENCE_MISMATCH;
            goto drop;
        }

        // advance the state machine before the early drop below, the next
        // packet has to be matched against AWAIT_MC_HANDSHAKE
        initial_state->state = state = AWAIT_MC_HANDSHAKE;

        // the empty ack finishing the TCP handshake is dropped on purpose:
        // the backend will accept the first minecraft data packet as that
        // ack, which elegantly limits backend connections to clients whose
        // handshake passed inspection. If the ack already carries payload,
        // fall through into payload inspection instead
        if (tcp_payload >= tcp_payload_end)
        {
            drop_reason = DROP_EMPTY_ACK;
            goto drop;
        }
    }

    if (tcp_payload < tcp_payload_end)
    {
        // payload without an ack flag is never legitimate mid-handshake
        if (!tcp->ack)
        {
            drop_reason = DROP_BAD_ACK;
            goto drop_connection;
        }

        // we fully track the tcp sequence, so a mismatch here is either a
        // retransmission or an out-of-order packet: drop the packet, and
        // drop the whole connection once that happens too often. Everything
        // that survives this check is exactly the in-order byte stream the
        // backend would see, which is what allows the hard punishments below
        if (initial_state->expected_sequence != bpf_ntohl(tcp->seq))
        {
            if (++initial_state->fails > MAX_OUT_OF_ORDER)
            {
                drop_reason = DROP_OUT_OF_ORDER_LIMIT;
                goto drop_connection;
            }
            drop_reason = DROP_SEQUENCE_MISMATCH;
            goto drop;
        }

        if (state == AWAIT_MC_HANDSHAKE)
        {
            // if the status request or login packet is in the same tcp
            // segment as the handshake, inspect_handshake returns a
            // DIRECT_READ_* state and advances tcp_payload to the rest
            const __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, data_end, &initial_state->protocol, &tcp_payload);
            if (!next_state)
            {
                // even with retransmissions the handshake of a legitimate
                // client is always parseable, this connection is bogus
                drop_reason = DROP_HANDSHAKE_INVALID;
                goto drop;
            }
            if (next_state == RECEIVED_LEGACY_PING)
            {
                drop_reason = DROP_LEGACY_PING;
                goto drop_connection;
            }
            if (next_state == DIRECT_READ_STATUS_REQUEST)
            {
                goto read_status;
            }
            if (next_state == DIRECT_READ_LOGIN)
            {
                goto read_login;
            }
            initial_state->state = next_state;
            goto update_state;
        }
        if (state == AWAIT_STATUS_REQUEST)
        read_status:
        {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, data_end))
            {
                drop_reason = DROP_STATUS_INVALID;
                goto drop;
            }
            initial_state->state = AWAIT_PING;
            goto update_state;
        }
        if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, data_end))
            {
                drop_reason = DROP_PING_INVALID;
                goto drop;
            }
            initial_state->state = PING_COMPLETE;
            goto update_state;
        }
        if (state == AWAIT_LOGIN)
        read_login:
        {
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, data_end, initial_state->protocol))
            {
                drop_reason = DROP_LOGIN_INVALID;
                goto drop;
            }
            // tracking ends here, no need to update the expected sequence
            return switch_to_verified(raw_packet_len, stats_ptr, &flow_key);
        }
        if (state == PING_COMPLETE)
        {
            // a finished ping flow has nothing more to say
            drop_reason = DROP_PING_EXTRA;
            goto drop_connection;
        }
    }
    else if (state == AWAIT_MC_HANDSHAKE)
    {
        // empty acks are not allowed while the handshake is pending,
        // otherwise an attacker could sit on a half-inspected connection
        drop_reason = DROP_EMPTY_SEGMENT;
        goto drop;
    }

    // empty segments in the remaining states (pure acks, FIN/RST teardown)
    return XDP_PASS;

// shared exit paths: jumping here instead of duplicating these blocks keeps
// the generated program drastically smaller
drop_connection:
    count_stats(stats_ptr, DROP_CONNECTION, 1);
    bpf_map_delete_elem(&conntrack_map, &flow_key);
    // fall through
drop:
    return drop_verdict(stats_ptr, raw_packet_len, drop_reason);
update_state:
    initial_state->expected_sequence += tcp_payload_len;
    count_stats(stats_ptr, STATE_SWITCH, 1);
    return XDP_PASS;
}

// must be GPL-compatible: the bpf_timer_* helpers used by the connection
// throttle are gpl_only, the kernel refuses to load them otherwise
char _license[] SEC("license") = "Dual BSD/GPL";
