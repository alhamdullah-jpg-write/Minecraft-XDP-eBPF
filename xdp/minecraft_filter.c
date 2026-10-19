/*
 * minecraft_filter - XDP program protecting Minecraft Java (and friends)
 * against L7 (D)DoS attacks, plus a tc egress program that gives the host
 * a real stateful firewall.
 *
 * Ingress (XDP, cheapest checks first):
 *
 *   1. layer 2: frame bounds, up to two vlan tags
 *   2. layer 3: IPv4/IPv6 header validation, ipv6 extension header walk,
 *      fragment classification. Both families end up in the same 16 byte
 *      address representation, so every map below holds both.
 *   3. blocklist / auto-block lookup (one source address, two lookups)
 *   4. layer 4 dispatch by protocol and destination port:
 *        - minecraft tcp range: per-connection state machine that
 *          validates the tcp handshake and the first minecraft packets;
 *          connections that complete it move to a verified fast path
 *        - bedrock/voice udp ports: stateless raknet/voice validation,
 *          per-source udp windows, egress pinhole requirement
 *        - icmp/icmpv6: configurable (allow / smart / drop)
 *        - everything else: the declarative rule map, then default-deny
 *          (an egress flow match) when enabled, then pass
 *
 * Egress (tc, only when enabled): records every flow the host sent on and
 * the tcp sequence space it used. The ingress side then requires replies
 * to match that state, which is what kills blind reflection: a spoofed
 * packet cannot guess a flow the host never opened, let alone a valid ack
 * inside it.
 *
 * All map cleanup happens in-kernel via bpf_timer, userspace never has to
 * touch the maps. Every drop path funnels through drop_epilogue(), which
 * counts a per-reason counter and can turn the whole program into a
 * dry-run tap that passes all traffic.
 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/time.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* the icmp types linux/icmp.h would provide; including it drags glibc's
 * sys/socket.h into a bpf-target build, which does not define a wordsize */
#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAMETERPROB 12

#include "common.h"
#include "config.h"
#include "flow.h"
#include "limits.h"
#include "stats.h"
#include "maps.h"
#include "rate.h"
#include "blocklist.h"
#include "talkers.h"
#include "egress.h"
#include "rules.h"
#include "udp.h"
#include "protocol.h"

/* uapi gaps: ipv6 extension protocols and icmpv6 types */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOOBIG 2
#define ICMPV6_TIME_EXCEED 3
#define ICMPV6_PARAMPROB 4
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define ICMPV6_ND_MIN 130 // router solicit .. redirect: never drop, it breaks ipv6
#define ICMPV6_ND_MAX 137

// fragment bits of iphdr->frag_off (kernel-internal net/ip.h, not uapi)
#ifndef IP_MF
#define IP_MF 0x2000 // flag: "more fragments"
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF // "fragment offset" part
#endif

/* ------------------------------------------------------------------------
 * Shared helpers
 * --------------------------------------------------------------------- */

// vlan tag header; the uapi if_vlan.h only forward-declares this
struct vlan_tag_hdr
{
    __be16 tci;
    __be16 encapsulated_proto;
} __attribute__((packed));
_Static_assert(sizeof(struct vlan_tag_hdr) == 4, "vlan_tag_hdr size mismatch!");

/*
 * Parses one optional 802.1q/802.1ad tag: advances l3 past it, updates the
 * inner ethertype. Unrolled twice by the callers (double tagging). Without
 * this an attacker that can deliver tagged frames would bypass the whole
 * filter: the kernel strips the tag and hands the tcp packet to the server.
 * Jumps to `label` when the tag is truncated.
 */
#define PARSE_VLAN_TAG_TO(l3, proto, dend, label)                                \
    do                                                                           \
    {                                                                            \
        if ((proto) == bpf_htons(ETH_P_8021Q) ||                                 \
            (proto) == bpf_htons(ETH_P_8021AD))                                  \
        {                                                                        \
            const struct vlan_tag_hdr *_tag = (const struct vlan_tag_hdr *)(l3); \
            if ((const void *)(_tag + 1) > (const void *)(dend))                 \
            {                                                                    \
                goto label;                                                      \
            }                                                                    \
            (proto) = _tag->encapsulated_proto;                                  \
            (l3) += sizeof(struct vlan_tag_hdr);                                 \
        }                                                                        \
    } while (0)

#define PARSE_VLAN_TAG(l3, proto, dend) PARSE_VLAN_TAG_TO(l3, proto, dend, drop)

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
static __always_inline __s32 drop_epilogue(struct statistics *stats_ptr, const __u64 raw_packet_len,
                                           const __u32 reason, const struct host_key *src)
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
    talker_note(src, raw_packet_len, 1, 0);
    return DRY_RUN ? XDP_PASS : XDP_DROP;
}

// cheap "is this source trusted": the allowlist is only ever consulted
// when the loader actually installed entries (ALLOWLIST_ENABLED)
static __always_inline __u8 allowlisted(const struct host_key *src)
{
    if (!ALLOWLIST_ENABLED)
    {
        return 0;
    }
    struct lpm_key key;
    lpm_key_from_host(src, &key);
    return bpf_map_lookup_elem(&allowlist_map, &key) != NULL;
}

// shared bogons check for the inspected paths
static __always_inline __u8 source_is_bogon(const __u8 fam, const struct host_key *src, __u32 *reason)
{
    if (DROP_RESERVED_SOURCES && source_is_reserved(fam, src->addr))
    {
        *reason = DROP_RESERVED_SOURCE;
        return 1;
    }
    if (DROP_PRIVATE_SOURCES && source_is_private(fam, src->addr))
    {
        *reason = DROP_PRIVATE_SOURCE;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------
 * Verified source addresses (scanned by the voice gate and the loader/ML)
 * --------------------------------------------------------------------- */

static __s32 verified_source_expired(void *map, struct host_key *key, struct verified_entry *entry)
{
    const __u64 now = bpf_ktime_get_ns();
    const __u64 ttl = VERIFIED_SOURCES_TTL_NS;
    const __u64 elapsed = now - entry->last_seen_ns;
    if (ttl && elapsed < ttl)
    {
        bpf_timer_start(&entry->timer, ttl - elapsed, 0);
        return 0;
    }
    bpf_map_delete_elem(map, key);
    return 0;
}

static __always_inline void verified_source_touch(const struct host_key *src)
{
    if (!VERIFIED_SOURCES_ENABLED || !VERIFIED_SOURCES_TTL_NS)
    {
        return;
    }
    const __u64 now = bpf_ktime_get_ns();
    struct verified_entry *entry = bpf_map_lookup_elem(&verified_sources, src);
    if (entry)
    {
        entry->last_seen_ns = now;
        return;
    }
    const struct verified_entry fresh = {.last_seen_ns = now};
    if (bpf_map_update_elem(&verified_sources, src, &fresh, BPF_NOEXIST) < 0)
    {
        return; // someone else inserted it, or the map is full
    }
    entry = bpf_map_lookup_elem(&verified_sources, src);
    if (!entry)
    {
        return;
    }
    if (bpf_timer_init(&entry->timer, &verified_sources, CLOCK_MONOTONIC) < 0 ||
        bpf_timer_set_callback(&entry->timer, verified_source_expired) < 0 ||
        bpf_timer_start(&entry->timer, VERIFIED_SOURCES_TTL_NS, 0) < 0)
    {
        // never leak an entry that has no expiry timer armed
        bpf_map_delete_elem(&verified_sources, src);
    }
}

/* ------------------------------------------------------------------------
 * Verified connections (players)
 * --------------------------------------------------------------------- */

/*
 * bpf_timer callback: delete the verified connection if it was idle for a
 * full interval, otherwise snapshot the counter and check again next interval
 */
static __s32 player_connection_idle_check(void *map, struct flow_key *key, struct player_entry *entry)
{
    const __u64 packets = entry->packets;
    if (packets == entry->last_packets)
    {
        bpf_map_delete_elem(map, key);
        return 0;
    }
    entry->last_packets = packets;
    // Keep the source's verified mark fresh for the whole session: the voice
    // gate and the ML labels must not expire under an online player. This
    // runs once per PLAYER_IDLE_NS per connection (not per packet), and the
    // flow key already carries the source address in the shared 16 byte form.
    struct host_key src = {.family = key->family};
    __builtin_memcpy(src.addr, key->saddr, ADDR_LEN);
    verified_source_touch(&src);
    // re-arming can only fail if this entry is concurrently being freed (map
    // delete/teardown NULLs the timer under its lock); then there is nothing
    // left to re-arm, so the result is deliberately ignored
    bpf_timer_start(&entry->timer, PLAYER_IDLE_NS, 0);
    return 0;
}

/*
 * The connection passed the full inspection sequence: move it from the
 * conntrack map into the player map so its packets skip inspection from now
 * on, and arm the idle timer that will eventually clean the entry up.
 */
static __always_inline __s32 switch_to_verified(const __u64 raw_packet_len, struct statistics *stats_ptr,
                                                const struct flow_key *flow, const struct host_key *src)
{
    bpf_map_delete_elem(&conntrack_map, flow);
    const struct player_entry fresh = {.packets = 1, .last_packets = 0};
    const long err = bpf_map_update_elem(&player_connection_map, flow, &fresh, BPF_NOEXIST);
    if (err < 0)
    {
        if (err == -EEXIST)
        {
            // another cpu promoted this flow first, or an entry from an
            // earlier connection with the same 4-tuple is still around:
            // either way the flow is on the verified fast path already, so
            // this packet must pass
            count_stats(stats_ptr, VERIFIED_PACKET, 1);
            verified_source_touch(src);
            return XDP_PASS;
        }
        return drop_epilogue(stats_ptr, raw_packet_len, err == -E2BIG ? DROP_VERIFY_MAP_FULL : DROP_VERIFY_FAILED, src);
    }
    struct player_entry *entry = bpf_map_lookup_elem(&player_connection_map, flow);
    if (!entry)
    {
        return drop_epilogue(stats_ptr, raw_packet_len, DROP_VERIFY_FAILED, src);
    }
    if (bpf_timer_init(&entry->timer, &player_connection_map, CLOCK_MONOTONIC) < 0 ||
        bpf_timer_set_callback(&entry->timer, player_connection_idle_check) < 0 ||
        bpf_timer_start(&entry->timer, PLAYER_IDLE_NS, 0) < 0)
    {
        // never leak an entry that has no idle timer attached
        bpf_map_delete_elem(&player_connection_map, flow);
        return drop_epilogue(stats_ptr, raw_packet_len, DROP_VERIFY_FAILED, src);
    }
    verified_source_touch(src);
    count_stats(stats_ptr, VERIFIED, 1);
    count_stats(stats_ptr, VERIFIED_PACKET, 1);
    return XDP_PASS;
}

/* ------------------------------------------------------------------------
 * Egress tracking (called from the tc program below)
 * --------------------------------------------------------------------- */

// tracks the tcp sequence space the host sent: [seq, seq + payload_len)
static __always_inline void egress_track_tcp(const struct flow_key *key, const __u32 seq, const __u32 payload_len)
{
    const __u64 now = bpf_ktime_get_ns();
    struct egress_value *entry = bpf_map_lookup_elem(&egress_flows, key);
    if (!entry)
    {
        const struct egress_value fresh = {
            .base_seq = seq,
            .next_seq = (__u64)seq + payload_len,
            .last_seen_ns = now,
            .packets = 1,
        };
        bpf_map_update_elem(&egress_flows, key, &fresh, BPF_NOEXIST);
        return;
    }
    if (seq < entry->base_seq)
    {
        entry->base_seq = seq;
    }
    const __u64 next = (__u64)seq + payload_len;
    if (next > entry->next_seq)
    {
        entry->next_seq = next;
    }
    entry->last_seen_ns = now;
    entry->packets++;
}

// udp/icmp: only the freshness of the flow matters
static __always_inline void egress_track_touch(const struct flow_key *key)
{
    const __u64 now = bpf_ktime_get_ns();
    struct egress_value *entry = bpf_map_lookup_elem(&egress_flows, key);
    if (!entry)
    {
        const struct egress_value fresh = {.last_seen_ns = now, .packets = 1};
        bpf_map_update_elem(&egress_flows, key, &fresh, BPF_NOEXIST);
        return;
    }
    entry->last_seen_ns = now;
    entry->packets++;
}

/* ========================================================================
 * Ingress program
 * ===================================================================== */

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
    struct tunables *tun = NULL;
    __u64 now = 0;

    struct host_key src_host = {};
    struct host_key dst_host = {};
    struct flow_key flow = {};
    const __u8 *l4 = NULL;
    __u16 l4_len = 0;
    __u8 l4_proto = 0;
    __u8 family = 0;
    __u8 more_frags = 0;

    const struct tcphdr *tcp = NULL;
    const struct udphdr *udp = NULL;
    __be16 sport_be = 0;
    __be16 dport_be = 0;

    const __u8 *payload = NULL;
    const __u8 *payload_end = NULL;
    __u16 payload_len = 0;

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

    /* ---------------- layer 3 ---------------- */

    if (l3_proto == bpf_htons(ETH_P_IP))
    {
        const struct iphdr *ip = (const struct iphdr *)l3;
        if ((const void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
        {
            drop_reason = DROP_IP_MALFORMED;
            goto drop;
        }

        const __u32 ip_hdr_len = (__u32)ip->ihl * 4;
        if ((const void *)ip + ip_hdr_len > data_end)
        {
            drop_reason = DROP_IP_MALFORMED;
            goto drop;
        }

        /*
         * Strict IP length validation:
         *  - tot_len must not exceed the frame, otherwise the packet is
         *    truncated and the payload would contain bytes the client never
         *    sent
         * Trailing bytes *after* tot_len are fine and ignored here (ethernet
         * padding of small frames, GRO/LRO coalesced segments in skb mode):
         * the ip stack ignores them as well.
         *
         * The comparison is done in scalar arithmetic on purpose: bpf_ntohs()
         * erases the scalar bounds of the u16 load, so the value itself must
         * never be added to a packet pointer (the verifier rejects a pointer
         * with unknown upper bits). Only the u16-truncated payload length
         * further down is used for pointer arithmetic; clang has to emit the
         * truncation mask there, which is exactly the bound the verifier
         * needs.
         */
        const __u32 ip_tot_len = bpf_ntohs(ip->tot_len);
        if (ip_tot_len > (__u32)((const __u8 *)data_end - l3) || ip_tot_len < ip_hdr_len)
        {
            drop_reason = DROP_IP_MALFORMED;
            goto drop;
        }

        host_key_from_v4(&src_host, ip->saddr);
        host_key_from_v4(&dst_host, ip->daddr);
        family = HOST_FAM_V4;
        l4_proto = ip->protocol;

        // non-first fragments (fragment offset != 0) carry no tcp/udp header,
        // so the port check below cannot run on them: pass them up the stack
        // so other services keep receiving their fragmented traffic. Safe for
        // the filtered ports because the matching first fragment is dropped
        // after the port check, so reassembly never completes and the kernel
        // discards the rest after the frag timeout. The ports can not be
        // forged via fragment overlap either: they live in bytes 0-3 of the
        // l4 header while the smallest non-first offset is 8 bytes, and linux
        // >= 4.19 drops overlapping fragments outright
        if (ip->frag_off & bpf_htons(IP_OFFSET))
        {
            return XDP_PASS;
        }
        more_frags = (ip->frag_off & bpf_htons(IP_MF)) ? 1 : 0;

        l4 = l3 + ip_hdr_len;
        l4_len = (__u16)(ip_tot_len - ip_hdr_len);
        goto l3_ready;
    }

    if (l3_proto == bpf_htons(ETH_P_IPV6))
    {
        const struct ipv6hdr *ip6 = (const struct ipv6hdr *)l3;
        if ((const void *)(ip6 + 1) > data_end || ip6->version != 6)
        {
            drop_reason = DROP_IPV6_MALFORMED;
            goto drop;
        }

        const __u32 ip6_payload_len = bpf_ntohs(ip6->payload_len);
        if (ip6_payload_len > (__u32)((const __u8 *)data_end - (const __u8 *)(ip6 + 1)))
        {
            drop_reason = DROP_IPV6_MALFORMED;
            goto drop;
        }

        host_key_from_v6(&src_host, (const __u8 *)&ip6->saddr);
        host_key_from_v6(&dst_host, (const __u8 *)&ip6->daddr);
        family = HOST_FAM_V6;

        /*
         * Walk the extension header chain (bounded to 4 options headers).
         * The fragment header is handled separately afterwards: only the
         * chain order matters for l4 dispatch. First fragments (offset 0,
         * more-fragments set) are dropped later, after the port check;
         * non-first fragments are passed exactly like in ipv4.
         */
        const __u8 *next_hdr = (const __u8 *)ip6 + sizeof(struct ipv6hdr);
        __u8 nexthdr = ip6->nexthdr;
        __u16 remaining = (__u16)ip6_payload_len;

#pragma unroll
        for (int i = 0; i < 4; i++)
        {
            if (nexthdr != IPPROTO_HOPOPTS && nexthdr != IPPROTO_ROUTING && nexthdr != IPPROTO_DSTOPTS)
            {
                break;
            }
            if ((const void *)(next_hdr + 2) > data_end)
            {
                drop_reason = DROP_IPV6_MALFORMED;
                goto drop;
            }
            const __u16 hdr_len = (__u16)(((__u16)next_hdr[1] + 1) * 8);
            if ((const void *)(next_hdr + hdr_len) > data_end || hdr_len > remaining)
            {
                drop_reason = DROP_IPV6_MALFORMED;
                goto drop;
            }
            nexthdr = next_hdr[0];
            next_hdr += hdr_len;
            remaining -= hdr_len;
        }

        if (nexthdr == IPPROTO_FRAGMENT)
        {
            if ((const void *)(next_hdr + 8) > data_end || remaining < 8)
            {
                drop_reason = DROP_IPV6_MALFORMED;
                goto drop;
            }
            __be16 frag_field;
            __builtin_memcpy(&frag_field, next_hdr + 2, 2);
            if (bpf_ntohs(frag_field) & 0xfff8)
            {
                return XDP_PASS; // non-first fragment
            }
            more_frags = 1;
            nexthdr = next_hdr[0];
            next_hdr += 8;
            remaining -= 8;
        }

        l4_proto = nexthdr;
        l4 = next_hdr;
        l4_len = remaining;
        count_stats(get_stats(), IPV6_TRAFFIC, 1);
        goto l3_ready;
    }

    // neither ipv4 nor ipv6: not our business (arp, ...)
    return XDP_PASS;

    /* ---------------- blocklist (cheapest source filter) ---------------- */

l3_ready:
    if (BLOCKLIST_ENABLED || AUTOBLOCK_ENABLED)
    {
        now = bpf_ktime_get_ns();
        struct block_entry *blocked = blocklist_lookup(&src_host, now);
        if (blocked)
        {
            drop_reason = blocked->strikes ? DROP_AUTOBLOCK : DROP_BLOCKLIST;
            goto drop;
        }
    }

    /* ---------------- layer 4 dispatch ---------------- */

    if (l4_proto == IPPROTO_TCP)
    {
        tcp = (const struct tcphdr *)l4;
        if ((const void *)(tcp + 1) > data_end)
        {
            drop_reason = DROP_TCP_MALFORMED;
            goto drop;
        }
        sport_be = tcp->source;
        dport_be = tcp->dest;
        const __u16 dest_port = bpf_ntohs(tcp->dest);
        if (dest_port >= START_PORT && dest_port <= END_PORT)
        {
            goto minecraft_tcp;
        }
        goto rule_path;
    }

    if (l4_proto == IPPROTO_UDP)
    {
        udp = (const struct udphdr *)l4;
        if ((const void *)(udp + 1) > data_end)
        {
            drop_reason = DROP_UDP_MALFORMED;
            goto drop;
        }
        sport_be = udp->source;
        dport_be = udp->dest;
        const __u16 dest_port = bpf_ntohs(udp->dest);
        if (BEDROCK_ENABLED && dest_port == (__u16)BEDROCK_PORT)
        {
            goto bedrock_udp;
        }
        if (VOICE_ENABLED && dest_port == (__u16)VOICE_PORT)
        {
            goto voice_udp;
        }
        goto rule_path;
    }

    if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6)
    {
        goto icmp_path;
    }

    // every other protocol: default-deny drops it right after the ip frame,
    // otherwise it is not our business
    if (DEFAULT_DENY)
    {
        drop_reason = DROP_PROTO_DENY;
        goto drop;
    }
    return XDP_PASS;

    /* ---------------- minecraft tcp ---------------- */

minecraft_tcp:
    if (allowlisted(&src_host))
    {
        count_stats(get_stats(), ALLOWLIST_PASS, 1);
        return XDP_PASS;
    }

    // first fragment of a fragmented packet aimed at our range: the remaining
    // payload is in fragments the state machine never sees, so after kernel
    // reassembly the backend would receive uninspected data. Legitimate tcp
    // does not fragment, the MSS keeps segments below the MTU. Dropping the
    // first fragment makes reassembly impossible, the kernel discards the
    // passed non-first fragments after the frag timeout
    if (more_frags)
    {
        drop_reason = (family == HOST_FAM_V6) ? DROP_IPV6_FRAGMENT : DROP_IP_FRAGMENT;
        goto drop;
    }

    if (tcp->doff < 5)
    {
        drop_reason = DROP_TCP_MALFORMED;
        goto drop;
    }

    const __u32 tcp_hdr_len = (__u32)tcp->doff * 4;
    if ((const void *)tcp + tcp_hdr_len > data_end)
    {
        drop_reason = DROP_TCP_MALFORMED;
        goto drop;
    }

    // spoofed source addresses: dropped before any state is touched. Both
    // checks are compile-time optional, so the branches disappear when off
    if (DROP_RESERVED_SOURCES || DROP_PRIVATE_SOURCES)
    {
        __u32 bogon_reason = 0;
        if (source_is_bogon(family, &src_host, &bogon_reason))
        {
            drop_reason = bogon_reason;
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

    flow_key_from_hosts(&flow, &src_host, &dst_host, tcp->source, tcp->dest, IPPROTO_TCP);
    tun = get_tunables();

    // new connection: rate limit it, then start tracking it
    if (tcp->syn)
    {
        count_stats(stats_ptr, SYN_RECEIVE, 1);
        talker_note(&src_host, raw_packet_len, 0, 1);

        // drop SYNs carrying payload (e.g. TCP fast open): the data would
        // reach the backend without ever passing the inspection state machine
        if (l4_len > tcp_hdr_len)
        {
            count_stats(stats_ptr, TCP_BYPASS, 1);
            drop_reason = DROP_SYN_PAYLOAD;
            goto drop;
        }

        if (RATE_LIMITS_ENABLED)
        {
            now = bpf_ktime_get_ns();

            // per source ip
            __s32 verdict = rate_check_host(&src_host, tun ? tun->host_limit : 0, now, tun);
            if (verdict != 0)
            {
                if (verdict > 0)
                {
                    autoblock_strike(&src_host, DROP_THROTTLE_LIMIT, now);
                }
                // a negative verdict means the throttle state could not be
                // created: that map is sized by max_throttled_ips, so the
                // operator needs the reason that names it
                drop_reason = verdict > 0 ? DROP_THROTTLE_LIMIT : DROP_THROTTLE_STATE;
                goto drop;
            }

            // per subnet (/24 v4, /64 v6): one abusive block can not eat the
            // whole host limit of the machine
            struct host_key subnet_host;
            subnet_key_from_host(&src_host, &subnet_host);
            verdict = rate_check_subnet(&subnet_host, tun ? tun->subnet_limit : 0, now, tun);
            if (verdict != 0)
            {
                // no auto-block strike here: the individual source has not
                // been proven abusive, only its neighborhood
                drop_reason = verdict > 0 ? DROP_SUBNET_LIMIT : DROP_THROTTLE_STATE;
                goto drop;
            }

            // host-wide admission control: during a volumetric flood only
            // the verified fast path keeps working
            verdict = rate_check_global(tun ? tun->global_limit : 0, now, tun);
            if (verdict != 0)
            {
                // and no strike either: shedding new work must never
                // auto-block legitimate players
                drop_reason = verdict > 0 ? DROP_GLOBAL_LIMIT : DROP_THROTTLE_STATE;
                goto drop;
            }
        }

        // track the connection: the next packet has to be the ACK finishing
        // the TCP handshake, with the sequence number following this SYN
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, bpf_ntohl(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow, &new_state, BPF_ANY) < 0)
        {
            drop_reason = DROP_TRACK_STATE;
            goto drop;
        }

        return XDP_PASS;
    }

    // verified connections skip all further inspection
    struct player_entry *player = bpf_map_lookup_elem(&player_connection_map, &flow);
    if (player)
    {
        // non-atomic on purpose: racing increments (flow migrating cpus) can
        // only lose single steps, never regress the counter across a window.
        // The idle check thus only false-matches if the connection sent
        // nothing for ~a full window, and minecraft clients keepalive every
        // few seconds, so such a connection is dead anyway
        player->packets++;
        count_stats(stats_ptr, VERIFIED_PACKET, 1);
        talker_note(&src_host, raw_packet_len, 0, 0);

        // opt-in abuse cap: a connection that passed the handshake can still
        // be a spam bot - play-state floods (swing/packet spam) are invisible
        // to the parser by design. Over the cap the packets are dropped but
        // the connection stays tracked, so a legitimate burst recovers by
        // itself in the next window. Off by default.
        if (VERIFIED_PPS_LIMIT || VERIFIED_BPS_LIMIT)
        {
            const __u64 window = (tun && tun->window_ms) ? (__u64)tun->window_ms * 1000000ULL
                                                         : 1000000000ULL;
            if (!flow_flood_ok(&player->window_start_ns, &player->window_packets, &player->window_bytes,
                               bpf_ktime_get_ns(), raw_packet_len,
                               VERIFIED_PPS_LIMIT, VERIFIED_BPS_LIMIT, window))
            {
                drop_reason = DROP_MC_PACKET_RATE;
                goto drop;
            }
        }
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow);
    if (!initial_state)
    {
        drop_reason = DROP_NOT_TRACKED; // neither tracked nor verified
        goto drop;
    }

    const __u8 *tcp_payload = (const __u8 *)tcp + tcp_hdr_len;

    /*
     * ip payload - tcp header = length of the tcp payload.
     *
     * The u16 arithmetic is deliberate: if the declared l4 length is smaller
     * than the tcp header the subtraction wraps to a huge u16, and the frame
     * check below drops the packet. The truncation also produces the
     * `& 0xffff` mask in the instruction stream that gives the verifier a
     * provably bounded value for the pointer arithmetic.
     */
    const __u16 tcp_payload_len = (__u16)(l4_len - tcp_hdr_len);
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
            // a client never sends a proxy-protocol header: it can only be
            // an attempt to poison a backend that trusts forwarding headers
            if (REJECT_PROXY_HEADER && looks_like_proxy_header(tcp_payload, tcp_payload_end, data_end))
            {
                drop_reason = DROP_PROXY_UNTRUSTED;
                goto drop_connection;
            }

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
            return switch_to_verified(raw_packet_len, stats_ptr, &flow, &src_host);
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

    /* ---------------- bedrock (raknet) udp ---------------- */

bedrock_udp:
    if (allowlisted(&src_host))
    {
        count_stats(get_stats(), ALLOWLIST_PASS, 1);
        return XDP_PASS;
    }
    if (more_frags)
    {
        drop_reason = (family == HOST_FAM_V6) ? DROP_IPV6_FRAGMENT : DROP_IP_FRAGMENT;
        goto drop;
    }
    if (DROP_RESERVED_SOURCES || DROP_PRIVATE_SOURCES)
    {
        __u32 bogon_reason = 0;
        if (source_is_bogon(family, &src_host, &bogon_reason))
        {
            drop_reason = bogon_reason;
            goto drop;
        }
    }
    stats_ptr = get_stats();
    count_stats(stats_ptr, UDP_TRAFFIC, 1);
    count_stats(stats_ptr, INCOMING_BYTES, raw_packet_len);
    talker_note(&src_host, raw_packet_len, 0, 0);

    if (l4_len < sizeof(struct udphdr))
    {
        drop_reason = DROP_UDP_MALFORMED;
        goto drop;
    }
    payload = (const __u8 *)udp + sizeof(struct udphdr);
    payload_len = (__u16)(l4_len - sizeof(struct udphdr));
    payload_end = payload + payload_len;
    if (payload_end > (const __u8 *)data_end)
    {
        drop_reason = DROP_IP_MALFORMED;
        goto drop;
    }

    tun = get_tunables();
    if (RATE_LIMITS_ENABLED)
    {
        if (!now)
        {
            now = bpf_ktime_get_ns();
        }
        const __s32 verdict = rate_check_udp(&src_host, tun ? tun->udp_limit : 0, now, tun);
        if (verdict != 0)
        {
            if (verdict > 0)
            {
                autoblock_strike(&src_host, DROP_UDP_LIMIT, now);
            }
            drop_reason = verdict > 0 ? DROP_UDP_LIMIT : DROP_RATE_STATE;
            goto drop;
        }
    }

    if (!raknet_is_valid_offline(payload, payload_len, data_end, BEDROCK_MTU_MIN, BEDROCK_MTU_MAX,
                                 BEDROCK_STRICT_VERSION, BEDROCK_PROTO_MIN, BEDROCK_PROTO_MAX))
    {
        /*
         * A claimed offline handshake with a broken shape can never reach
         * any backend either: reject it right here, statelessly, before any
         * map lookup. This is the cheap side of the raknet handshake flood
         * (wrong magic, truncated body, bogus mtu).
         */
        if (raknet_looks_like_offline_handshake(payload, payload_len, data_end))
        {
            drop_reason = DROP_BEDROCK_INVALID;
            goto drop;
        }
        // connected game traffic and garbage look the same statelessly:
        // require the same flow state as any other untracked protocol
        if (!EGRESS_TRACK_ENABLED)
        {
            return XDP_PASS;
        }
        if (!now)
        {
            now = bpf_ktime_get_ns();
        }
        flow_key_from_hosts(&flow, &src_host, &dst_host, sport_be, dport_be, IPPROTO_UDP);
        if (!egress_pinhole(&flow, now, EGRESS_TIMEOUT_NS))
        {
            drop_reason = DROP_BEDROCK_UNTRACKED;
            goto drop;
        }
    }
    return XDP_PASS;

    /* ---------------- simple voice chat udp ---------------- */

voice_udp:
    if (allowlisted(&src_host))
    {
        count_stats(get_stats(), ALLOWLIST_PASS, 1);
        return XDP_PASS;
    }
    if (more_frags)
    {
        drop_reason = (family == HOST_FAM_V6) ? DROP_IPV6_FRAGMENT : DROP_IP_FRAGMENT;
        goto drop;
    }
    if (DROP_RESERVED_SOURCES || DROP_PRIVATE_SOURCES)
    {
        __u32 bogon_reason = 0;
        if (source_is_bogon(family, &src_host, &bogon_reason))
        {
            drop_reason = bogon_reason;
            goto drop;
        }
    }
    stats_ptr = get_stats();
    count_stats(stats_ptr, UDP_TRAFFIC, 1);
    count_stats(stats_ptr, INCOMING_BYTES, raw_packet_len);
    talker_note(&src_host, raw_packet_len, 0, 0);

    // the strong gate: voice packets are only accepted from addresses that
    // have a verified minecraft connection (players), when configured
    if (VOICE_REQUIRE_VERIFIED)
    {
        if (!VERIFIED_SOURCES_ENABLED || !bpf_map_lookup_elem(&verified_sources, &src_host))
        {
            drop_reason = DROP_VOICE_UNVERIFIED;
            goto drop;
        }
    }

    if (l4_len < sizeof(struct udphdr))
    {
        drop_reason = DROP_UDP_MALFORMED;
        goto drop;
    }
    payload = (const __u8 *)udp + sizeof(struct udphdr);
    payload_len = (__u16)(l4_len - sizeof(struct udphdr));
    payload_end = payload + payload_len;
    if (payload_end > (const __u8 *)data_end)
    {
        drop_reason = DROP_IP_MALFORMED;
        goto drop;
    }

    tun = get_tunables();
    if (RATE_LIMITS_ENABLED)
    {
        if (!now)
        {
            now = bpf_ktime_get_ns();
        }
        const __s32 verdict = rate_check_udp(&src_host, tun ? tun->udp_limit : 0, now, tun);
        if (verdict != 0)
        {
            if (verdict > 0)
            {
                autoblock_strike(&src_host, DROP_UDP_LIMIT, now);
            }
            drop_reason = verdict > 0 ? DROP_UDP_LIMIT : DROP_RATE_STATE;
            goto drop;
        }
    }

    if (!voice_is_valid_shape(payload, payload_len, data_end, VOICE_MAX_TYPE))
    {
        drop_reason = DROP_VOICE_INVALID;
        goto drop;
    }
    return XDP_PASS;

    /* ---------------- icmp / icmpv6 ---------------- */

icmp_path:
    if (ICMP_MODE == 0)
    {
        return XDP_PASS;
    }
    if (allowlisted(&src_host))
    {
        count_stats(get_stats(), ALLOWLIST_PASS, 1);
        return XDP_PASS;
    }
    {
        const __u8 *icmp = l4;
        if ((const void *)(icmp + 1) > data_end)
        {
            drop_reason = DROP_IP_MALFORMED;
            goto drop;
        }
        const __u8 type = icmp[0];
        if (ICMP_MODE == 2)
        {
            drop_reason = DROP_PROTO_DENY;
            goto drop;
        }
        if (l4_proto == IPPROTO_ICMP)
        {
            if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED || type == ICMP_PARAMETERPROB)
            {
                return XDP_PASS; // needed for PMTU/error signalling
            }
            if (type != ICMP_ECHOREPLY)
            {
                drop_reason = DROP_PROTO_DENY;
                goto drop;
            }
        }
        else
        {
            if (type >= ICMPV6_DEST_UNREACH && type <= ICMPV6_PARAMPROB)
            {
                return XDP_PASS; // errors, including packet-too-big
            }
            if (type >= ICMPV6_ND_MIN && type <= ICMPV6_ND_MAX)
            {
                return XDP_PASS; // neighbor discovery/MLD: dropping these breaks ipv6
            }
            if (type != ICMPV6_ECHO_REPLY)
            {
                drop_reason = DROP_PROTO_DENY;
                goto drop;
            }
        }

        // echo reply: only legitimate as the answer to a request we sent
        if (!EGRESS_TRACK_ENABLED)
        {
            // nothing to validate against: pass (documented)
            return XDP_PASS;
        }
        if ((const void *)(icmp + 8) > data_end)
        {
            drop_reason = DROP_IP_MALFORMED;
            goto drop;
        }
        __be16 ident;
        __builtin_memcpy(&ident, icmp + 4, 2);
        if (!now)
        {
            now = bpf_ktime_get_ns();
        }
        // the identifier sits in the same position in requests and replies,
        // so both directions use the same key layout
        flow_key_from_hosts(&flow, &src_host, &dst_host, ident, ident, l4_proto);
        if (!egress_pinhole(&flow, now, EGRESS_TIMEOUT_NS))
        {
            drop_reason = DROP_UNSOLICITED;
            goto drop;
        }
        return XDP_PASS;
    }

    /* ---------------- rules / default-deny ---------------- */

rule_path:
    if (allowlisted(&src_host))
    {
        count_stats(get_stats(), ALLOWLIST_PASS, 1);
        return XDP_PASS;
    }
    if (more_frags)
    {
        drop_reason = (family == HOST_FAM_V6) ? DROP_IPV6_FRAGMENT : DROP_IP_FRAGMENT;
        goto drop;
    }
    if (RULES_ENABLED)
    {
        struct rule *rule = rule_lookup(l4_proto, dport_be);
        if (rule)
        {
            /*
             * The l4 payload slice for the length/magic checks.
             *
             * This block re-parses the transport header from `l4` instead of
             * reusing the `tcp` pointer the dispatch above set on the
             * minecraft-range path only: the two dispatch paths join here,
             * and a variable that is a packet pointer on one path and NULL
             * on the other joins as a plain scalar, which the verifier
             * rejects on the next dereference. `l4` is set on both paths,
             * so parsing from it keeps the pointer type.
             */
            __u16 rule_hdr_len = sizeof(struct udphdr);
            __u8 rule_ack = 0;
            __be32 rule_ack_seq = 0;
            if (l4_proto == IPPROTO_TCP)
            {
                const struct tcphdr *rule_tcp = (const struct tcphdr *)l4;
                if (!pkt_within(rule_tcp, sizeof(struct tcphdr), data_end))
                {
                    drop_reason = DROP_TCP_MALFORMED;
                    goto drop;
                }
                if (rule_tcp->doff < 5)
                {
                    drop_reason = DROP_TCP_MALFORMED;
                    goto drop;
                }
                rule_hdr_len = (__u16)((__u16)rule_tcp->doff * 4);
                if (!pkt_within(rule_tcp, rule_hdr_len, data_end))
                {
                    drop_reason = DROP_TCP_MALFORMED;
                    goto drop;
                }
                // read as scalars here, where the verifier still knows the
                // header pointer: the stateful check below runs after joins
                rule_ack = rule_tcp->ack;
                rule_ack_seq = rule_tcp->ack_seq;
            }
            if (l4_len < rule_hdr_len)
            {
                drop_reason = DROP_IP_MALFORMED;
                goto drop;
            }
            payload = l4 + rule_hdr_len;
            payload_len = (__u16)(l4_len - rule_hdr_len);
            payload_end = payload + payload_len;
            if (payload_end > (const __u8 *)data_end)
            {
                drop_reason = DROP_IP_MALFORMED;
                goto drop;
            }

            if (rule->action == RULE_ACTION_DROP)
            {
                drop_reason = DROP_RULE;
                goto drop;
            }
            if (rule->min_len && payload_len < rule->min_len)
            {
                drop_reason = DROP_RULE_MAGIC;
                goto drop;
            }
            if (rule->max_len && payload_len > rule->max_len)
            {
                drop_reason = DROP_RULE_MAGIC;
                goto drop;
            }
            if (!rule_magic_ok(rule, payload, payload_len, data_end))
            {
                drop_reason = DROP_RULE_MAGIC;
                goto drop;
            }

            if (rule->flags & RULE_FLAG_STATEFUL)
            {
                if (!EGRESS_TRACK_ENABLED)
                {
                    drop_reason = DROP_UNSOLICITED;
                    goto drop;
                }
                if (!now)
                {
                    now = bpf_ktime_get_ns();
                }
                flow_key_from_hosts(&flow, &src_host, &dst_host, sport_be, dport_be, l4_proto);
                struct egress_value *pin = egress_pinhole(&flow, now, EGRESS_TIMEOUT_NS);
                if (!pin)
                {
                    drop_reason = DROP_UNSOLICITED;
                    goto drop;
                }
                if (l4_proto == IPPROTO_TCP && rule_ack &&
                    !egress_seq_in_window(pin->base_seq, pin->next_seq, bpf_ntohl(rule_ack_seq)))
                {
                    drop_reason = DROP_EGRESS_SEQ;
                    goto drop;
                }
            }

            if (rule->action == RULE_ACTION_RATE)
            {
                if (!now)
                {
                    now = bpf_ktime_get_ns();
                }
                const __u32 limit = rule->max_rate ? rule->max_rate : (tun ? tun->rule_limit : 0);
                struct rule_rate_key rkey;
                __builtin_memset(&rkey, 0, sizeof(rkey));
                __builtin_memcpy(&rkey.host, &src_host, sizeof(src_host));
                rkey.rule_id = rule->rule_id;
                const __s32 verdict = rate_check_rule(&rkey, limit, now, tun);
                if (verdict > 0)
                {
                    autoblock_strike(&src_host, DROP_RULE_RATE, now);
                    drop_reason = DROP_RULE_RATE;
                    goto drop;
                }
                if (verdict < 0)
                {
                    drop_reason = DROP_RATE_STATE;
                    goto drop;
                }
            }
            return XDP_PASS;
        }
    }
    if (!DEFAULT_DENY)
    {
        return XDP_PASS;
    }
    goto unsolicited; // explicit: keeps the label used when rules are off

unsolicited:
    if (!EGRESS_TRACK_ENABLED)
    {
        drop_reason = DROP_UNSOLICITED;
        goto drop;
    }
    if (!now)
    {
        now = bpf_ktime_get_ns();
    }
    flow_key_from_hosts(&flow, &src_host, &dst_host, sport_be, dport_be, l4_proto);
    {
        struct egress_value *pin = egress_pinhole(&flow, now, EGRESS_TIMEOUT_NS);
        if (!pin)
        {
            drop_reason = DROP_UNSOLICITED;
            goto drop;
        }
        // parse the ack fields from l4 for the same reason as the rule
        // path: this label is a join of the tcp and udp dispatch paths
        if (l4_proto == IPPROTO_TCP)
        {
            const struct tcphdr *uns_tcp = (const struct tcphdr *)l4;
            if (!pkt_within(uns_tcp, sizeof(struct tcphdr), data_end))
            {
                drop_reason = DROP_TCP_MALFORMED;
                goto drop;
            }
            if (uns_tcp->ack &&
                !egress_seq_in_window(pin->base_seq, pin->next_seq, bpf_ntohl(uns_tcp->ack_seq)))
            {
                drop_reason = DROP_EGRESS_SEQ;
                goto drop;
            }
        }
    }
    return XDP_PASS;

    /* ---------------- shared exit paths ---------------- */

drop_connection:
    count_stats(stats_ptr, DROP_CONNECTION, 1);
    bpf_map_delete_elem(&conntrack_map, &flow);
    // fall through
drop:
    return drop_epilogue(stats_ptr, raw_packet_len, drop_reason, family ? &src_host : NULL);
update_state:
    initial_state->expected_sequence += tcp_payload_len;
    count_stats(stats_ptr, STATE_SWITCH, 1);
    return XDP_PASS;
}

/* ========================================================================
 * Egress program (tc/clsact): track every flow the host sent on
 * ===================================================================== */

SEC("classifier")
__s32 tc_egress_track(struct __sk_buff *skb)
{
    if (!EGRESS_TRACK_ENABLED)
    {
        return TC_ACT_OK;
    }

    const void *data = (const void *)(long)skb->data;
    const void *data_end = (const void *)(long)skb->data_end;

    const struct ethhdr *eth = data;
    if ((const void *)(eth + 1) > data_end)
    {
        goto egress_error;
    }

    const __u8 *l3 = data + sizeof(struct ethhdr);
    __be16 l3_proto = eth->h_proto;
    PARSE_VLAN_TAG_TO(l3, l3_proto, data_end, egress_error);

    struct host_key src_host = {};
    struct host_key dst_host = {};
    const __u8 *l4 = NULL;
    __u8 l4_proto = 0;

    if (l3_proto == bpf_htons(ETH_P_IP))
    {
        const struct iphdr *ip = (const struct iphdr *)l3;
        if ((const void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
        {
            goto egress_error;
        }
        // our own stack never fragments; if it did, skip (the ingress side
        // passes non-first fragments and drops first ones anyway)
        if (ip->frag_off & bpf_htons(IP_OFFSET | IP_MF))
        {
            return TC_ACT_OK;
        }
        const __u32 ip_hdr_len = (__u32)ip->ihl * 4;
        if ((const void *)ip + ip_hdr_len > data_end)
        {
            goto egress_error;
        }
        host_key_from_v4(&src_host, ip->saddr);
        host_key_from_v4(&dst_host, ip->daddr);
        l4_proto = ip->protocol;
        l4 = l3 + ip_hdr_len;
    }
    else if (l3_proto == bpf_htons(ETH_P_IPV6))
    {
        const struct ipv6hdr *ip6 = (const struct ipv6hdr *)l3;
        if ((const void *)(ip6 + 1) > data_end || ip6->version != 6)
        {
            goto egress_error;
        }
        const __u8 *next_hdr = (const __u8 *)ip6 + sizeof(struct ipv6hdr);
        __u8 nexthdr = ip6->nexthdr;
        const __u32 ip6_payload_len = bpf_ntohs(ip6->payload_len);
        __u16 remaining = (__u16)ip6_payload_len;
        if (ip6_payload_len > (__u32)((const __u8 *)data_end - next_hdr))
        {
            goto egress_error;
        }

#pragma unroll
        for (int i = 0; i < 4; i++)
        {
            if (nexthdr != IPPROTO_HOPOPTS && nexthdr != IPPROTO_ROUTING && nexthdr != IPPROTO_DSTOPTS)
            {
                break;
            }
            if ((const void *)(next_hdr + 2) > data_end)
            {
                goto egress_error;
            }
            const __u16 hdr_len = (__u16)(((__u16)next_hdr[1] + 1) * 8);
            if ((const void *)(next_hdr + hdr_len) > data_end || hdr_len > remaining)
            {
                goto egress_error;
            }
            nexthdr = next_hdr[0];
            next_hdr += hdr_len;
            remaining -= hdr_len;
        }
        if (nexthdr == IPPROTO_FRAGMENT)
        {
            return TC_ACT_OK; // skip: fragmented egress is unusual and stateful-checks poorly
        }

        host_key_from_v6(&src_host, (const __u8 *)&ip6->saddr);
        host_key_from_v6(&dst_host, (const __u8 *)&ip6->daddr);
        l4_proto = nexthdr;
        l4 = next_hdr;
    }
    else
    {
        return TC_ACT_OK; // not ip: nothing to track
    }

    struct flow_key flow = {};

    if (l4_proto == IPPROTO_TCP)
    {
        const struct tcphdr *tcp = (const struct tcphdr *)l4;
        if ((const void *)(tcp + 1) > data_end)
        {
            goto egress_error;
        }
        const __u32 tcp_hdr_len = (__u32)tcp->doff * 4;
        if (tcp->doff < 5 || (const void *)tcp + tcp_hdr_len > data_end)
        {
            goto egress_error;
        }
        /*
         * Payload length from skb->len, not from data_end: under TSO/GSO a
         * super-packet's payload lives in frags and data_end only covers
         * the linear part. skb->len is the full on-wire length, which is
         * exactly the sequence space the peer will ack.
         */
        const __u32 total = skb->len;
        const __u32 l4_off = (__u32)((const __u8 *)l4 - (const __u8 *)data);
        __u32 tcp_payload_len = 0;
        if (total > l4_off + tcp_hdr_len)
        {
            tcp_payload_len = total - l4_off - tcp_hdr_len;
        }
        if (tcp_payload_len > 0xffff)
        {
            tcp_payload_len = 0xffff;
        }
        flow_key_from_hosts(&flow, &src_host, &dst_host, tcp->source, tcp->dest, IPPROTO_TCP);
        egress_track_tcp(&flow, bpf_ntohl(tcp->seq), tcp_payload_len);
        return TC_ACT_OK;
    }

    if (l4_proto == IPPROTO_UDP)
    {
        const struct udphdr *udp = (const struct udphdr *)l4;
        if ((const void *)(udp + 1) > data_end)
        {
            goto egress_error;
        }
        flow_key_from_hosts(&flow, &src_host, &dst_host, udp->source, udp->dest, IPPROTO_UDP);
        egress_track_touch(&flow);
        return TC_ACT_OK;
    }

    if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6)
    {
        const __u8 *icmp = l4;
        if ((const void *)(icmp + 8) > data_end)
        {
            goto egress_error;
        }
        // only echo requests open a pinhole for the reply
        if (icmp[0] == ICMP_ECHO || icmp[0] == ICMPV6_ECHO_REQUEST)
        {
            __be16 ident;
            __builtin_memcpy(&ident, icmp + 4, 2);
            flow_key_from_hosts(&flow, &src_host, &dst_host, ident, ident, l4_proto);
            egress_track_touch(&flow);
        }
        return TC_ACT_OK;
    }

    return TC_ACT_OK;

egress_error:
    count_stats(get_stats(), EGRESS_ERRORS, 1);
    return TC_ACT_OK;
}

// must be GPL-compatible: the bpf_timer_* helpers used by every window are
// gpl_only, the kernel refuses to load them otherwise
char _license[] SEC("license") = "Dual BSD/GPL";
