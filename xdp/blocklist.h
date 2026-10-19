#ifndef BLOCKLIST_H
#define BLOCKLIST_H

#include "maps.h"

/*
 * Two blocklists, both checked right after the IP header is parsed (the
 * cheapest place a source address is known):
 *
 *  - blocklist_map: operator-supplied CIDRs from a file, permanent or with
 *    an expiry, managed by the loaders. A single LPM trie holds IPv4
 *    (::ffff: mapped) and IPv6 entries.
 *
 *  - autoblock_map: exact-address blocks the kernel inserts itself when a
 *    source keeps violating the rate limits. The lifetime escalates with
 *    every renewed burst (base_ttl << (strikes - threshold), capped), and
 *    the loader prunes expired entries, exports them for upstream
 *    enforcement and can add ML-driven entries with the same format.
 *
 * Both are read-only from the packet path and only ever drop traffic that
 * is already over a proven limit unless an operator allows otherwise, so
 * every block is visible as its own drop reason and metric.
 */

// returns the blocking entry, or NULL. now comes from one bpf_ktime_get_ns()
// per packet.
static __always_inline struct block_entry *blocklist_lookup(const struct host_key *host, const __u64 now)
{
    if (BLOCKLIST_ENABLED)
    {
        struct lpm_key key;
        lpm_key_from_host(host, &key);
        struct block_entry *entry = bpf_map_lookup_elem(&blocklist_map, &key);
        if (entry && (entry->expires_ns == 0 || now < entry->expires_ns))
        {
            return entry;
        }
    }
    if (AUTOBLOCK_ENABLED)
    {
        struct block_entry *entry = bpf_map_lookup_elem(&autoblock_map, host);
        if (entry && entry->expires_ns != 0 && now < entry->expires_ns)
        {
            return entry;
        }
    }
    return NULL;
}

/*
 * Records one rate-limit violation for this source. The first
 * `strike_threshold` violations only build up the count; from then on every
 * violation (re-)arms a block whose duration doubles per escalation step up
 * to block_max_ttl_s. A quiet period longer than strike_decay_s forgets
 * the history, so a one-off burst from a shared/NAT address does not leave
 * it blocked forever.
 */
static __always_inline void autoblock_strike(const struct host_key *host, const __u32 reason, const __u64 now)
{
    if (!AUTOBLOCK_ENABLED)
    {
        return;
    }
    const struct tunables *tun = get_tunables();
    if (!tun || !tun->strike_threshold || !tun->block_base_ttl_s || !tun->block_max_ttl_s)
    {
        return;
    }

    struct block_entry *entry = bpf_map_lookup_elem(&autoblock_map, host);
    if (!entry)
    {
        const struct block_entry fresh = {
            .expires_ns = 0,
            .last_strike_ns = now,
            .strikes = 1,
            .reason = reason,
        };
        bpf_map_update_elem(&autoblock_map, host, &fresh, BPF_NOEXIST);
        return;
    }

    __u32 strikes = entry->strikes;
    if (tun->strike_decay_s && now - entry->last_strike_ns > (__u64)tun->strike_decay_s * 1000000000ULL)
    {
        strikes = 0; // quiet for long enough: start over
    }
    strikes = strikes < 31 ? strikes + 1 : 31;
    entry->strikes = strikes;
    entry->last_strike_ns = now;
    entry->reason = reason;

    if (strikes < tun->strike_threshold)
    {
        return;
    }

    // escalation: base << min(strikes - threshold, 6), capped. The shift is
    // done in u32 seconds before converting to ns to stay far from the u64
    // ceiling even for absurdly configured bases.
    __u32 base_s = tun->block_base_ttl_s;
    if (base_s > (1u << 20))
    {
        base_s = 1u << 20;
    }
    __u32 shift = strikes - tun->strike_threshold;
    if (shift > 6)
    {
        shift = 6;
    }
    __u32 ttl_s = base_s << shift;
    const __u32 max_s = tun->block_max_ttl_s;
    if (max_s && ttl_s > max_s)
    {
        ttl_s = max_s;
    }
    entry->expires_ns = now + (__u64)ttl_s * 1000000000ULL;
}

#endif
