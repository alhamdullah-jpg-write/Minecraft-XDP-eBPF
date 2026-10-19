#ifndef TALKERS_H
#define TALKERS_H

#include "maps.h"

/*
 * Sampled per-source counters ("top talkers").
 *
 * One in (TALKER_SAMPLE_MASK + 1) packets does one LRU map update, which
 * keeps the cost independent of the packet mix: an attacker cannot make
 * this map hotter than 1/16 of its own packet rate. The loader aggregates
 * the map into the prometheus top-talker metrics and feeds it to the ML
 * scorer; everything else (limits, blocks) is decided without it.
 */

static __always_inline void talker_note(const struct host_key *src, const __u64 bytes,
                                        const __u8 is_drop, const __u8 is_syn)
{
    if (!TALKERS_ENABLED || !src)
    {
        return;
    }
    const __u32 zero = 0;
    __u64 *clock = bpf_map_lookup_elem(&talker_sample, &zero);
    if (!clock)
    {
        return;
    }
    // non-atomic on purpose: a lost sample is irrelevant
    const __u64 n = (*clock)++;
    if (((__u32)n & TALKER_SAMPLE_MASK) != 0)
    {
        return;
    }

    const __u64 now = bpf_ktime_get_ns();
    struct talker_entry *entry = bpf_map_lookup_elem(&talkers_map, src);
    if (!entry)
    {
        const struct talker_entry fresh = {
            .packets = 1,
            .bytes = bytes,
            .first_seen_ns = now,
            .last_seen_ns = now,
            .drops = is_drop,
            .syns = is_syn,
        };
        bpf_map_update_elem(&talkers_map, src, &fresh, BPF_NOEXIST);
        return;
    }
    entry->packets++;
    entry->bytes += bytes;
    entry->last_seen_ns = now;
    if (is_drop)
    {
        entry->drops++;
    }
    if (is_syn)
    {
        entry->syns++;
    }
}

#endif
