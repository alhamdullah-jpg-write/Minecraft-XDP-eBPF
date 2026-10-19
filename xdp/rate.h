#ifndef RATE_H
#define RATE_H

#include "limits.h"
#include "maps.h"

/*
 * Sliding-window rate limiting, fully in kernel.
 *
 * Every key owns a window: a bpf_timer rotates prev <- cur every window_ns,
 * the packet path only bumps cur with a per-entry atomic (no lock, no
 * global counter). The rate the caller compares against its limit is
 *
 *     cur + prev * (window - elapsed_since_rotation) / window
 *
 * i.e. the standard sliding-window-counter estimate, which closes the 2x
 * boundary burst of a plain fixed window without needing per-packet
 * timestamps.
 *
 * Idle entries delete themselves on rotation, so map capacity recovers
 * without userspace help even under attack.
 */

// the loader caps window_ms at this: prev (u32) * remaining_ns (u64-ish)
// must stay far from the u64 ceiling
#define RATE_WINDOW_MAX_MS 4000

// --- rotation callbacks (bpf_timer requires real functions, one per key
// --- type: the verifier checks the callback signature) -------------------

static __always_inline void rate_rotate_entry(struct rate_entry *entry)
{
    const __u64 now = bpf_ktime_get_ns();
    const struct tunables *tun = get_tunables();
    __u64 window = entry->window_ns;
    if (tun && tun->window_ms)
    {
        const __u64 configured = (__u64)tun->window_ms * 1000000ULL;
        if (configured != window)
        {
            // auto-tune changed the window: apply it on the next rotation
            window = configured;
            entry->window_ns = window;
        }
    }
    entry->prev = entry->cur;
    entry->cur = 0;
    entry->last_rotate_ns = now;
    // re-arming can only fail if this entry is concurrently being freed
    // (map delete/teardown NULLs the timer under its lock); then there is
    // nothing left to re-arm, so the result is deliberately ignored
    bpf_timer_start(&entry->timer, window, 0);
}

static __s32 rate_window_rotate_host(void *map, struct host_key *key, struct rate_entry *entry)
{
    if (entry->cur == 0 && entry->prev == 0)
    {
        bpf_map_delete_elem(map, key); // idle: give the slot back
        return 0;
    }
    rate_rotate_entry(entry);
    return 0;
}

static __s32 rate_window_rotate_rule(void *map, struct rule_rate_key *key, struct rate_entry *entry)
{
    if (entry->cur == 0 && entry->prev == 0)
    {
        bpf_map_delete_elem(map, key);
        return 0;
    }
    rate_rotate_entry(entry);
    return 0;
}

static __s32 rate_window_rotate_global(void *map, __u32 *key, struct rate_entry *entry)
{
    (void)map;
    (void)key;
    rate_rotate_entry(entry); // array slot: never delete
    return 0;
}

// --- the sliding estimate lives in limits.h (pure, unit tested) ----------

// --- generic check used by the hash-backed windows -----------------------

#define DEFINE_RATE_CHECK(fn, map_ptr, rotate_cb, backoff_id)                                                \
    /* 0 = counted, 1 = over limit, -1 = state error (map full/timer) */                                     \
    static __always_inline __s32 fn(void *key, const __u32 limit, const __u64 now, const struct tunables *tun) \
    {                                                                                                        \
        if (!limit)                                                                                          \
        {                                                                                                    \
            return 0;                                                                                        \
        }                                                                                                    \
        const __u64 window = (tun && tun->window_ms) ? (__u64)tun->window_ms * 1000000ULL                     \
                                                     : 1000000000ULL;                                        \
        struct rate_entry *entry = bpf_map_lookup_elem(map_ptr, key);                                         \
        if (entry)                                                                                           \
        {                                                                                                    \
            const __u64 elapsed = now > entry->last_rotate_ns ? now - entry->last_rotate_ns : 0;             \
            if (rate_sliding_estimate(entry->cur, entry->prev, elapsed, entry->window_ns) >= limit)           \
            {                                                                                                \
                return 1;                                                                                    \
            }                                                                                                \
            __sync_fetch_and_add(&entry->cur, 1);                                                             \
            return 0;                                                                                        \
        }                                                                                                    \
        const __u32 slot = backoff_id;                                                                        \
        __u64 *backoff = bpf_map_lookup_elem(&rate_insert_backoff, &slot);                                    \
        if (!backoff)                                                                                         \
        {                                                                                                    \
            return -1;                                                                                        \
        }                                                                                                    \
        if (now < *backoff)                                                                                   \
        {                                                                                                    \
            return -1;                                                                                        \
        }                                                                                                    \
        const struct rate_entry fresh = {.window_ns = window, .last_rotate_ns = now, .cur = 1};                \
        const long err = bpf_map_update_elem(map_ptr, key, &fresh, BPF_NOEXIST);                              \
        if (err < 0)                                                                                          \
        {                                                                                                    \
            if (err == -EEXIST)                                                                               \
            {                                                                                                \
                entry = bpf_map_lookup_elem(map_ptr, key);                                                    \
                if (!entry)                                                                                   \
                {                                                                                             \
                    return -1;                                                                                \
                }                                                                                             \
                __sync_fetch_and_add(&entry->cur, 1);                                                         \
                return 0;                                                                                     \
            }                                                                                                 \
            /* map full (attack): back off, the caller fails closed */                                        \
            *backoff = now + RATE_BACKOFF_NS;                                                                 \
            return -1;                                                                                        \
        }                                                                                                    \
        entry = bpf_map_lookup_elem(map_ptr, key);                                                            \
        if (!entry)                                                                                           \
        {                                                                                                    \
            return -1;                                                                                        \
        }                                                                                                    \
        if (bpf_timer_init(&entry->timer, map_ptr, CLOCK_MONOTONIC) < 0 ||                                     \
            bpf_timer_set_callback(&entry->timer, rotate_cb) < 0 ||                                            \
            bpf_timer_start(&entry->timer, window, 0) < 0)                                                     \
        {                                                                                                    \
            /* never leak an entry that has no expiry timer armed */                                          \
            bpf_map_delete_elem(map_ptr, key);                                                                 \
            return -1;                                                                                         \
        }                                                                                                    \
        return 0;                                                                                             \
    }

DEFINE_RATE_CHECK(rate_check_host, &host_throttle, rate_window_rotate_host, BACKOFF_HOST)
DEFINE_RATE_CHECK(rate_check_subnet, &subnet_throttle, rate_window_rotate_host, BACKOFF_SUBNET)
DEFINE_RATE_CHECK(rate_check_rule, &rule_rates, rate_window_rotate_rule, BACKOFF_RULE)
DEFINE_RATE_CHECK(rate_check_udp, &udp_throttle, rate_window_rotate_host, BACKOFF_UDP)

/*
 * Host-wide window on the single array slot. Unlike the hash windows an
 * array element can not "not exist", so the timer is initialized in place
 * on first use (window_ns == 0 marks an uninitialized entry).
 */
static __always_inline __s32 rate_check_global(const __u32 limit, const __u64 now, const struct tunables *tun)
{
    if (!limit)
    {
        return 0;
    }
    const __u32 zero = 0;
    struct rate_entry *entry = bpf_map_lookup_elem(&global_rate, &zero);
    if (!entry)
    {
        return 0; // unreachable (array index 0); never shed traffic on it
    }
    const __u64 window = (tun && tun->window_ms) ? (__u64)tun->window_ms * 1000000ULL : 1000000000ULL;
    if (entry->window_ns == 0)
    {
        entry->window_ns = window;
        entry->last_rotate_ns = now;
        entry->cur = 1;
        entry->prev = 0;
        // best effort: if another cpu initializes first, -EBUSY is fine
        if (bpf_timer_init(&entry->timer, &global_rate, CLOCK_MONOTONIC) == 0)
        {
            bpf_timer_set_callback(&entry->timer, rate_window_rotate_global);
            bpf_timer_start(&entry->timer, window, 0);
        }
        return 0;
    }
    const __u64 elapsed = now > entry->last_rotate_ns ? now - entry->last_rotate_ns : 0;
    if (rate_sliding_estimate(entry->cur, entry->prev, elapsed, entry->window_ns) >= limit)
    {
        return 1;
    }
    __sync_fetch_and_add(&entry->cur, 1);
    return 0;
}

#endif
