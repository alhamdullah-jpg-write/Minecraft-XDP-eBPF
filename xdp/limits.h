#ifndef LIMITS_H
#define LIMITS_H

#include <linux/types.h>

#include "flow.h"

/*
 * Pure helpers behind the rate limiter and the egress state check, kept in
 * a map-free header so the native unit tests can exercise them directly.
 */

static __always_inline __u64 __rate_sliding_estimate(const __u32 cur, const __u32 prev,
                                                     const __u64 elapsed_ns, const __u64 window_ns)
{
    if (!window_ns || elapsed_ns >= window_ns)
    {
        return cur;
    }
    const __u64 remaining = window_ns - elapsed_ns;
    return (__u64)cur + (__u64)prev * remaining / window_ns;
}

#define rate_sliding_estimate(cur, prev, elapsed_ns, window_ns) \
    __rate_sliding_estimate((cur), (prev), (elapsed_ns), (window_ns))

/* --------------------------------------------------------------------- */
/* subnet buckets: one rate window per /24 (v4) or /64 (v6)                */
/* --------------------------------------------------------------------- */

#define SUBNET4_BITS 24
#define SUBNET6_BITS 64

// zeroes the host part of the address (keeps the family byte untouched)
static __always_inline void subnet_key_from_host(const struct host_key *host, struct host_key *out)
{
    __builtin_memcpy(out, host, sizeof(*out));
    if (host->family == HOST_FAM_V4)
    {
        out->addr[15] = 0; // mapped v4: the /24 host part is the last byte
    }
    else
    {
#pragma unroll
        for (int i = SUBNET6_BITS / 8; i < ADDR_LEN; i++)
        {
            out->addr[i] = 0;
        }
    }
}

/*
 * TCP sequence check against a tracked egress flow: the ack from the
 * remote side must fall inside the sequence space the host itself sent.
 * A SYN consumes one sequence number, hence the one byte of slack above
 * next_seq (the syn-ack is acked with isn+1 while next_seq is still isn).
 */
static __always_inline __u8 egress_seq_in_window(const __u64 base_seq, const __u64 next_seq, const __u64 ack)
{
    return ack + 1 >= base_seq && ack <= next_seq + 1;
}

/* --------------------------------------------------------------------- */
/* verified-flow abuse cap                                                */
/* --------------------------------------------------------------------- */

/*
 * Lazy per-flow window for the verified fast path: unlike the hash-backed
 * rate windows there is no per-flow bpf_timer (a timer per player
 * connection would be the most expensive state in the program). The window
 * simply restarts inline the first time a packet arrives after it expired,
 * which is why the 2x boundary burst of a fixed window is acceptable here:
 * this is an abuse cap orders of magnitude above real client rates, not
 * admission control.
 *
 * window_start_ns == 0 marks a fresh entry. Both limits are independent
 * (either can be 0/off) and a packet over either limit is dropped without
 * touching the connection state, so a client that legitimately bursts -
 * or a misbehaving mod - recovers by itself in the next window.
 */
static __always_inline __u8 flow_flood_ok(__u64 *window_start_ns, __u64 *window_packets, __u64 *window_bytes,
                                          const __u64 now, const __u32 raw_len,
                                          const __u32 limit_pps, const __u32 limit_bps,
                                          const __u64 window_ns)
{
    if (!limit_pps && !limit_bps)
    {
        return 1;
    }
    if (*window_start_ns == 0 || now < *window_start_ns || now - *window_start_ns >= window_ns)
    {
        *window_start_ns = now;
        *window_packets = 0;
        *window_bytes = 0;
    }
    (*window_packets)++;
    *window_bytes += raw_len;
    if (limit_pps && *window_packets > limit_pps)
    {
        return 0;
    }
    if (limit_bps && *window_bytes > limit_bps)
    {
        return 0;
    }
    return 1;
}

#endif
