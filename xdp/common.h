#ifndef COMMON_H
#define COMMON_H

#include <linux/tcp.h>
#include <linux/types.h>

// compiler barrier: prevents clang from merging or reordering the pointer
// arithmetic around bounds checks, which would make the verifier lose track
// of the checked range
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

/*
 * Packet bounds check the verifier can rely on.
 *
 * `(const void *)(ptr + len) > end` is the idiom used everywhere in this
 * program, but clang may *prove* such a check redundant from an earlier
 * check on an equivalent expression (the caller already validated
 * `payload + payload_len <= data_end`, the callee then checks
 * `payload + 1`), delete the comparison - and with it the range the
 * verifier needs for the access that follows. The load is then rejected as
 * out of bounds even though the C source clearly checked.
 *
 * The register barrier makes `ptr` opaque to clang, so the comparison (and
 * the range the verifier derives from it) always survives. Use this for the
 * first access to every freshly derived payload pointer.
 */
static __always_inline __u8 pkt_within(const void *ptr, const __u32 len, const void *end)
{
    const __u8 *p = (const __u8 *)ptr;
    barrier_var(p);
    return (const void *)(p + len) <= end;
}

// maximum amount of out-of-order/retransmitted packets before a tracked
// connection is dropped entirely
#define MAX_OUT_OF_ORDER 4

/*
 * Connection states stored in initial_state.state, plus pseudo states only
 * returned by inspect_handshake() (RECEIVED_LEGACY_PING and the DIRECT_READ_*
 * values, which signal that more protocol data follows in the same packet).
 * STATE_INVALID doubles as the generic "parse failed" return value of all
 * inspectors.
 */
enum connection_state
{
    STATE_INVALID = 0,
    AWAIT_ACK = 1,
    AWAIT_MC_HANDSHAKE = 2,
    RECEIVED_LEGACY_PING = 3, // this connection will be fully dropped
    AWAIT_STATUS_REQUEST = 4,
    AWAIT_LOGIN = 5,
    AWAIT_PING = 6,
    PING_COMPLETE = 7,
    DIRECT_READ_STATUS_REQUEST = 8,
    DIRECT_READ_LOGIN = 9,
};

/*
 * Bounds-check macros.
 *
 * All of them bail out of the CALLING function with `return 0` when the
 * requested bytes are not fully inside both the TCP payload (pend) and the
 * packet (dend). Checking against both bounds with a barrier in between is
 * what convinces the verifier that every later access is safe.
 */

// checks that [ptr, ptr + n) is in bounds; does NOT advance ptr
#define CHECK_BOUNDS_OR_RETURN(ptr, n, pend, dend)        \
    do                                                    \
    {                                                     \
        if ((void *)(ptr) + (n) > (const void *)(dend))   \
            return 0;                                     \
        barrier_var(ptr);                                 \
        if ((void *)(ptr) + (n) > (const void *)(pend))   \
            return 0;                                     \
        barrier_var(ptr);                                 \
    } while (0)

// checks that [ptr, ptr + n) is in bounds and advances ptr past those bytes
#define SKIP_OR_RETURN(ptr, n, pend, dend)                \
    do                                                    \
    {                                                     \
        CHECK_BOUNDS_OR_RETURN(ptr, n, pend, dend);       \
        (ptr) += (n);                                     \
    } while (0)

/*
 * Range-checked skip for *variable* lengths: [ptr, ptr + n) must be inside
 * both bounds and n must be in [min, max] before ptr is advanced by n.
 *
 * `val` must be a modifiable lvalue (in practice the varint value field) and
 * `mask` the smallest 2^k-1 that covers max (SKIP_MASK(max)).
 *
 * This is one macro instead of ASSERT_IN_RANGE_OR_RETURN + SKIP_OR_RETURN
 * because of three verifier properties that are easy to miss and that
 * produce a rejection pointing at a completely unrelated line of code
 * ("invalid access to packet, off=N size=1, R offset is outside of the
 * packet" on the *next* payload access):
 *
 * 1. a varint is assembled from shifted, masked bytes with bitwise OR, and
 *    the verifier does not track bitwise ops on registers it marked precise
 *    ("scalar(id=..)" in the log) - the accumulated value is a full-range
 *    scalar (bound 0..2^64-1 as far as the verifier knows)
 * 2. adding such a value to a packet pointer gives the pointer a variable
 *    offset wider than MAX_PACKET_OFF. find_good_pkt_pointers() then bails
 *    out for that pointer id, so *no* later comparison (against payload_end
 *    or data_end) establishes a range, and the first payload access is
 *    rejected. This happens even though the C source clearly checks bounds.
 *
 *    The mask below closes this hole: it is emitted (at this point of the
 *    program LLVM knows nothing about the value's magnitude) and it is a
 *    no-op for every value that passes the range check. It is stored back
 *    into the field on purpose - if clang later reloads the field from its
 *    stack slot, the reload carries the bound with it.
 * 3. every variable pointer advance creates a fresh pointer id, and the
 *    verifier tracks proven ranges per id. The range for the new id is
 *    established by the caller's next bounds-checked read, which checks
 *    against both bounds again - do not "optimize" that away.
 */
#define SKIP_IN_RANGE_OR_RETURN(ptr, val, min, max, mask, pend, dend) \
    do                                                               \
    {                                                                \
        (val) = (__s32)((__u32)(val) & (mask));                      \
        if ((__u32)(val) < (min) || (__u32)(val) > (max))            \
            return 0;                                                \
        barrier_var(val);                                            \
        if ((void *)(ptr) + (__u32)(val) > (const void *)(dend))     \
            return 0;                                                \
        barrier_var(ptr);                                            \
        if ((void *)(ptr) + (__u32)(val) > (const void *)(pend))     \
            return 0;                                                \
        (ptr) += (__u32)(val);                                       \
        barrier_var(ptr);                                            \
    } while (0)

// smallest 2^k-1 that is >= max: bounds a skip so the resulting pointer
// offset stays small enough for the verifier (see above). Must stay well
// below MAX_PACKET_OFF.
#define SKIP_MASK(max) \
    (((max) <= 0x3f) ? 0x3fu : ((max) <= 0xff) ? 0xffu : ((max) <= 0x3ff) ? 0x3ffu : ((max) <= 0xfff) ? 0xfffu : 0x1fffu)

// reads a fixed-size value into dest and advances ptr past it
#define READ_VAL_OR_RETURN(dest, ptr, pend, dend)               \
    do                                                          \
    {                                                           \
        CHECK_BOUNDS_OR_RETURN(ptr, sizeof(dest), pend, dend);  \
        (dest) = *(const __typeof__(dest) *)(ptr);              \
        (ptr) += sizeof(dest);                                  \
    } while (0)

// returns 0 from the calling function if the condition does not hold
#define ASSERT_OR_RETURN(cond) \
    do                         \
    {                          \
        if (!(cond))           \
            return 0;          \
    } while (0)

// returns 0 from the calling function if val is not in [min, max]
#define ASSERT_IN_RANGE_OR_RETURN(val, min, max) \
    do                                           \
    {                                            \
        if ((val) < (min) || (val) > (max))      \
            return 0;                            \
    } while (0)

// key identifying one TCP flow, the address and flow helpers and the
// per-connection state now live in flow.h / maps.h (both address families).

/*
 * Flag combinations that never occur on legitimate client traffic. Matches
 * return 0 (implausible) and are dropped silently so a scanner learns
 * nothing from the connection state. A client never sends SYN+ACK (that is
 * the server's reply), never mixes SYN with FIN/RST, and never uses URG.
 * Packets without any of SYN/ACK/FIN/RST (NULL scan) are always forged.
 *
 * Kept here (and not in the bpf-only headers) so the native unit tests can
 * exercise it directly.
 */
static __always_inline __u8 tcp_flags_are_plausible(const struct tcphdr *tcp)
{
    if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst)
    {
        return 0;
    }
    if (tcp->syn && (tcp->ack || tcp->fin || tcp->rst))
    {
        return 0;
    }
    if (tcp->urg)
    {
        return 0;
    }
    return 1;
}

#endif
