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

// key identifying one TCP flow (all fields in network byte order)
struct ipv4_flow_key
{
    const __u32 src_ip;
    const __u32 dst_ip;
    const __u16 src_port;
    const __u16 dst_port;
};
_Static_assert(sizeof(struct ipv4_flow_key) == 12, "ipv4_flow_key size mismatch!");

// per-connection tracking data while the handshake sequence is inspected
struct initial_state
{
    __u16 state;    // enum connection_state; u16 to keep the struct padding-free
    __u16 fails;    // out-of-order packets seen so far (see MAX_OUT_OF_ORDER)
    __s32 protocol; // minecraft protocol version (signed by protocol definition)
    __u32 expected_sequence;
};
_Static_assert(sizeof(struct initial_state) == 12, "initial_state size mismatch!");

static __always_inline struct ipv4_flow_key gen_ipv4_flow_key(const __u32 src_ip, const __u32 dst_ip, const __u16 src_port, const __u16 dst_port)
{
    struct ipv4_flow_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port};
    return key;
}

static __always_inline struct initial_state gen_initial_state(const __u16 state, const __s32 protocol, const __u32 expected_sequence)
{
    struct initial_state new_state = {
        .state = state,
        .fails = 0,
        .protocol = protocol,
        .expected_sequence = expected_sequence,
    };
    return new_state;
}

/* ------------------------------------------------------------------------
 * Stateless packet sanity checks
 *
 * All host-order where noted; kept header-only (not in the XDP translation
 * unit) so the native unit tests can exercise them directly.
 * --------------------------------------------------------------------- */

/*
 * Source addresses that can never belong to a legitimate client, in host
 * byte order:
 *   - 0.0.0.0/8       "this network" / unconfigured (also covers 0.0.0.0)
 *   - 169.254.0.0/16  link-local, clients are not reachable there
 *   - 224.0.0.0/4     multicast
 *   - 240.0.0.0/16    reserved, includes 255.255.255.255
 * Dropping these is nearly free and defeats the laziest spoofing tools.
 */
static __always_inline __u8 ipv4_is_reserved_src(const __u32 host_src)
{
    const __u8 top = (__u8)(host_src >> 24);
    if (top == 0 || top >= 224)
    {
        return 1;
    }
    if (top == 169 && (__u8)(host_src >> 16) == 254)
    {
        return 1;
    }
    return 0;
}

/*
 * Sources that are only reachable from inside the operator's own network
 * (host byte order): loopback, RFC1918, and CGNAT (100.64/10). Off by
 * default because a same-host proxy or a LAN monitoring host legitimately
 * connects from these ranges; turn it on when the protected service is
 * public-only. Never spoofed by an internet attacker, so the value here is
 * limiting self-inflicted noise and sloppy proxy configurations.
 */
static __always_inline __u8 ipv4_is_private_src(const __u32 host_src)
{
    const __u8 top = (__u8)(host_src >> 24);
    const __u8 second = (__u8)(host_src >> 16);
    if (top == 10 || top == 127)
    {
        return 1;
    }
    if (top == 192 && second == 168)
    {
        return 1;
    }
    if (top == 172 && second >= 16 && second <= 31)
    {
        return 1;
    }
    if (top == 100 && second >= 64 && second <= 127)
    {
        return 1;
    }
    return 0;
}

/*
 * Flag combinations that never occur on legitimate client traffic. Matches
 * return 0 (implausible) and are dropped silently so a scanner learns
 * nothing from the connection state. A client never sends SYN+ACK (that is
 * the server's reply), never mixes SYN with FIN/RST, and never uses URG.
 * Packets without any of SYN/ACK/FIN/RST (NULL scan) are always forged.
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
