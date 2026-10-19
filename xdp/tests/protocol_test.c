/*
 * Native unit tests for the eBPF parsing code (varint.h, protocol.h and the
 * bounds-check macros in common.h).
 *
 * Compiled for the host (not for BPF) and executed by tests/c_unit_tests.rs
 * as part of `cargo test`, with ASan/UBSan enabled when available. Every
 * inspector call runs on an exact-size heap copy of the packet, so any read
 * past data_end trips the address sanitizer instead of going unnoticed.
 */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// provided by bpf/bpf_helpers.h in the BPF build
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

// provided by bpf/bpf_endian.h in the BPF build
#ifndef bpf_ntohl
#define bpf_ntohl(value) __builtin_bswap32(value)
#endif
#ifndef bpf_ntohs
#define bpf_ntohs(value) __builtin_bswap16(value)
#endif
#ifndef bpf_htons
#define bpf_htons(value) __builtin_bswap16(value)
#endif
#ifndef bpf_htonl
#define bpf_htonl(value) __builtin_bswap32(value)
#endif

/*
 * Stand-in for xdp/config.h, suppressed via its include guard: the real header
 * defines the knobs `volatile const`, but the login tests need to flip
 * ONLINE_NAMES at runtime.
 */
#define CONFIG_H
static volatile __u8 ONLINE_NAMES = 1;

#include "../common.h"
#include "../varint.h"
#include "../protocol.h"
#include "../flow.h"
#include "../limits.h"
#include "../udp.h"

/* ------------------------------------------------------------------------
 * Tiny test framework
 * --------------------------------------------------------------------- */

static unsigned checks_run = 0;
static unsigned checks_failed = 0;

#define CHECK(cond)                                                          \
    do                                                                       \
    {                                                                        \
        checks_run++;                                                        \
        if (!(cond))                                                         \
        {                                                                    \
            checks_failed++;                                                 \
            printf("FAIL %s:%d in %s: %s\n", __FILE__, __LINE__, __func__,   \
                   #cond);                                                   \
        }                                                                    \
    } while (0)

/* ------------------------------------------------------------------------
 * Packet building helpers
 * --------------------------------------------------------------------- */

// reference varint encoder, validated against the wiki.vg test vectors below
static __u32 write_varint(__u8 *out, __s32 value)
{
    __u32 v = (__u32)value;
    __u32 n = 0;
    do
    {
        __u8 byte = v & 0x7F;
        v >>= 7;
        if (v)
        {
            byte |= 0x80;
        }
        out[n++] = byte;
    } while (v);
    return n;
}

struct buf
{
    __u8 b[2048];
    __u32 n;
};

static void put_varint(struct buf *p, __s32 value)
{
    p->n += write_varint(p->b + p->n, value);
}

static void put_u8(struct buf *p, __u8 value)
{
    p->b[p->n++] = value;
}

static void put_fill(struct buf *p, __u8 fill, __u32 count)
{
    memset(p->b + p->n, fill, count);
    p->n += count;
}

// prefixes a packet body with its length varint, like the protocol does
static struct buf packetize(const struct buf *body)
{
    struct buf pkt = {{0}, 0};
    put_varint(&pkt, (__s32)body->n);
    memcpy(pkt.b + pkt.n, body->b, body->n);
    pkt.n += body->n;
    return pkt;
}

/* ------------------------------------------------------------------------
 * Runners: every parse happens on an exact-size heap copy so ASan catches
 * any access past data_end. `slack` adds extra bytes between payload_end
 * and data_end to exercise the dual-bounds checks.
 * --------------------------------------------------------------------- */

static __u8 *heap_copy(const __u8 *bytes, __u32 len, __u32 slack)
{
    const __u32 size = len + slack;
    __u8 *heap = malloc(size ? size : 1); // malloc(0) may return NULL
    if (len)
    {
        memcpy(heap, bytes, len);
    }
    if (slack)
    {
        // 0x01 terminates a varint, so a parser that wrongly runs past
        // payload_end produces a successful-looking parse the assertions
        // can catch (instead of failing by coincidence)
        memset(heap + len, 0x01, slack);
    }
    return heap;
}

static struct varint_value run_varint_slack(const __u8 *bytes, __u32 payload_len, __u32 slack, __u8 max_size)
{
    __u8 *heap = heap_copy(bytes, payload_len, slack);
    const struct varint_value v =
        read_varint_sized(heap, heap + payload_len, max_size, heap + payload_len + slack);
    free(heap);
    return v;
}

static struct varint_value run_varint(const __u8 *bytes, __u32 payload_len, __u8 max_size)
{
    return run_varint_slack(bytes, payload_len, 0, max_size);
}

static __u8 run_status_slack(const __u8 *pkt, __u32 len, __u32 slack)
{
    __u8 *heap = heap_copy(pkt, len, slack);
    const __u8 ok = inspect_status_request(heap, heap + len, heap + len + slack);
    free(heap);
    return ok;
}

static __u8 run_status(const __u8 *pkt, __u32 len)
{
    return run_status_slack(pkt, len, 0);
}

static __u8 run_ping(const __u8 *pkt, __u32 len)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 ok = inspect_ping_request(heap, heap + len, heap + len);
    free(heap);
    return ok;
}

static __u8 run_login(const __u8 *pkt, __u32 len, __s32 protocol)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 ok = inspect_login_packet(heap, heap + len, heap + len, protocol);
    free(heap);
    return ok;
}

static __s32 run_handshake(const __u8 *pkt, __u32 len, __s32 *proto_out, __u32 *resume_off)
{
    __u8 *heap = heap_copy(pkt, len, 0);
    const __u8 *resume = NULL;
    __s32 proto = 0;
    const __s32 state = inspect_handshake(heap, heap + len, heap + len, &proto, &resume);
    if (proto_out)
    {
        *proto_out = proto;
    }
    if (resume_off)
    {
        *resume_off = resume ? (__u32)(resume - heap) : 0;
    }
    free(heap);
    return state;
}

/* ------------------------------------------------------------------------
 * VARINT_SIZE (compile-time)
 * --------------------------------------------------------------------- */

_Static_assert(VARINT_SIZE(0x00) == 1, "VARINT_SIZE(0)");
_Static_assert(VARINT_SIZE(0x7F) == 1, "VARINT_SIZE(127)");
_Static_assert(VARINT_SIZE(0x80) == 2, "VARINT_SIZE(128)");
_Static_assert(VARINT_SIZE(0x3FFF) == 2, "VARINT_SIZE(16383)");
_Static_assert(VARINT_SIZE(0x4000) == 3, "VARINT_SIZE(16384)");
_Static_assert(VARINT_SIZE(0x1FFFFF) == 3, "VARINT_SIZE(2097151)");
_Static_assert(VARINT_SIZE(0x200000) == 4, "VARINT_SIZE(2097152)");
_Static_assert(VARINT_SIZE(0xFFFFFFF) == 4, "VARINT_SIZE(268435455)");
_Static_assert(VARINT_SIZE(0x10000000) == 5, "VARINT_SIZE(268435456)");

/* ------------------------------------------------------------------------
 * Varint reader
 * --------------------------------------------------------------------- */

// test vectors from the protocol documentation (wiki.vg)
static const struct
{
    __u8 bytes[5];
    __u32 len;
    __s32 value;
} VARINT_VECTORS[] = {
    {{0x00}, 1, 0},
    {{0x01}, 1, 1},
    {{0x02}, 1, 2},
    {{0x7F}, 1, 127},
    {{0x80, 0x01}, 2, 128},
    {{0xFF, 0x01}, 2, 255},
    {{0xDD, 0xC7, 0x01}, 3, 25565},
    {{0xFF, 0xFF, 0x7F}, 3, 2097151},
    {{0xFF, 0xFF, 0xFF, 0xFF, 0x07}, 5, 2147483647},
    {{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, 5, -1},
    {{0x80, 0x80, 0x80, 0x80, 0x08}, 5, -2147483647 - 1},
};

static void test_varint_decodes_known_vectors(void)
{
    for (__u32 i = 0; i < sizeof(VARINT_VECTORS) / sizeof(VARINT_VECTORS[0]); i++)
    {
        const struct varint_value v =
            run_varint(VARINT_VECTORS[i].bytes, VARINT_VECTORS[i].len, MAX_VARINT_BYTES);
        CHECK(v.value == VARINT_VECTORS[i].value);
        CHECK(v.bytes == VARINT_VECTORS[i].len);

        // the encoder used by the packet builders must produce these
        // exact bytes, otherwise all later tests would test nothing
        __u8 encoded[5] = {0};
        const __u32 n = write_varint(encoded, VARINT_VECTORS[i].value);
        CHECK(n == VARINT_VECTORS[i].len);
        CHECK(memcmp(encoded, VARINT_VECTORS[i].bytes, n) == 0);
    }
}

static void test_varint_roundtrip(void)
{
    static const __s32 VALUES[] = {0,     1,        2,       127,        128,        255,
                                   300,   16383,    16384,   25565,      2097151,    2097152,
                                   -1,    -25565,   268435455, 268435456, 2147483647, -2147483647 - 1};
    for (__u32 i = 0; i < sizeof(VALUES) / sizeof(VALUES[0]); i++)
    {
        __u8 encoded[5];
        const __u32 n = write_varint(encoded, VALUES[i]);
        const struct varint_value v = run_varint(encoded, n, MAX_VARINT_BYTES);
        CHECK(v.value == VALUES[i]);
        CHECK(v.bytes == n);
    }
}

static void test_varint_rejects_truncated_input(void)
{
    const __u8 two_byte[] = {0x80, 0x01};
    CHECK(run_varint(two_byte, 1, MAX_VARINT_BYTES).bytes == 0); // continuation cut off
    CHECK(run_varint(two_byte, 0, MAX_VARINT_BYTES).bytes == 0); // empty payload

    const __u8 three_byte[] = {0xDD, 0xC7, 0x01};
    CHECK(run_varint(three_byte, 2, MAX_VARINT_BYTES).bytes == 0);
}

static void test_varint_respects_max_size(void)
{
    const __u8 two_byte[] = {0x80, 0x01};
    CHECK(run_varint(two_byte, 2, 1).bytes == 0);
    CHECK(run_varint(two_byte, 2, 2).bytes == 2);

    const __u8 three_byte[] = {0xDD, 0xC7, 0x01};
    CHECK(run_varint(three_byte, 3, 2).bytes == 0);
    CHECK(run_varint(three_byte, 3, 3).bytes == 3);
}

static void test_varint_never_reads_past_payload_end(void)
{
    // a continuation byte at the end of the payload, with valid-looking
    // bytes behind payload_end: must fail instead of reading the slack
    const __u8 bytes[] = {0x80};
    CHECK(run_varint_slack(bytes, 1, 4, MAX_VARINT_BYTES).bytes == 0);
}

static void test_varint_stops_at_terminator(void)
{
    // trailing bytes after a complete varint are someone else's business
    const __u8 bytes[] = {0x01, 0xFF, 0xFF};
    const struct varint_value v = run_varint(bytes, 3, MAX_VARINT_BYTES);
    CHECK(v.value == 1);
    CHECK(v.bytes == 1);
}

static void test_varint_rejects_overlong_encoding(void)
{
    // continuation bit still set on the fifth byte: a sixth byte would be
    // required, which no 32-bit varint may have
    const __u8 bytes[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
    CHECK(run_varint(bytes, 6, MAX_VARINT_BYTES).bytes == 0);
}

/* ------------------------------------------------------------------------
 * Bounds-check macros
 * --------------------------------------------------------------------- */

static __u8 wrap_check_bounds(const __u8 *cursor, __u32 n, const __u8 *pend, const void *dend)
{
    CHECK_BOUNDS_OR_RETURN(cursor, n, pend, dend);
    return 1;
}

static __u8 wrap_skip_twice(const __u8 *cursor, __u32 a, __u32 b, const __u8 *pend, const void *dend)
{
    SKIP_OR_RETURN(cursor, a, pend, dend);
    SKIP_OR_RETURN(cursor, b, pend, dend);
    return 1;
}

static __u8 wrap_read_u64(const __u8 *cursor, const __u8 *pend, const void *dend, __u64 *out)
{
    READ_VAL_OR_RETURN(*out, cursor, pend, dend);
    return 1;
}

static void test_bounds_macros(void)
{
    __u8 *heap = malloc(16);
    for (__u8 i = 0; i < 16; i++)
    {
        heap[i] = i;
    }
    const __u8 *pend = heap + 16;

    CHECK(wrap_check_bounds(heap, 16, pend, pend) == 1);
    CHECK(wrap_check_bounds(heap, 17, pend, pend) == 0);
    CHECK(wrap_check_bounds(heap + 16, 0, pend, pend) == 1);
    // payload_end binds even when data_end leaves room
    CHECK(wrap_check_bounds(heap, 10, heap + 8, pend) == 0);

    CHECK(wrap_skip_twice(heap, 8, 8, pend, pend) == 1);
    CHECK(wrap_skip_twice(heap, 8, 9, pend, pend) == 0);

    __u64 value = 0;
    CHECK(wrap_read_u64(heap, pend, pend, &value) == 1);
    CHECK(value == 0x0706050403020100ULL); // little endian
    // unaligned read is fine by design (network data)
    CHECK(wrap_read_u64(heap + 1, pend, pend, &value) == 1);
    CHECK(value == 0x0807060504030201ULL);
    CHECK(wrap_read_u64(heap + 9, pend, pend, &value) == 0);

    free(heap);
}

/* ------------------------------------------------------------------------
 * Status request: [len=0x01][id=0x00]
 * --------------------------------------------------------------------- */

static void test_status_request(void)
{
    const __u8 valid[] = {0x01, 0x00};
    CHECK(run_status(valid, 2) == 1);
    // bytes beyond payload_end must not change the verdict
    CHECK(run_status_slack(valid, 2, 8) == 1);

    const __u8 wrong_len[] = {0x02, 0x00};
    CHECK(run_status(wrong_len, 2) == 0);

    const __u8 wrong_id[] = {0x01, 0x01};
    CHECK(run_status(wrong_id, 2) == 0);

    const __u8 trailing[] = {0x01, 0x00, 0x00};
    CHECK(run_status(trailing, 3) == 0);

    const __u8 non_canonical_len[] = {0x81, 0x00, 0x00};
    CHECK(run_status(non_canonical_len, 3) == 0);

    CHECK(run_status(valid, 1) == 0);
    CHECK(run_status(valid, 0) == 0);
}

/* ------------------------------------------------------------------------
 * Ping request: [len=0x09][id=0x01][8 byte timestamp]
 * --------------------------------------------------------------------- */

static void test_ping_request(void)
{
    const __u8 valid[] = {0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(valid, 10) == 1);

    CHECK(run_ping(valid, 9) == 0); // truncated timestamp

    const __u8 wrong_id[] = {0x09, 0x00, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(wrong_id, 10) == 0);

    const __u8 wrong_len[] = {0x08, 0x01, 1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(run_ping(wrong_len, 10) == 0);

    const __u8 trailing[] = {0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    CHECK(run_ping(trailing, 11) == 0);
}

/* ------------------------------------------------------------------------
 * Handshake: [len][id=0x00][protocol][host len][host][port][intention]
 * --------------------------------------------------------------------- */

static struct buf build_handshake(__s32 protocol, __u32 host_len, __s32 intention)
{
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00); // packet id
    put_varint(&body, protocol);
    put_varint(&body, (__s32)host_len);
    put_fill(&body, 'h', host_len);
    put_u8(&body, 0x63); // port 25565
    put_u8(&body, 0xDD);
    put_varint(&body, intention);
    return packetize(&body);
}

static void test_handshake_intentions(void)
{
    __s32 proto = 0;

    struct buf status = build_handshake(763, 14, 1);
    CHECK(run_handshake(status.b, status.n, &proto, NULL) == AWAIT_STATUS_REQUEST);
    CHECK(proto == 763);

    struct buf login = build_handshake(763, 14, 2);
    CHECK(run_handshake(login.b, login.n, &proto, NULL) == AWAIT_LOGIN);

    // intention 3 (transfer) exists since 1.20.5 (766)
    struct buf transfer_new = build_handshake(766, 14, 3);
    CHECK(run_handshake(transfer_new.b, transfer_new.n, &proto, NULL) == AWAIT_LOGIN);
    struct buf transfer_old = build_handshake(765, 14, 3);
    CHECK(run_handshake(transfer_old.b, transfer_old.n, &proto, NULL) == STATE_INVALID);

    struct buf intention_zero = build_handshake(763, 14, 0);
    CHECK(run_handshake(intention_zero.b, intention_zero.n, &proto, NULL) == STATE_INVALID);
    struct buf intention_four = build_handshake(763, 14, 4);
    CHECK(run_handshake(intention_four.b, intention_four.n, &proto, NULL) == STATE_INVALID);
}

static void test_handshake_legacy_ping(void)
{
    const __u8 legacy[] = {0xFE, 0x01};
    CHECK(run_handshake(legacy, 2, NULL, NULL) == RECEIVED_LEGACY_PING);
    CHECK(run_handshake(legacy, 1, NULL, NULL) == RECEIVED_LEGACY_PING);
    CHECK(run_handshake(legacy, 0, NULL, NULL) == STATE_INVALID);
}

static void test_handshake_rejects_malformed(void)
{
    // wrong packet id
    struct buf body = {{0}, 0};
    put_varint(&body, 0x01); // packet id 1 instead of 0
    put_varint(&body, 763);
    put_varint(&body, 0);
    put_u8(&body, 0x63);
    put_u8(&body, 0xDD);
    put_varint(&body, 1);
    struct buf wrong_id = packetize(&body);
    CHECK(run_handshake(wrong_id.b, wrong_id.n, NULL, NULL) == STATE_INVALID);

    // truncated: every prefix of a valid handshake must be rejected
    struct buf valid = build_handshake(763, 14, 1);
    for (__u32 len = 0; len < valid.n; len++)
    {
        CHECK(run_handshake(valid.b, len, NULL, NULL) == STATE_INVALID);
    }

    // length field below the minimum (smallest possible body is 6 bytes)
    const __u8 len_too_small[] = {0x03, 0x00, 0x00};
    CHECK(run_handshake(len_too_small, 3, NULL, NULL) == STATE_INVALID);

    // length field above the maximum (787)
    struct buf len_too_big = {{0}, 0};
    put_varint(&len_too_big, 788);
    put_fill(&len_too_big, 0x00, 8);
    CHECK(run_handshake(len_too_big.b, len_too_big.n, NULL, NULL) == STATE_INVALID);

    // host longer than the protocol allows (255 * 3 = 765)
    struct buf host_too_long = build_handshake(763, 766, 1);
    CHECK(run_handshake(host_too_long.b, host_too_long.n, NULL, NULL) == STATE_INVALID);

    // the longest legal host must still parse
    struct buf host_max = build_handshake(763, 765, 1);
    CHECK(run_handshake(host_max.b, host_max.n, NULL, NULL) == AWAIT_STATUS_REQUEST);

    // empty host is allowed by the protocol bounds
    struct buf host_empty = build_handshake(763, 0, 1);
    CHECK(run_handshake(host_empty.b, host_empty.n, NULL, NULL) == AWAIT_STATUS_REQUEST);
}

static void test_handshake_combined_with_status_request(void)
{
    struct buf pkt = build_handshake(763, 14, 1);
    const __u32 handshake_len = pkt.n;
    put_u8(&pkt, 0x01); // status request appended in the same segment
    put_u8(&pkt, 0x00);

    __s32 proto = 0;
    __u32 resume = 0;
    CHECK(run_handshake(pkt.b, pkt.n, &proto, &resume) == DIRECT_READ_STATUS_REQUEST);
    CHECK(resume == handshake_len);
    CHECK(run_status(pkt.b + resume, pkt.n - resume) == 1);
}

static void test_handshake_combined_with_login(void)
{
    struct buf pkt = build_handshake(765, 14, 2);
    const __u32 handshake_len = pkt.n;

    struct buf login_body = {{0}, 0};
    put_varint(&login_body, 0x00); // packet id
    put_varint(&login_body, 5);    // username length
    put_fill(&login_body, 'a', 5);
    put_fill(&login_body, 0xAB, 16); // uuid (1.20.2+)
    struct buf login = packetize(&login_body);
    memcpy(pkt.b + pkt.n, login.b, login.n);
    pkt.n += login.n;

    __s32 proto = 0;
    __u32 resume = 0;
    CHECK(run_handshake(pkt.b, pkt.n, &proto, &resume) == DIRECT_READ_LOGIN);
    CHECK(resume == handshake_len);
    CHECK(proto == 765);
    CHECK(run_login(pkt.b + resume, pkt.n - resume, proto) == 1);
}

static void test_handshake_rejects_length_mismatch(void)
{
    // valid fields, but the declared length is off by one: the backend's
    // frame decoder would cut the stream at a different offset than the
    // filter's state machine
    struct buf too_big = build_handshake(763, 14, 1);
    too_big.b[0]++;
    CHECK(run_handshake(too_big.b, too_big.n, NULL, NULL) == STATE_INVALID);

    struct buf too_small = build_handshake(763, 14, 1);
    too_small.b[0]--;
    CHECK(run_handshake(too_small.b, too_small.n, NULL, NULL) == STATE_INVALID);

    // the appended status request must not be reachable through a lying
    // handshake length either (the backend would read its bytes as part of
    // the handshake frame)
    struct buf combined = build_handshake(763, 14, 1);
    combined.b[0]++;
    put_u8(&combined, 0x01);
    put_u8(&combined, 0x00);
    CHECK(run_handshake(combined.b, combined.n, NULL, NULL) == STATE_INVALID);
}

/* ------------------------------------------------------------------------
 * Login request, all protocol eras:
 *   < 759            [id][name]
 *   759 (1.19)       [id][name][key block]
 *   760 (1.19.1/2)   [id][name][key block][has uuid + uuid]
 *   761+ (1.19.3)    [id][name][has uuid + uuid]
 *   764+ (1.20.2)    [id][name][uuid]
 * --------------------------------------------------------------------- */

static struct buf build_simple_login(__u32 name_len)
{
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00); // packet id
    put_varint(&body, (__s32)name_len);
    put_fill(&body, 'a', name_len);
    return body; // callers append era-specific fields, then packetize
}

static void test_login_pre_1_19(void)
{
    struct buf body = build_simple_login(5);
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 47) == 1);  // 1.8
    CHECK(run_login(pkt.b, pkt.n, 758) == 1); // 1.18.2

    // 1.20.2+ requires a uuid after the name, so the same bytes must fail
    CHECK(run_login(pkt.b, pkt.n, 764) == 0);

    CHECK(run_login(pkt.b, pkt.n - 1, 47) == 0); // truncated
    put_u8(&pkt, 0x00);
    CHECK(run_login(pkt.b, pkt.n, 47) == 0); // trailing byte
    CHECK(run_login(pkt.b, 0, 47) == 0);     // empty payload
}

static void test_login_username_rules(void)
{
    // 16 chars is the online-mode maximum
    struct buf name16 = build_simple_login(16);
    struct buf pkt16 = packetize(&name16);
    CHECK(run_login(pkt16.b, pkt16.n, 758) == 1);

    struct buf name17 = build_simple_login(17);
    struct buf pkt17 = packetize(&name17);
    CHECK(run_login(pkt17.b, pkt17.n, 758) == 0);

    // offline mode allows up to 48 bytes (16 chars * 3 utf-8 bytes)
    ONLINE_NAMES = 0;
    CHECK(run_login(pkt17.b, pkt17.n, 758) == 1);
    struct buf name48 = build_simple_login(48);
    struct buf pkt48 = packetize(&name48);
    CHECK(run_login(pkt48.b, pkt48.n, 758) == 1);
    struct buf name49 = build_simple_login(49);
    struct buf pkt49 = packetize(&name49);
    CHECK(run_login(pkt49.b, pkt49.n, 758) == 0);
    ONLINE_NAMES = 1;

    // empty names are impossible
    struct buf name0 = build_simple_login(0);
    struct buf pkt0 = packetize(&name0);
    CHECK(run_login(pkt0.b, pkt0.n, 758) == 0);

    // a non-canonical two-byte encoding of name length 16 must be rejected
    // (the reader is limited to the canonical varint width)
    struct buf body = {{0}, 0};
    put_varint(&body, 0x00);
    put_u8(&body, 0x90); // 16 with a needless continuation byte
    put_u8(&body, 0x00);
    put_fill(&body, 'a', 16);
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 758) == 0);
}

static void test_login_1_19_key_block(void)
{
    // 1.19 - 1.19.2 (759/760): optional chat signing key after the name
    struct buf no_key = build_simple_login(5);
    put_u8(&no_key, 0x00); // has_public_key = false
    struct buf no_key_pkt = packetize(&no_key);
    CHECK(run_login(no_key_pkt.b, no_key_pkt.n, 759) == 1);

    struct buf with_key = build_simple_login(5);
    put_u8(&with_key, 0x01);       // has_public_key = true
    put_fill(&with_key, 0xEE, 8);  // expiry timestamp
    put_varint(&with_key, 16);     // key length
    put_fill(&with_key, 0xBB, 16); // key
    put_varint(&with_key, 32);     // signature length
    put_fill(&with_key, 0xCC, 32); // signature
    struct buf with_key_pkt = packetize(&with_key);
    CHECK(run_login(with_key_pkt.b, with_key_pkt.n, 759) == 1);

    // key larger than the protocol maximum (512)
    struct buf big_key = build_simple_login(5);
    put_u8(&big_key, 0x01);
    put_fill(&big_key, 0xEE, 8);
    put_varint(&big_key, 513);
    put_fill(&big_key, 0xBB, 513);
    put_varint(&big_key, 32);
    put_fill(&big_key, 0xCC, 32);
    struct buf big_key_pkt = packetize(&big_key);
    CHECK(run_login(big_key_pkt.b, big_key_pkt.n, 759) == 0);

    // 1.19.3 (761) dropped the key block again, so a packet carrying one
    // must be rejected there. (The no-key packet is coincidentally also a
    // valid 761 packet: its 0x00 then reads as has_uuid = false.)
    CHECK(run_login(with_key_pkt.b, with_key_pkt.n, 761) == 0);
    CHECK(run_login(no_key_pkt.b, no_key_pkt.n, 761) == 1);
}

static void test_login_uuid_eras(void)
{
    // 760 (1.19.1): key block, then optional uuid
    struct buf v760 = build_simple_login(5);
    put_u8(&v760, 0x00);          // has_public_key = false
    put_u8(&v760, 0x01);          // has_uuid = true
    put_fill(&v760, 0xAB, 16);    // uuid
    struct buf v760_pkt = packetize(&v760);
    CHECK(run_login(v760_pkt.b, v760_pkt.n, 760) == 1);

    struct buf v760_no_uuid = build_simple_login(5);
    put_u8(&v760_no_uuid, 0x00); // has_public_key = false
    put_u8(&v760_no_uuid, 0x00); // has_uuid = false
    struct buf v760_no_uuid_pkt = packetize(&v760_no_uuid);
    CHECK(run_login(v760_no_uuid_pkt.b, v760_no_uuid_pkt.n, 760) == 1);

    // 761/762 (1.19.3/4): no key block, optional uuid
    struct buf v762 = build_simple_login(5);
    put_u8(&v762, 0x01);
    put_fill(&v762, 0xAB, 16);
    struct buf v762_pkt = packetize(&v762);
    CHECK(run_login(v762_pkt.b, v762_pkt.n, 762) == 1);

    // 764+ (1.20.2): uuid always present, no flag
    struct buf v765 = build_simple_login(5);
    put_fill(&v765, 0xAB, 16);
    struct buf v765_pkt = packetize(&v765);
    CHECK(run_login(v765_pkt.b, v765_pkt.n, 765) == 1);

    // truncated uuid
    struct buf v765_short = build_simple_login(5);
    put_fill(&v765_short, 0xAB, 8);
    struct buf v765_short_pkt = packetize(&v765_short);
    CHECK(run_login(v765_short_pkt.b, v765_short_pkt.n, 765) == 0);
}

static void test_login_rejects_length_mismatch(void)
{
    // modern login (1.20.2+): name + uuid, with a length prefix off by one
    struct buf body = build_simple_login(5);
    put_fill(&body, 0xAB, 16); // uuid
    struct buf pkt = packetize(&body);
    CHECK(run_login(pkt.b, pkt.n, 765) == 1); // consistent length is fine

    pkt.b[0]++;
    CHECK(run_login(pkt.b, pkt.n, 765) == 0);

    pkt.b[0] -= 2;
    CHECK(run_login(pkt.b, pkt.n, 765) == 0);
}

/* ------------------------------------------------------------------------
 * Stateless sanity helpers (common.h)
 * --------------------------------------------------------------------- */

static void test_ipv4_source_classification(void)
{
    // reserved sources: never a legitimate client
    const __u32 reserved[] = {
        0x00000000u, // 0.0.0.0
        0x00000001u, // 0.0.0.1 (0/8)
        0x00FFFFFFu, // 0.255.255.255
        0xA9FE0001u, // 169.254.0.1 (link local)
        0xA9FEFFFFu, // 169.254.255.255
        0xE0000001u, // 224.0.0.1 (multicast)
        0xFFFFFFFFu, // 255.255.255.255 (240/4)
    };
    for (__u32 i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++)
    {
        CHECK(ipv4_is_reserved_src(reserved[i]) == 1);
    }

    CHECK(ipv4_is_reserved_src(0x08080808u) == 0); // 8.8.8.8
    CHECK(ipv4_is_reserved_src(0x01020304u) == 0); // 1.2.3.4
    CHECK(ipv4_is_reserved_src(0xA9FF0001u) == 0); // 169.255.0.1, not link local
    CHECK(ipv4_is_reserved_src(0xDFFFFFFFu) == 0); // 223.255.255.255, below 224/4

    // private sources: only flagged by the optional check
    const __u32 private[] = {
        0x7F000001u, // 127.0.0.1
        0x0A000001u, // 10.0.0.1
        0xAC100001u, // 172.16.0.1
        0xAC1FFFFFu, // 172.31.255.255
        0xC0A80101u, // 192.168.1.1
        0x64400001u, // 100.64.0.1 (cgnat)
        0x647FFFFFu, // 100.127.255.255
    };
    for (__u32 i = 0; i < sizeof(private) / sizeof(private[0]); i++)
    {
        CHECK(ipv4_is_private_src(private[i]) == 1);
    }

    CHECK(ipv4_is_private_src(0x0B000001u) == 0); // 11.0.0.1
    CHECK(ipv4_is_private_src(0xAC0F0001u) == 0); // 172.15.0.1, just outside
    CHECK(ipv4_is_private_src(0xAC200001u) == 0); // 172.32.0.1, just outside
    CHECK(ipv4_is_private_src(0x643F0001u) == 0); // 100.63.0.1, below cgnat
    CHECK(ipv4_is_private_src(0x64800001u) == 0); // 100.128.0.1, above cgnat
    CHECK(ipv4_is_private_src(0xC0A90101u) == 0); // 192.169.1.1
    CHECK(ipv4_is_private_src(0x08080808u) == 0); // 8.8.8.8
}

static struct tcphdr tcp_with_flags(__u8 syn, __u8 ack, __u8 fin, __u8 rst, __u8 urg)
{
    struct tcphdr tcp = {0};
    tcp.syn = syn;
    tcp.ack = ack;
    tcp.fin = fin;
    tcp.rst = rst;
    tcp.urg = urg;
    return tcp;
}

static void test_tcp_flags_plausible(void)
{
    // flag combinations a client sends
    struct tcphdr tcp = tcp_with_flags(1, 0, 0, 0, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 1); // SYN
    tcp = tcp_with_flags(0, 1, 0, 0, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 1); // ACK
    tcp = tcp_with_flags(0, 0, 1, 0, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 1); // FIN
    tcp = tcp_with_flags(0, 0, 0, 1, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 1); // RST
    tcp = tcp_with_flags(0, 1, 1, 0, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 1); // ACK+FIN (normal close)
    tcp = tcp_with_flags(0, 1, 0, 0, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 1); // ACK + data

    // combinations that are always forged or broken
    tcp = tcp_with_flags(0, 0, 0, 0, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 0); // NULL scan
    tcp = tcp_with_flags(1, 1, 0, 0, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 0); // SYN+ACK (server side only)
    tcp = tcp_with_flags(1, 0, 1, 0, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 0); // SYN+FIN
    tcp = tcp_with_flags(1, 0, 0, 1, 0);
    CHECK(tcp_flags_are_plausible(&tcp) == 0); // SYN+RST
    tcp = tcp_with_flags(0, 1, 0, 0, 1);
    CHECK(tcp_flags_are_plausible(&tcp) == 0); // URG
}

/* ------------------------------------------------------------------------
 * Range-checked variable skip (common.h)
 * --------------------------------------------------------------------- */

static __u8 wrap_skip_in_range(const __u8 **cursor, __s32 *value, __u32 min, __u32 max, __u32 mask,
                               const __u8 *pend, const void *dend)
{
    SKIP_IN_RANGE_OR_RETURN(*cursor, *value, min, max, mask, pend, dend);
    return 1;
}

static void test_skip_in_range_macro(void)
{
    __u8 *heap = malloc(64);
    const __u8 *pend = heap + 64;

    // an in-range value is used verbatim and advances the cursor
    const __u8 *cursor = heap;
    __s32 value = 16;
    CHECK(wrap_skip_in_range(&cursor, &value, 1, 765, 0x3ff, pend, pend) == 1);
    CHECK(cursor == heap + 16);
    CHECK(value == 16);

    // both bounds bind
    cursor = heap;
    value = 0;
    CHECK(wrap_skip_in_range(&cursor, &value, 1, 765, 0x3ff, pend, pend) == 0);
    cursor = heap;
    value = 766;
    CHECK(wrap_skip_in_range(&cursor, &value, 1, 765, 0x3ff, pend, pend) == 0);

    // 0 is allowed where min is 0 (key/signature skips)
    cursor = heap;
    value = 0;
    CHECK(wrap_skip_in_range(&cursor, &value, 0, 512, 0x3ff, pend, pend) == 1);
    CHECK(cursor == heap);

    // the payload_end bound binds even when data_end leaves room
    cursor = heap;
    value = 8;
    CHECK(wrap_skip_in_range(&cursor, &value, 1, 765, 0x3ff, heap + 4, heap + 64) == 0);

    // exact fit against payload_end
    cursor = heap;
    value = 8;
    CHECK(wrap_skip_in_range(&cursor, &value, 1, 765, 0x3ff, heap + 8, heap + 64) == 1);
    CHECK(cursor == heap + 8);

    // the mask can only ever reduce the value, never inflate it
    CHECK(SKIP_MASK(0) == 0x3f);
    CHECK(SKIP_MASK(16) == 0x3f);
    CHECK(SKIP_MASK(48) == 0x3f);
    CHECK(SKIP_MASK(255) == 0xff);
    CHECK(SKIP_MASK(256) == 0x3ff);
    CHECK(SKIP_MASK(765) == 0x3ff);
    CHECK(SKIP_MASK(512) == 0x3ff);
    CHECK(SKIP_MASK(4096) == 0x1fff);

    free(heap);
}

/* ------------------------------------------------------------------------
 * Flow keys, IPv6 classification and the pure limit helpers
 * --------------------------------------------------------------------- */

static void test_flow_key_layout(void)
{
    struct host_key src, dst;
    host_key_from_v4(&src, bpf_htonl(0x0A000001u)); // 10.0.0.1
    host_key_from_v4(&dst, bpf_htonl(0x0A000002u)); // 10.0.0.2
    CHECK(src.family == HOST_FAM_V4);
    CHECK(src.pad[0] == 0 && src.pad[1] == 0 && src.pad[2] == 0);
    CHECK(src.addr[10] == 0xff && src.addr[11] == 0xff);
    CHECK(src.addr[12] == 10 && src.addr[13] == 0 && src.addr[14] == 0 && src.addr[15] == 1);
    CHECK(v4_from_mapped(src.addr) == bpf_htonl(0x0A000001u));

    struct flow_key flow;
    flow_key_from_hosts(&flow, &src, &dst, bpf_htons(1234), bpf_htons(25565), 6);
    CHECK(flow.family == HOST_FAM_V4 && flow.proto == 6);
    CHECK(flow.sport == bpf_htons(1234) && flow.dport == bpf_htons(25565));
    CHECK(memcmp(flow.saddr, src.addr, 16) == 0);
    CHECK(memcmp(flow.daddr, dst.addr, 16) == 0);

    struct flow_key reverse;
    flow_key_reverse(&flow, &reverse);
    CHECK(memcmp(reverse.saddr, flow.daddr, 16) == 0);
    CHECK(memcmp(reverse.daddr, flow.saddr, 16) == 0);
    CHECK(reverse.sport == flow.dport && reverse.dport == flow.sport);
    CHECK(reverse.family == flow.family && reverse.proto == flow.proto);

    // reversing twice is the identity
    struct flow_key back;
    flow_key_reverse(&reverse, &back);
    CHECK(memcmp(&back, &flow, sizeof(flow)) == 0);

    // the family byte keeps a v4-mapped v6 packet from colliding with v4
    __u8 mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1};
    struct host_key as_v6;
    host_key_from_v6(&as_v6, mapped);
    CHECK(as_v6.family == HOST_FAM_V6);
    CHECK(memcmp(as_v6.addr, src.addr, 16) == 0);
    CHECK(memcmp(&as_v6, &src, sizeof(src)) != 0); // only the family byte differs

    // LPM key: exact match with prefixlen 128 for both families
    struct lpm_key lpm;
    lpm_key_from_host(&src, &lpm);
    CHECK(lpm.prefixlen == 128);
    CHECK(memcmp(lpm.addr, src.addr, 16) == 0);
}

static void test_ipv6_source_classification(void)
{
    __u8 unspecified[16] = {0};
    CHECK(ipv6_is_reserved_src(unspecified) == 1); // ::

    __u8 loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    CHECK(ipv6_is_reserved_src(loopback) == 1); // ::1

    __u8 multicast[16] = {0xff, 0x02};
    CHECK(ipv6_is_reserved_src(multicast) == 1); // ff02::/16 is inside ff00::/8

    __u8 link_local[16] = {0xfe, 0x80};
    link_local[15] = 1;
    CHECK(ipv6_is_reserved_src(link_local) == 1); // fe80::1

    __u8 site_local[16] = {0xfe, 0xc0};
    CHECK(ipv6_is_reserved_src(site_local) == 0); // fec0::/10 is not in the set

    __u8 mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4};
    CHECK(ipv6_is_reserved_src(mapped) == 1); // ::ffff:1.2.3.4 on the wire

    __u8 global[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    CHECK(ipv6_is_reserved_src(global) == 0); // 2001:db8::1
    CHECK(ipv6_is_private_src(global) == 0);

    __u8 ula[16] = {0xfd, 0x12};
    CHECK(ipv6_is_private_src(ula) == 1);  // fc00::/7
    CHECK(ipv6_is_reserved_src(ula) == 0);

    // the family dispatch routes each family to its own check
    struct host_key key;
    host_key_from_v4(&key, bpf_htonl(0x7F000001u)); // 127.0.0.1
    CHECK(source_is_reserved(key.family, key.addr) == 0);
    CHECK(source_is_private(key.family, key.addr) == 1);
    host_key_from_v6(&key, loopback);
    CHECK(source_is_reserved(key.family, key.addr) == 1);
    host_key_from_v6(&key, global);
    CHECK(source_is_reserved(key.family, key.addr) == 0);
}

static void test_subnet_masking(void)
{
    struct host_key host, subnet;
    host_key_from_v4(&host, bpf_htonl(0xC0A80A63u)); // 192.168.10.99
    subnet_key_from_host(&host, &subnet);
    CHECK(subnet.family == HOST_FAM_V4);
    CHECK(subnet.addr[12] == 192 && subnet.addr[13] == 168 && subnet.addr[14] == 10);
    CHECK(subnet.addr[15] == 0);

    // two addresses in one /24 share a bucket, the next /24 does not
    struct host_key other, other_subnet;
    host_key_from_v4(&other, bpf_htonl(0xC0A80A01u)); // 192.168.10.1
    subnet_key_from_host(&other, &other_subnet);
    CHECK(memcmp(&subnet, &other_subnet, sizeof(subnet)) == 0);
    host_key_from_v4(&other, bpf_htonl(0xC0A80B01u)); // 192.168.11.1
    subnet_key_from_host(&other, &other_subnet);
    CHECK(memcmp(&subnet, &other_subnet, sizeof(subnet)) != 0);

    // v6: the /64 keeps the first 8 bytes, zeroes the interface id
    __u8 addr[16] = {0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8};
    host_key_from_v6(&host, addr);
    subnet_key_from_host(&host, &subnet);
    CHECK(subnet.family == HOST_FAM_V6);
    CHECK(memcmp(subnet.addr, addr, 8) == 0);
    for (int i = 8; i < 16; i++)
    {
        CHECK(subnet.addr[i] == 0);
    }
}

static void test_rate_sliding_estimate(void)
{
    const __u64 window = 1000000000ull;
    // half the window elapsed: half of the previous window still counts
    CHECK(rate_sliding_estimate(10, 20, window / 2, window) == 20);
    // start of the window: the full previous window counts
    CHECK(rate_sliding_estimate(10, 20, 0, window) == 30);
    // quarter elapsed: three quarters of the previous window
    CHECK(rate_sliding_estimate(0, 1000, window / 4, window) == 750);
    // a full window (or more) elapsed: only the current window remains
    CHECK(rate_sliding_estimate(10, 20, window, window) == 10);
    CHECK(rate_sliding_estimate(10, 20, window * 2, window) == 10);
    // no window configured (never written by the loader) means no extrapolation
    CHECK(rate_sliding_estimate(7, 999, 0, 0) == 7);
}

static void test_egress_seq_in_window(void)
{
    // the remote side acks what we sent: ack in [base-1, next+1]
    CHECK(egress_seq_in_window(100, 100, 99) == 1);  // ack = base-1: the syn-ack
    CHECK(egress_seq_in_window(100, 100, 100) == 1); // ack = base
    CHECK(egress_seq_in_window(100, 150, 151) == 1); // ack = next+1: all data acked
    CHECK(egress_seq_in_window(100, 100, 98) == 0);  // before the window: blind
    CHECK(egress_seq_in_window(100, 150, 152) == 0); // beyond what we sent: blind
    // an unsolicited segment cannot guess an ack in the middle of the window
    CHECK(egress_seq_in_window(0, 4096, 2048) == 1);
    // near the top of the sequence space the comparisons still hold
    CHECK(egress_seq_in_window(0xFFFFFFFFFFFFFF00ull, 0xFFFFFFFFFFFFFF00ull + 16,
                               0xFFFFFFFFFFFFFF00ull + 8) == 1);
}

static void test_flow_flood_ok(void)
{
    const __u64 window = 1000000000ull;
    __u64 start = 0, packets = 0, bytes = 0;

    // both limits off: never touches the counters
    CHECK(flow_flood_ok(&start, &packets, &bytes, 500, 100, 0, 0, window) == 1);
    CHECK(start == 0 && packets == 0 && bytes == 0);

    // pps cap of 3: the 4th packet in the window is over the cap
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1000, 60, 3, 0, window) == 1);
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1100, 60, 3, 0, window) == 1);
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1200, 60, 3, 0, window) == 1);
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1300, 60, 3, 0, window) == 0);
    // ... but a new window recovers without any state being killed
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1000 + window, 60, 3, 0, window) == 1);
    CHECK(packets == 1);

    // byte cap of 200: counted independently of the packet cap
    start = 0;
    packets = 0;
    bytes = 0;
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1000, 150, 0, 200, window) == 1);
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1100, 150, 0, 200, window) == 0);
    // exactly at the cap passes, one byte over does not
    CHECK(bytes == 300);
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1000 + window, 200, 0, 200, window) == 1);
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1000 + window + 1, 1, 0, 200, window) == 0);

    // a stale window (clock going backwards is impossible, but a start in the
    // future must not wedge the entry) restarts instead of wrapping
    start = 5000;
    packets = 9;
    bytes = 9;
    CHECK(flow_flood_ok(&start, &packets, &bytes, 1000, 10, 1, 0, window) == 1);
    CHECK(start == 1000 && packets == 1 && bytes == 10);
}

static void test_proxy_header_detection(void)
{
    __u8 v1[16] = {'P', 'R', 'O', 'X', 'Y', ' ', 'T', 'C', 'P', '4'};
    CHECK(looks_like_proxy_header(v1, v1 + sizeof(v1), v1 + sizeof(v1)) == 1);
    // exactly the 6 byte prefix already classifies (payload ends there)
    __u8 prefix[6] = {'P', 'R', 'O', 'X', 'Y', ' '};
    CHECK(looks_like_proxy_header(prefix, prefix + 6, prefix + 6) == 1);
    // a truncated prefix can not be classified without reading past payload_end
    CHECK(looks_like_proxy_header(prefix, prefix + 5, prefix + 6) == 0);

    // PROXY v2 binary signature
    const __u8 v2[12] = {0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d,
                         0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a};
    CHECK(looks_like_proxy_header(v2, v2 + 12, v2 + 12) == 1);
    CHECK(looks_like_proxy_header(v2, v2 + 11, v2 + 12) == 0); // needs all 12
    __u8 bad[12];
    memcpy(bad, v2, sizeof(bad));
    bad[4] = 0x0b;
    CHECK(looks_like_proxy_header(bad, bad + 12, bad + 12) == 0);

    // ordinary minecraft payloads never match: a handshake, a legacy ping
    // and a lone 'P' (which is the frame length 80, not a prefix)
    __u8 handshake[8] = {0x10, 0x00, 0x02, 0x2f, 0x02, 'l', 'o', 'c'};
    CHECK(looks_like_proxy_header(handshake, handshake + sizeof(handshake), handshake + sizeof(handshake)) == 0);
    __u8 legacy[2] = {0xfe, 0x01};
    CHECK(looks_like_proxy_header(legacy, legacy + 2, legacy + 2) == 0);
    __u8 lone_p[6] = {'P', 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK(looks_like_proxy_header(lone_p, lone_p + 6, lone_p + 6) == 0);
}

static void put_raknet_magic(__u8 *at)
{
    const __u8 magic[16] = {0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
                            0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78};
    memcpy(at, magic, 16);
}

static void test_raknet_offline_validation(void)
{
    // 0x01 unconnected ping: exactly 33 bytes
    __u8 ping[33] = {0x01};
    put_raknet_magic(&ping[9]);
    CHECK(raknet_is_valid_offline(ping, sizeof(ping), ping + sizeof(ping), 1400, 1500, 0, 0, 255) == 1);
    CHECK(raknet_is_valid_offline(ping, sizeof(ping) - 1, ping + sizeof(ping), 1400, 1500, 0, 0, 255) == 0);
    __u8 ping_long[34] = {0x01};
    put_raknet_magic(&ping_long[9]);
    CHECK(raknet_is_valid_offline(ping_long, sizeof(ping_long), ping_long + sizeof(ping_long), 1400, 1500, 0, 0, 255) == 0);
    ping[12] ^= 0xff; // corrupted magic
    CHECK(raknet_is_valid_offline(ping, sizeof(ping), ping + sizeof(ping), 1400, 1500, 0, 0, 255) == 0);
    put_raknet_magic(&ping[9]);

    // 0x02 (open ping, some forks append the mtu): 33 bytes and up
    __u8 open_ping[35] = {0x02};
    put_raknet_magic(&open_ping[9]);
    CHECK(raknet_is_valid_offline(open_ping, 33, open_ping + 35, 1400, 1500, 0, 0, 255) == 1);
    CHECK(raknet_is_valid_offline(open_ping, 35, open_ping + 35, 1400, 1500, 0, 0, 255) == 1);
    CHECK(raknet_is_valid_offline(open_ping, 32, open_ping + 32, 1400, 1500, 0, 0, 255) == 0);

    // 0x05 open connection request 1: magic at offset 1, mtu in the last two bytes
    __u8 ocr1[20] = {0x05};
    put_raknet_magic(&ocr1[1]);
    ocr1[17] = 0x00; // protocol version byte
    ocr1[18] = 0x05; // mtu 1400, big endian
    ocr1[19] = 0x78;
    CHECK(raknet_is_valid_offline(ocr1, sizeof(ocr1), ocr1 + sizeof(ocr1), 1400, 1500, 0, 0, 255) == 1);
    ocr1[18] = 0x00; // mtu 1: below the window
    ocr1[19] = 0x01;
    CHECK(raknet_is_valid_offline(ocr1, sizeof(ocr1), ocr1 + sizeof(ocr1), 1400, 1500, 0, 0, 255) == 0);
    ocr1[18] = 0x0f; // mtu 4095: above the window
    ocr1[19] = 0xff;
    CHECK(raknet_is_valid_offline(ocr1, sizeof(ocr1), ocr1 + sizeof(ocr1), 1400, 1500, 0, 0, 255) == 0);
    ocr1[18] = 0x05;
    ocr1[19] = 0x78;
    ocr1[17] = 100; // protocol version byte outside the strict window
    CHECK(raknet_is_valid_offline(ocr1, sizeof(ocr1), ocr1 + sizeof(ocr1), 1400, 1500, 1, 10, 12) == 0);
    ocr1[17] = 11; // the historical raknet protocol version
    CHECK(raknet_is_valid_offline(ocr1, sizeof(ocr1), ocr1 + sizeof(ocr1), 1400, 1500, 1, 10, 12) == 1);
    ocr1[17] = 3; // permissive mode ignores the version byte
    CHECK(raknet_is_valid_offline(ocr1, sizeof(ocr1), ocr1 + sizeof(ocr1), 1400, 1500, 0, 10, 12) == 1);
    // a truncated packet is rejected even when the declared length fits
    CHECK(raknet_is_valid_offline(ocr1, sizeof(ocr1) - 1, ocr1 + sizeof(ocr1) - 1, 1400, 1500, 0, 0, 255) == 0);
    // oversize datagrams are rejected before any field is trusted
    static __u8 big[RAKNET_MAX_DATAGRAM + 1];
    memset(big, 0, sizeof(big));
    big[0] = 0x05;
    put_raknet_magic(&big[1]);
    CHECK(raknet_is_valid_offline(big, sizeof(big), big + sizeof(big), 1400, 1500, 0, 0, 255) == 0);

    // 0x07 open connection request 2: magic at offset 1, at least 21 bytes
    __u8 ocr2[21] = {0x07};
    put_raknet_magic(&ocr2[1]);
    CHECK(raknet_is_valid_offline(ocr2, sizeof(ocr2), ocr2 + sizeof(ocr2), 1400, 1500, 0, 0, 255) == 1);
    CHECK(raknet_is_valid_offline(ocr2, 20, ocr2 + sizeof(ocr2), 1400, 1500, 0, 0, 255) == 0);

    // connected traffic and empty payloads are not offline handshakes
    __u8 connected = 0xfe;
    CHECK(raknet_is_valid_offline(&connected, 1, &connected + 1, 1400, 1500, 0, 0, 255) == 0);
    CHECK(raknet_is_valid_offline(ping, 0, ping, 1400, 1500, 0, 0, 255) == 0);
}

static void test_raknet_offline_ids(void)
{
    // the four ids the offline validator understands are recognized as such
    // (that is what turns a malformed body into a provable reject: no
    // legitimate connected datagram starts with one of these ids)
    __u8 ping[33] = {0x01};
    CHECK(raknet_looks_like_offline_handshake(ping, sizeof(ping), ping + sizeof(ping)) == 1);
    __u8 open_ping[35] = {0x02};
    CHECK(raknet_looks_like_offline_handshake(open_ping, 33, open_ping + sizeof(open_ping)) == 1);
    __u8 ocr1[20] = {0x05};
    CHECK(raknet_looks_like_offline_handshake(ocr1, sizeof(ocr1), ocr1 + sizeof(ocr1)) == 1);
    __u8 ocr2[21] = {0x07};
    CHECK(raknet_looks_like_offline_handshake(ocr2, sizeof(ocr2), ocr2 + sizeof(ocr2)) == 1);

    // connected game traffic (0x80 valid bit) and raknet's own internal
    // datagram ids are not connection attempts
    __u8 game[4] = {0x84, 0x01, 0x02, 0x03};
    CHECK(raknet_looks_like_offline_handshake(game, sizeof(game), game + sizeof(game)) == 0);
    __u8 ack = 0xa0;
    CHECK(raknet_looks_like_offline_handshake(&ack, 1, &ack + 1) == 0);
    __u8 connection_request = 0x09;
    CHECK(raknet_looks_like_offline_handshake(&connection_request, 1, &connection_request + 1) == 0);
    __u8 garbage[10] = {'B', 'E', 'D', 'G', 'A', 'R', 'B', 'A', 'G', 'E'};
    CHECK(raknet_looks_like_offline_handshake(garbage, sizeof(garbage), garbage + sizeof(garbage)) == 0);

    // empty payloads (and a payload whose first byte is not in the frame)
    CHECK(raknet_looks_like_offline_handshake(garbage, 0, garbage) == 0);

    // and the combination the filter uses: a well-formed offline ping is
    // valid, the same packet with a corrupted magic is a handshake that
    // must be rejected statelessly
    put_raknet_magic(&ping[9]);
    CHECK(raknet_is_valid_offline(ping, sizeof(ping), ping + sizeof(ping), 1400, 1500, 0, 0, 255) == 1);
    ping[9] ^= 0xff;
    CHECK(raknet_looks_like_offline_handshake(ping, sizeof(ping), ping + sizeof(ping)) == 1);
    CHECK(raknet_is_valid_offline(ping, sizeof(ping), ping + sizeof(ping), 1400, 1500, 0, 0, 255) == 0);
}

static void test_voice_shape_check(void)
{
    __u8 packet[8] = {0x05, 1, 2, 3, 4, 5, 6, 7};
    CHECK(voice_is_valid_shape(packet, sizeof(packet), packet + sizeof(packet), 0x10) == 1);
    packet[0] = 0x11; // outside the configured type range
    CHECK(voice_is_valid_shape(packet, sizeof(packet), packet + sizeof(packet), 0x10) == 0);
    packet[0] = 0x00;
    CHECK(voice_is_valid_shape(packet, 0, packet + sizeof(packet), 0x10) == 0);
    static __u8 big[1401];
    memset(big, 1, sizeof(big));
    CHECK(voice_is_valid_shape(big, sizeof(big), big + sizeof(big), 0xff) == 0);
    CHECK(voice_is_valid_shape(big, 1400, big + 1400, 0xff) == 1);
}

/* --------------------------------------------------------------------- */

int main(void)
{
    test_varint_decodes_known_vectors();
    test_varint_roundtrip();
    test_varint_rejects_truncated_input();
    test_varint_respects_max_size();
    test_varint_never_reads_past_payload_end();
    test_varint_stops_at_terminator();
    test_varint_rejects_overlong_encoding();
    test_bounds_macros();
    test_status_request();
    test_ping_request();
    test_handshake_intentions();
    test_handshake_legacy_ping();
    test_handshake_rejects_malformed();
    test_handshake_combined_with_status_request();
    test_handshake_combined_with_login();
    test_handshake_rejects_length_mismatch();
    test_login_pre_1_19();
    test_login_username_rules();
    test_login_1_19_key_block();
    test_login_uuid_eras();
    test_login_rejects_length_mismatch();
    test_ipv4_source_classification();
    test_tcp_flags_plausible();
    test_skip_in_range_macro();
    test_flow_key_layout();
    test_ipv6_source_classification();
    test_subnet_masking();
    test_rate_sliding_estimate();
    test_egress_seq_in_window();
    test_flow_flood_ok();
    test_proxy_header_detection();
    test_raknet_offline_validation();
    test_raknet_offline_ids();
    test_voice_shape_check();

    printf("%u checks, %u failures\n", checks_run, checks_failed);
    return checks_failed ? 1 : 0;
}
