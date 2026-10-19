#ifndef UDP_H
#define UDP_H

#include <linux/types.h>

#include "common.h"

/*
 * Stateless validation for the two udp protocols the filter understands:
 * bedrock (raknet) and simple voice chat.
 *
 * Only the *offline* raknet handshake messages have a fixed, documented
 * shape, so that is all this validates. Everything else (connected game
 * traffic) is validated by the egress pinhole instead (see egress.h) -
 * deliberately, because the connected raknet stream is version and
 * feature dependent and guessing at it would break custom server
 * software. Where raknet flavors differ between versions/forks the
 * checks stay permissive: over-accepting here is harmless (the stateful
 * gate still applies), while a false drop would break a real client.
 */

// raknet offline message magic: 00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78
#define RAKNET_MAGIC_W0 0x00ffff00u
#define RAKNET_MAGIC_W1 0xfefefefeu
#define RAKNET_MAGIC_W2 0xfdfdfdfdu
#define RAKNET_MAGIC_W3 0x12345678u

// upper bound for a raknet datagram payload (mtu probe frames stay < 1500)
#define RAKNET_MAX_DATAGRAM 1600

// magic_off is a compile-time constant at every call site, so all offsets
// below fold to constant packet accesses
static __always_inline __u8 raknet_magic_ok(const __u8 *payload, const __u16 payload_len,
                                            const __u8 magic_off, const void *data_end)
{
    if (magic_off > payload_len || (__u16)(payload_len - magic_off) < 16)
    {
        return 0;
    }
    const __u8 *m = payload + magic_off;
    if (!pkt_within(m, 16, data_end))
    {
        return 0;
    }
    __u32 w0, w1, w2, w3;
    __builtin_memcpy(&w0, m, 4);
    __builtin_memcpy(&w1, m + 4, 4);
    __builtin_memcpy(&w2, m + 8, 4);
    __builtin_memcpy(&w3, m + 12, 4);
    return bpf_ntohl(w0) == RAKNET_MAGIC_W0 && bpf_ntohl(w1) == RAKNET_MAGIC_W1 &&
           bpf_ntohl(w2) == RAKNET_MAGIC_W2 && bpf_ntohl(w3) == RAKNET_MAGIC_W3;
}

/*
 * Reads the last two bytes of a payload whose length the caller has already
 * bounded by RAKNET_MAX_DATAGRAM (the 0x05 handshake's mtu field).
 *
 * The offset is masked before it is added to the pointer on purpose: an
 * unmasked `payload + payload_len - 2` carries a variable offset as wide as
 * the length field itself (up to 64k), find_good_pkt_pointers() refuses to
 * derive a range for such a pointer (umax + off > MAX_PACKET_OFF), and the
 * load is rejected - even though the caller checked the length. The mask is
 * a no-op for every length that passed that check, so the read still hits
 * the real tail bytes; the pkt_within() below keeps the access safe
 * regardless.
 */
static __always_inline __u8 raknet_tail_u16_be(const __u8 *payload, const __u32 payload_len,
                                               __u16 *out, const void *data_end)
{
    _Static_assert(RAKNET_MAX_DATAGRAM <= 0x7ff, "tail mask must cover the datagram cap");
    const __u8 *at = payload + ((payload_len - 2) & 0x7ff);
    if (!pkt_within(at, 2, data_end))
    {
        return 0;
    }
    __u16 v;
    __builtin_memcpy(&v, at, 2);
    *out = bpf_ntohs(v);
    return 1;
}

/*
 * Validates one inbound raknet *offline* handshake message:
 *
 *   0x01  unconnected ping:      id(1) time(8) magic(16) guid(8)      = 33 bytes
 *   0x02  unconnected ping open: id(1) time(8) magic(16) guid(8) [+mtu]
 *   0x05  open connection req 1: id(1) magic(16) proto(1) pad(n) mtu(2)
 *   0x07  open connection req 2: id(1) magic(16) cookie(4) ...        >= 21 bytes
 *
 * Returns 1 for a plausible offline handshake, 0 otherwise. The protocol
 * version and mtu windows are only enforced when configured (strict mode /
 * mtu bounds), so custom forks keep working with the defaults.
 */
static __always_inline __u8 raknet_is_valid_offline(const __u8 *payload, const __u16 payload_len, const void *data_end,
                                                    const __u32 mtu_min, const __u32 mtu_max,
                                                    const __u8 strict_version, const __u32 proto_min, const __u32 proto_max)
{
    if (payload_len < 1 || !pkt_within(payload, 1, data_end))
    {
        return 0;
    }
    switch (payload[0])
    {
    case 0x01:
        return payload_len == 33 && raknet_magic_ok(payload, payload_len, 9, data_end);
    case 0x02:
        // some forks append the tested mtu, the base shape is identical
        return payload_len >= 33 && raknet_magic_ok(payload, payload_len, 9, data_end);
    case 0x05:
    {
        if (payload_len < 20 || payload_len > RAKNET_MAX_DATAGRAM)
        {
            return 0;
        }
        if (!raknet_magic_ok(payload, payload_len, 1, data_end))
        {
            return 0;
        }
        // mtu size: last two bytes
        __u16 mtu = 0;
        if (!raknet_tail_u16_be(payload, payload_len, &mtu, data_end))
        {
            return 0;
        }
        if (mtu < mtu_min || mtu > mtu_max)
        {
            return 0;
        }
        if (strict_version)
        {
            if (!pkt_within(payload, 19, data_end))
            {
                return 0;
            }
            const __u32 version = payload[17];
            if (version < proto_min || version > proto_max)
            {
                return 0;
            }
        }
        return 1;
    }
    case 0x07:
        // cookie response: fixed prefix only (the tail depends on the fork)
        return payload_len >= 21 && raknet_magic_ok(payload, payload_len, 1, data_end);
    default:
        return 0;
    }
}

/*
 * True when the payload's first byte is one of the *offline* handshake ids
 * handled by raknet_is_valid_offline(). Connected game traffic is either
 * encrypted with the 0x80 valid bit set or uses ids >= 0x80, so an inbound
 * datagram that starts with one of these ids really is a (claimed)
 * connection attempt. A client behind a proxy still sends well-formed
 * handshakes, and no legitimate flow can be rejected by a backend either:
 * what fails validation below was never deliverable.
 */
static __always_inline __u8 raknet_looks_like_offline_handshake(const __u8 *payload, const __u16 payload_len,
                                                               const void *data_end)
{
    if (payload_len < 1 || !pkt_within(payload, 1, data_end))
    {
        return 0;
    }
    switch (payload[0])
    {
    case 0x01: // unconnected ping
    case 0x02: // unconnected ping open connections
    case 0x05: // open connection request 1
    case 0x07: // open connection request 2
        return 1;
    default:
        return 0;
    }
}

/*
 * Shape check for a simple voice chat udp packet: one type byte in a
 * configurable range plus sane datagram bounds. The real gate for voice
 * is the verified-ip map / egress pinhole; this only filters obvious
 * garbage early and is permissive by default.
 */
static __always_inline __u8 voice_is_valid_shape(const __u8 *payload, const __u16 payload_len,
                                                 const void *data_end, const __u32 max_type)
{
    if (payload_len < 1 || payload_len > 1400)
    {
        return 0;
    }
    if (!pkt_within(payload, 1, data_end))
    {
        return 0;
    }
    return payload[0] <= max_type;
}

#endif
