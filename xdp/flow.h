#ifndef FLOW_H
#define FLOW_H

#include <linux/types.h>

/*
 * Address and flow keys.
 *
 * One key layout for both address families: addresses are always stored as
 * 16 bytes, IPv4 in the v4-mapped form (::ffff:a.b.c.d). The family byte
 * keeps an IPv4 client from ever colliding with an IPv6 packet that
 * carries a v4-mapped source on the wire.
 *
 * The same 16 byte address representation feeds the LPM trie maps
 * (allowlist/blocklist): an IPv4 CIDR is inserted as ::ffff:x.y.z.0/96+len,
 * so a single trie holds both families.
 *
 * Everything here is pure (no map or helper access) so the native unit
 * tests can exercise it directly.
 */

#define ADDR_LEN 16

#define HOST_FAM_V4 4
#define HOST_FAM_V6 6

struct host_key
{
    __u8 family; // HOST_FAM_V4 / HOST_FAM_V6
    __u8 pad[3];
    __u8 addr[ADDR_LEN]; // v4: v4-mapped, v6: raw bytes
};
_Static_assert(sizeof(struct host_key) == 20, "host_key size mismatch!");

// identifies one direction of a flow; ports are network byte order
struct flow_key
{
    __u8 family;
    __u8 proto;
    __u8 pad[2];
    __u8 saddr[ADDR_LEN];
    __u8 daddr[ADDR_LEN];
    __be16 sport;
    __be16 dport;
};
_Static_assert(sizeof(struct flow_key) == 40, "flow_key size mismatch!");

// key layout of the two LPM tries (allowlist/blocklist); matches aya's
// LpmTrie Key<[u8; 16]> layout: u32 prefix length, then the address bytes
struct lpm_key
{
    __u32 prefixlen;
    __u8 addr[ADDR_LEN];
};
_Static_assert(sizeof(struct lpm_key) == 20, "lpm_key size mismatch!");

/* --------------------------------------------------------------------- */
/* address conversion                                                      */
/* --------------------------------------------------------------------- */

// 10 zero bytes, 0xff 0xff, then the 4 IPv4 bytes
static __always_inline void addr_from_v4(__u8 out[ADDR_LEN], const __be32 v4)
{
    __builtin_memset(out, 0, ADDR_LEN);
    out[10] = 0xff;
    out[11] = 0xff;
    __builtin_memcpy(&out[12], &v4, 4);
}

static __always_inline void addr_from_v6(__u8 out[ADDR_LEN], const __u8 in[ADDR_LEN])
{
    __builtin_memcpy(out, in, ADDR_LEN);
}

static __always_inline void host_key_from_v4(struct host_key *key, const __be32 src)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = HOST_FAM_V4;
    addr_from_v4(key->addr, src);
}

static __always_inline void host_key_from_v6(struct host_key *key, const __u8 src[ADDR_LEN])
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = HOST_FAM_V6;
    addr_from_v6(key->addr, src);
}

static __always_inline void flow_key_from_v4(struct flow_key *key, const __be32 saddr, const __be32 daddr,
                                             const __be16 sport, const __be16 dport, const __u8 proto)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = HOST_FAM_V4;
    key->proto = proto;
    addr_from_v4(key->saddr, saddr);
    addr_from_v4(key->daddr, daddr);
    key->sport = sport;
    key->dport = dport;
}

static __always_inline void flow_key_from_v6(struct flow_key *key, const __u8 saddr[ADDR_LEN], const __u8 daddr[ADDR_LEN],
                                             const __be16 sport, const __be16 dport, const __u8 proto)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = HOST_FAM_V6;
    key->proto = proto;
    addr_from_v6(key->saddr, saddr);
    addr_from_v6(key->daddr, daddr);
    key->sport = sport;
    key->dport = dport;
}

// builds a flow key from two host keys (the address family comes from src)
static __always_inline void flow_key_from_hosts(struct flow_key *key, const struct host_key *src, const struct host_key *dst,
                                                const __be16 sport, const __be16 dport, const __u8 proto)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = src->family;
    key->proto = proto;
    __builtin_memcpy(key->saddr, src->addr, ADDR_LEN);
    __builtin_memcpy(key->daddr, dst->addr, ADDR_LEN);
    key->sport = sport;
    key->dport = dport;
}

// swaps the endpoints: used to look up the egress flow a packet responds to
static __always_inline void flow_key_reverse(const struct flow_key *in, struct flow_key *out){
    __builtin_memset(out, 0, sizeof(*out));
    out->family = in->family;
    out->proto = in->proto;
    __builtin_memcpy(out->saddr, in->daddr, ADDR_LEN);
    __builtin_memcpy(out->daddr, in->saddr, ADDR_LEN);
    out->sport = in->dport;
    out->dport = in->sport;
}

// exact-match LPM key for a host (prefixlen 128 works for v4-mapped and v6
// alike: the mapped 96 bit prefix plus the 32 host bits)
static __always_inline void lpm_key_from_host(const struct host_key *host, struct lpm_key *out)
{
    out->prefixlen = 128;
    __builtin_memcpy(out->addr, host->addr, ADDR_LEN);
}

/* --------------------------------------------------------------------- */
/* stateless source classification                                          */
/* --------------------------------------------------------------------- */

/*
 * IPv4 source addresses that can never belong to a legitimate client, in
 * host byte order:
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
 * IPv6 sources that can never legitimately arrive from the internet:
 *   - ::           unspecified
 *   - ::1          loopback
 *   - ::ffff:0:0/96  v4-mapped: v4 traffic arrives as AF_INET, so a mapped
 *                    source on the wire is either a broken stack or a spoof
 *   - ff00::/8     multicast
 *   - fe80::/10    link-local
 * The 16 bytes are compared with constant offsets only; this is called
 * once per packet on the inspected paths and disappears with the flag off.
 */
static __always_inline __u8 ipv6_is_reserved_src(const __u8 addr[ADDR_LEN])
{
    __u8 nonzero = 0;
#pragma unroll
    for (int i = 0; i < ADDR_LEN; i++)
    {
        nonzero |= addr[i];
    }
    if (nonzero == 0) // ::
    {
        return 1;
    }
    // ::1: 15 zero bytes then 1
    if (addr[0] == 0 && addr[15] == 1 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
        addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
        addr[8] == 0 && addr[9] == 0 && addr[10] == 0 && addr[11] == 0 &&
        addr[12] == 0 && addr[13] == 0 && addr[14] == 0)
    {
        return 1;
    }
    if (addr[0] == 0xff) // ff00::/8 multicast
    {
        return 1;
    }
    if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80) // fe80::/10 link-local
    {
        return 1;
    }
    // ::ffff:0:0/96 v4-mapped
    if (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
        addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
        addr[8] == 0 && addr[9] == 0 && addr[10] == 0xff && addr[11] == 0xff)
    {
        return 1;
    }
    return 0;
}

/*
 * IPv6 sources that are only reachable from inside the operator's network:
 * unique local addresses (fc00::/7). The v4-mapped forms of the private
 * IPv4 ranges are already covered by ipv6_is_reserved_src().
 */
static __always_inline __u8 ipv6_is_private_src(const __u8 addr[ADDR_LEN])
{
    return (addr[0] & 0xfe) == 0xfc;
}

// reads the 4 IPv4 bytes back out of the v4-mapped form (network order)
static __always_inline __be32 v4_from_mapped(const __u8 addr[ADDR_LEN])
{
    __be32 v4;
    __builtin_memcpy(&v4, &addr[12], 4);
    return v4;
}

// convenience wrappers that take a host key by family
static __always_inline __u8 source_is_reserved(const __u8 family, const __u8 addr[ADDR_LEN])
{
    if (family == HOST_FAM_V4)
    {
        return ipv4_is_reserved_src(bpf_ntohl(v4_from_mapped(addr)));
    }
    return ipv6_is_reserved_src(addr);
}

static __always_inline __u8 source_is_private(const __u8 family, const __u8 addr[ADDR_LEN])
{
    if (family == HOST_FAM_V4)
    {
        return ipv4_is_private_src(bpf_ntohl(v4_from_mapped(addr)));
    }
    return ipv6_is_private_src(addr);
}

#endif
