#ifndef RULES_H
#define RULES_H

#include "maps.h"

/*
 * Declarative rule engine for every port/protocol outside the minecraft
 * range: allow, drop, or per-source rate limit, with optional length and
 * magic checks. Rules are loaded from the config file, so any server
 * software (forks, modded ports, admin interfaces, ...) can be described
 * without touching the BPF program.
 */

static __always_inline struct rule *rule_lookup(const __u8 proto, const __be16 dport)
{
    const struct rule_key key = {.proto = proto, .port = dport};
    return bpf_map_lookup_elem(&rule_map, &key);
}

/*
 * Masked 8 byte compare at a fixed payload offset (the loader builds
 * magic/magic_mask from the configured hex string, so there is no
 * variable-length loop on the packet path). Returns 1 when the check
 * passes or is disabled.
 *
 * Two bounds: a scalar one against the declared payload length (semantics)
 * and a packet one against `data_end` (verifier). The packet check must be
 * against the real `data_end` and must come last: a comparison against a
 * derived pointer like `payload_end` cannot bound the load, because the
 * verifier cannot order two different variable packet pointers - and clang
 * happily drops the redundant-looking `data_end` check in favour of the
 * cheaper one if both are present.
 */
static __always_inline __u8 rule_magic_ok(const struct rule *rule, const __u8 *payload,
                                          const __u16 payload_len, const void *data_end)
{
    if (!rule->magic_mask)
    {
        return 1;
    }
    const __u32 off = rule->magic_off;
    if (off + 8 > (__u32)payload_len)
    {
        return 0;
    }
    const __u8 *at = payload + off; // magic_off is u8: bounded
    barrier_var(at);
    if ((const void *)(at + 8) > data_end)
    {
        return 0;
    }
    __u64 word;
    __builtin_memcpy(&word, at, 8);
    return ((word ^ rule->magic) & rule->magic_mask) == 0;
}

#endif
