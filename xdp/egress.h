#ifndef EGRESS_H
#define EGRESS_H

#include "limits.h"
#include "maps.h"

/*
 * Ingress side of the egress state tracking (the tc program fills
 * egress_flows, see minecraft_filter.c). A flow entry means: the host
 * itself sent traffic on this 5-tuple recently, so inbound packets that
 * match it are requested, not blind.
 *
 * For TCP the sequence is checked too: an unsolicited segment cannot
 * guess an ack that falls inside the sequence space the host actually
 * sent, which is what makes this a real stateful punch and not just a 5
 * tuple filter (blinded spoofing is impossible, blind reflection dies).
 */

// reverse lookup + freshness; returns the entry or NULL
static __always_inline struct egress_value *egress_pinhole(const struct flow_key *ingress_key,
                                                           const __u64 now, const __u64 timeout_ns)
{
    struct flow_key reverse;
    flow_key_reverse(ingress_key, &reverse);
    struct egress_value *entry = bpf_map_lookup_elem(&egress_flows, &reverse);
    if (!entry)
    {
        return NULL;
    }
    if (now - entry->last_seen_ns > timeout_ns)
    {
        return NULL; // stale: the host stopped talking on this flow
    }
    return entry;
}

#endif
