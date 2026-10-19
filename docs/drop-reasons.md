# Drop reasons

Every packet the filter drops increments one counter in `struct statistics`
(`xdp/stats.h`), which the loader exports as
`minecraft_drop_reason{reason="<label>"}`. The label is the C enum name with
the `DROP_` prefix removed and lowercased (`DROP_THROTTLE_LIMIT` →
`throttle_limit`). `build.rs` parses the enum at build time and generates the
Rust label list from it, so the metric labels and the kernel can not drift
apart; **the enum is the ABI**:

- values are **append-only**: never renumber or reuse a value, alert rules and
  dashboards depend on them;
- `DROP_REASON_SLOTS` (512) is the size of the counter array in
  `struct statistics`; values beyond the enum are unused zero slots that a
  future release can fill without changing the struct size.

## How to read this document

The filter ships **two disjoint sets** of reasons, and the difference matters
when you alert:

| Set | What it means |
|---|---|
| **Emitted** | Some code path in `xdp/` assigns this reason. A non-zero counter is direct evidence of that drop; a zero counter means that class of traffic has not been dropped (yet) *by this build's code paths*. |
| **Reserved** | Documented, stable names for detections that are planned, optional, or live in other deployment branches. **No code path in this build increments them.** A zero counter here proves nothing about traffic — it only means "not implemented here". Never build an "this attack did not happen" conclusion on a reserved counter, and never page on one. |

`dry_run = true` counts *would-be* drops in the same counters while forwarding
the packets; `minecraft_dry_run` tells you which mode you are looking at, so
always pair a reason counter with that gauge before believing a number.

`empty_ack` is the one expected, healthy reason: the filter deliberately
swallows the empty ACK that finishes the TCP handshake, and the backend only
completes the connection when the first *inspected* data packet arrives.

## The emitted set

This is what the current build can actually drop. Everything else in the
registry below is reserved.

<!-- BEGIN GENERATED: emitted (edit xdp/stats.h, then run xdp/tests/gen_drop_reason_docs.py) -->

| Value | Name (`minecraft_drop_reason{reason=...}`) | Meaning | Emitted by |
|---|---|---|---|
| 0 | `eth_malformed` | frame shorter than the ethernet header / bad vlan tag | `xdp/minecraft_filter.c` |
| 1 | `ip_malformed` | bad version, ihl, total length, or truncated frame | `xdp/minecraft_filter.c` |
| 2 | `ip_fragment` | first fragment towards an inspected port | `xdp/minecraft_filter.c` |
| 3 | `tcp_malformed` | tcp header truncated or doff < 5 | `xdp/minecraft_filter.c` |
| 4 | `reserved_source` | 0/8, 169.254/16, multicast, reserved | `xdp/minecraft_filter.c` |
| 5 | `private_source` | rfc1918, loopback, cgnat (optional) | `xdp/minecraft_filter.c` |
| 6 | `tcp_flags` | flags that clients never send | `xdp/minecraft_filter.c` |
| 7 | `syn_payload` | SYN carrying data (tcp fast open) | `xdp/minecraft_filter.c` |
| 8 | `throttle_limit` | per-ip new-connection window exceeded | `xdp/minecraft_filter.c` |
| 9 | `throttle_state` | throttle map full / insert or timer failure | `xdp/minecraft_filter.c` |
| 10 | `track_state` | conntrack insert failed (lru map full) | `xdp/minecraft_filter.c` |
| 11 | `not_tracked` | no state for this flow (ack/rst/fin flood) | `xdp/minecraft_filter.c` |
| 12 | `bad_ack` | payload without ACK mid-handshake | `xdp/minecraft_filter.c` |
| 13 | `sequence_mismatch` | retransmission or out-of-order packet | `xdp/minecraft_filter.c` |
| 14 | `out_of_order_limit` | too many mismatches, whole connection dropped | `xdp/minecraft_filter.c` |
| 15 | `handshake_invalid` | minecraft handshake packet invalid | `xdp/minecraft_filter.c` |
| 16 | `legacy_ping` | pre-1.7 ping (0xFE) | `xdp/minecraft_filter.c` |
| 17 | `status_invalid` | status request packet invalid | `xdp/minecraft_filter.c` |
| 18 | `ping_invalid` | ping request packet invalid | `xdp/minecraft_filter.c` |
| 19 | `login_invalid` | login start packet invalid | `xdp/minecraft_filter.c` |
| 20 | `ping_extra` | more data after a finished ping flow | `xdp/minecraft_filter.c` |
| 21 | `empty_ack` | the expected drop of the empty final ACK | `xdp/minecraft_filter.c` |
| 22 | `empty_segment` | empty segment while the handshake is pending | `xdp/minecraft_filter.c` |
| 23 | `verify_failed` | player map insert or timer setup failed | `xdp/minecraft_filter.c` |
| 24 | `verify_map_full` | player map exhausted (raise max_player_connections) | `xdp/minecraft_filter.c` |
| 25 | `ipv6_malformed` | bad ipv6 header, extension header chain, or length | `xdp/minecraft_filter.c` |
| 26 | `ipv6_fragment` | first fragment of an ipv6 fragmented packet | `xdp/minecraft_filter.c` |
| 27 | `udp_malformed` | udp header truncated or length mismatch | `xdp/minecraft_filter.c` |
| 28 | `bedrock_invalid` | raknet handshake packet with wrong magic/length/mtu | `xdp/minecraft_filter.c` |
| 29 | `bedrock_untracked` | bedrock traffic without a matching egress pinhole | `xdp/minecraft_filter.c` |
| 30 | `voice_invalid` | voice packet shape check failed | `xdp/minecraft_filter.c` |
| 31 | `voice_unverified` | voice source ip has no verified minecraft connection | `xdp/minecraft_filter.c` |
| 32 | `rule` | explicit drop rule matched | `xdp/minecraft_filter.c` |
| 33 | `rule_magic` | rule magic/length check failed | `xdp/minecraft_filter.c` |
| 34 | `rule_rate` | rule per-source rate exceeded | `xdp/minecraft_filter.c` |
| 35 | `subnet_limit` | per-subnet new-connection window exceeded | `xdp/minecraft_filter.c` |
| 36 | `global_limit` | host-wide new-connection window exceeded | `xdp/minecraft_filter.c` |
| 37 | `udp_limit` | per-source udp packet window exceeded | `xdp/minecraft_filter.c` |
| 38 | `unsolicited` | default-deny: no egress pinhole for this flow | `xdp/minecraft_filter.c` |
| 39 | `proto_deny` | default-deny: protocol is not tracked at all | `xdp/minecraft_filter.c` |
| 40 | `blocklist` | operator blocklist entry | `xdp/minecraft_filter.c` |
| 41 | `autoblock` | auto-block / ml block entry | `xdp/minecraft_filter.c` |
| 42 | `egress_seq` | tcp sequence outside the egress-tracked window | `xdp/minecraft_filter.c` |
| 43 | `rate_state` | rate map full / timer failure | `xdp/minecraft_filter.c` |
| 238 | `mc_packet_rate` | packet rate limit exceeded | `xdp/minecraft_filter.c` |
| 304 | `proxy_untrusted` | untrusted proxy source | `xdp/minecraft_filter.c` |

<!-- END GENERATED: emitted -->

## The full registry

Every value with its stable name, meaning and (where it came from the
operator-facing registry) its registry number. Values 0–43 are the reasons
this filter has always emitted; 44+ are the transcribed registry; the
`Emitted` column of the previous table is authoritative, not this one.

<!-- BEGIN GENERATED: registry (edit xdp/stats.h, then run xdp/tests/gen_drop_reason_docs.py) -->

| Value | Registry | Name (`minecraft_drop_reason{reason=...}`) | Meaning | Referenced by |
|---|---|---|---|---|
| 0 |  | `eth_malformed` | frame shorter than the ethernet header / bad vlan tag | `xdp/minecraft_filter.c` |
| 1 |  | `ip_malformed` | bad version, ihl, total length, or truncated frame | `xdp/minecraft_filter.c` |
| 2 |  | `ip_fragment` | first fragment towards an inspected port | `xdp/minecraft_filter.c` |
| 3 |  | `tcp_malformed` | tcp header truncated or doff < 5 | `xdp/minecraft_filter.c` |
| 4 |  | `reserved_source` | 0/8, 169.254/16, multicast, reserved | `xdp/minecraft_filter.c` |
| 5 |  | `private_source` | rfc1918, loopback, cgnat (optional) | `xdp/minecraft_filter.c` |
| 6 |  | `tcp_flags` | flags that clients never send | `xdp/minecraft_filter.c` |
| 7 |  | `syn_payload` | SYN carrying data (tcp fast open) | `xdp/minecraft_filter.c` |
| 8 |  | `throttle_limit` | per-ip new-connection window exceeded | `xdp/minecraft_filter.c` |
| 9 |  | `throttle_state` | throttle map full / insert or timer failure | `xdp/minecraft_filter.c` |
| 10 |  | `track_state` | conntrack insert failed (lru map full) | `xdp/minecraft_filter.c` |
| 11 |  | `not_tracked` | no state for this flow (ack/rst/fin flood) | `xdp/minecraft_filter.c` |
| 12 |  | `bad_ack` | payload without ACK mid-handshake | `xdp/minecraft_filter.c` |
| 13 |  | `sequence_mismatch` | retransmission or out-of-order packet | `xdp/minecraft_filter.c` |
| 14 |  | `out_of_order_limit` | too many mismatches, whole connection dropped | `xdp/minecraft_filter.c` |
| 15 |  | `handshake_invalid` | minecraft handshake packet invalid | `xdp/minecraft_filter.c` |
| 16 |  | `legacy_ping` | pre-1.7 ping (0xFE) | `xdp/minecraft_filter.c` |
| 17 |  | `status_invalid` | status request packet invalid | `xdp/minecraft_filter.c` |
| 18 |  | `ping_invalid` | ping request packet invalid | `xdp/minecraft_filter.c` |
| 19 |  | `login_invalid` | login start packet invalid | `xdp/minecraft_filter.c` |
| 20 |  | `ping_extra` | more data after a finished ping flow | `xdp/minecraft_filter.c` |
| 21 |  | `empty_ack` | the expected drop of the empty final ACK | `xdp/minecraft_filter.c` |
| 22 |  | `empty_segment` | empty segment while the handshake is pending | `xdp/minecraft_filter.c` |
| 23 |  | `verify_failed` | player map insert or timer setup failed | `xdp/minecraft_filter.c` |
| 24 |  | `verify_map_full` | player map exhausted (raise max_player_connections) | `xdp/minecraft_filter.c` |
| 25 |  | `ipv6_malformed` | bad ipv6 header, extension header chain, or length | `xdp/minecraft_filter.c` |
| 26 |  | `ipv6_fragment` | first fragment of an ipv6 fragmented packet | `xdp/minecraft_filter.c` |
| 27 |  | `udp_malformed` | udp header truncated or length mismatch | `xdp/minecraft_filter.c` |
| 28 |  | `bedrock_invalid` | raknet handshake packet with wrong magic/length/mtu | `xdp/minecraft_filter.c` |
| 29 |  | `bedrock_untracked` | bedrock traffic without a matching egress pinhole | `xdp/minecraft_filter.c` |
| 30 |  | `voice_invalid` | voice packet shape check failed | `xdp/minecraft_filter.c` |
| 31 |  | `voice_unverified` | voice source ip has no verified minecraft connection | `xdp/minecraft_filter.c` |
| 32 |  | `rule` | explicit drop rule matched | `xdp/minecraft_filter.c` |
| 33 |  | `rule_magic` | rule magic/length check failed | `xdp/minecraft_filter.c` |
| 34 |  | `rule_rate` | rule per-source rate exceeded | `xdp/minecraft_filter.c` |
| 35 |  | `subnet_limit` | per-subnet new-connection window exceeded | `xdp/minecraft_filter.c` |
| 36 |  | `global_limit` | host-wide new-connection window exceeded | `xdp/minecraft_filter.c` |
| 37 |  | `udp_limit` | per-source udp packet window exceeded | `xdp/minecraft_filter.c` |
| 38 |  | `unsolicited` | default-deny: no egress pinhole for this flow | `xdp/minecraft_filter.c` |
| 39 |  | `proto_deny` | default-deny: protocol is not tracked at all | `xdp/minecraft_filter.c` |
| 40 |  | `blocklist` | operator blocklist entry | `xdp/minecraft_filter.c` |
| 41 |  | `autoblock` | auto-block / ml block entry | `xdp/minecraft_filter.c` |
| 42 |  | `egress_seq` | tcp sequence outside the egress-tracked window | `xdp/minecraft_filter.c` |
| 43 |  | `rate_state` | rate map full / timer failure | `xdp/minecraft_filter.c` |
| 44 | 1 | `eth_truncated` | ethernet header incomplete | — |
| 45 | 2 | `eth_invalid_len` | invalid ethernet frame length | — |
| 46 | 3 | `eth_unsupported_type` | unsupported ethertype | — |
| 47 | 4 | `eth_unknown_proto` | unknown network protocol | — |
| 48 | 5 | `eth_bad_header` | malformed ethernet header | — |
| 49 | 6 | `eth_short_frame` | frame shorter than required | — |
| 50 | 7 | `eth_too_large` | frame exceeds configured limit | — |
| 51 | 8 | `eth_vlan_limit` | too many vlan headers | — |
| 52 | 9 | `eth_vlan_malformed` | malformed vlan header | — |
| 53 | 10 | `eth_double_tag` | unexpected double vlan tagging | — |
| 54 | 11 | `eth_bad_offset` | invalid packet-header offset | — |
| 55 | 12 | `pkt_empty` | empty packet | — |
| 56 | 13 | `pkt_truncated` | packet ends unexpectedly | — |
| 57 | 14 | `pkt_length_mismatch` | declared and actual lengths disagree | — |
| 58 | 15 | `pkt_invalid_bounds` | header exceeds packet boundaries | — |
| 59 | 16 | `pkt_unsupported_format` | unsupported packet format | — |
| 60 | 17 | `pkt_parse_failure` | general packet parsing failure | — |
| 61 | 18 | `pkt_header_overflow` | header length exceeds safe bounds | — |
| 62 | 19 | `pkt_invalid_offset` | invalid field offset | — |
| 63 | 20 | `pkt_policy_reject` | packet rejected by configured policy | — |
| 64 | 21 | `ipv4_truncated` | incomplete ipv4 header | — |
| 65 | 22 | `ipv4_bad_version` | invalid ip version field | — |
| 66 | 23 | `ipv4_bad_ihl` | invalid ipv4 header length | — |
| 67 | 24 | `ipv4_bad_totlen` | invalid total length | — |
| 68 | 25 | `ipv4_bad_checksum` | invalid ipv4 header checksum | — |
| 69 | 26 | `ipv4_ttl_expired` | ttl policy rejected packet | — |
| 70 | 27 | `ipv4_reserved_flag` | reserved flag rejected by policy | — |
| 71 | 28 | `ipv4_bad_options` | invalid ipv4 options | — |
| 72 | 29 | `ipv4_source_deny` | source address is denied | — |
| 73 | 30 | `ipv4_dest_deny` | destination address is denied | — |
| 74 | 31 | `ipv4_broadcast` | disallowed broadcast traffic | — |
| 75 | 32 | `ipv4_multicast` | disallowed multicast traffic | — |
| 76 | 33 | `ipv4_zero_source` | invalid zero source address | — |
| 77 | 34 | `ipv4_martian_source` | invalid or unexpected source range | — |
| 78 | 35 | `ipv6_truncated` | incomplete ipv6 header | — |
| 79 | 36 | `ipv6_bad_version` | invalid ip version | — |
| 80 | 37 | `ipv6_bad_payload_len` | invalid payload length | — |
| 81 | 38 | `ipv6_bad_ext_header` | malformed extension header | — |
| 82 | 39 | `ipv6_ext_limit` | extension-header count exceeds limit | — |
| 83 | 40 | `ipv6_hop_limit` | hop-limit policy rejected packet | — |
| 84 | 41 | `ip_frag_deny` | ip fragmentation disabled by policy | — |
| 85 | 42 | `ip_frag_first` | first fragment rejected by policy | — |
| 86 | 43 | `ip_frag_nonfirst` | non-initial fragment cannot be validated | — |
| 87 | 44 | `ip_frag_overlap` | fragment overlap detected | — |
| 88 | 45 | `ip_frag_tiny` | fragment below the configured minimum | — |
| 89 | 46 | `ip_frag_limit` | fragment limit exceeded | — |
| 90 | 47 | `ip_frag_timeout` | fragment reassembly timeout | — |
| 91 | 48 | `ip_frag_bad_offset` | invalid fragment offset | — |
| 92 | 49 | `ip_frag_bad_length` | invalid fragment length | — |
| 93 | 50 | `ip_frag_rate` | fragment rate limit exceeded | — |
| 94 | 51 | `ipv6_frag_deny` | ipv6 fragmentation prohibited by policy | — |
| 95 | 52 | `ipv6_frag_bad` | malformed ipv6 fragment header | — |
| 96 | 53 | `ipv6_frag_limit` | ipv6 fragment limit exceeded | — |
| 97 | 54 | `ipv6_routing_header` | disallowed routing header | — |
| 98 | 55 | `ipv6_hop_by_hop` | invalid hop-by-hop header | — |
| 99 | 56 | `ipv6_dest_options` | invalid destination options | — |
| 100 | 57 | `ipv6_ah_header` | disallowed authentication header | — |
| 101 | 58 | `ipv6_esp_header` | unsupported esp traffic | — |
| 102 | 59 | `ipv6_jumbogram` | unsupported jumbogram | — |
| 103 | 60 | `ip_reassembly_unsupported` | required reassembly not supported at this layer | — |
| 104 | 61 | `tcp_truncated` | incomplete tcp header | — |
| 105 | 62 | `tcp_bad_doff` | invalid tcp data offset | — |
| 106 | 63 | `tcp_bad_checksum` | invalid tcp checksum | — |
| 107 | 64 | `tcp_zero_port` | invalid zero port | — |
| 108 | 65 | `tcp_port_deny` | destination port denied | — |
| 109 | 66 | `tcp_source_port_deny` | source port denied by policy | — |
| 110 | 67 | `tcp_syn_deny` | syn packet rejected by policy | — |
| 111 | 68 | `tcp_rst_policy` | reset packet rejected by policy | — |
| 112 | 69 | `tcp_fin_policy` | fin packet rejected by policy | — |
| 113 | 70 | `tcp_null_flags` | tcp null scan pattern detected | — |
| 114 | 71 | `tcp_xmas_flags` | tcp xmas scan pattern detected | — |
| 115 | 72 | `tcp_bad_flags` | invalid or forbidden flag combination | — |
| 116 | 73 | `tcp_syn_fin` | syn and fin flags combined | — |
| 117 | 74 | `tcp_syn_rst` | syn and rst flags combined | — |
| 118 | 75 | `tcp_header_options` | malformed tcp options | — |
| 119 | 76 | `tcp_option_limit` | tcp option count or length limit exceeded | — |
| 120 | 77 | `tcp_urg_policy` | urgent flag rejected by policy | — |
| 121 | 78 | `tcp_ece_policy` | ece flag rejected by policy | — |
| 122 | 79 | `tcp_cwr_policy` | cwr flag rejected by policy | — |
| 123 | 80 | `tcp_invalid_window` | tcp window violates configured policy | — |
| 124 | 81 | `tcp_syn_rate` | syn rate limit exceeded | — |
| 125 | 82 | `tcp_syn_burst` | syn burst limit exceeded | — |
| 126 | 83 | `tcp_syn_flood` | syn flood threshold exceeded | — |
| 127 | 84 | `tcp_ack_flood` | ack flood threshold exceeded | — |
| 128 | 85 | `tcp_rst_flood` | rst flood threshold exceeded | — |
| 129 | 86 | `tcp_fin_flood` | fin flood threshold exceeded | — |
| 130 | 87 | `tcp_psh_flood` | psh traffic threshold exceeded | — |
| 131 | 88 | `tcp_conn_limit` | connection limit exceeded | — |
| 132 | 89 | `tcp_new_conn_limit` | new connection limit exceeded | — |
| 133 | 90 | `tcp_halfopen_limit` | half-open connection limit exceeded | — |
| 134 | 91 | `tcp_bad_state` | invalid connection state | — |
| 135 | 92 | `tcp_state_mismatch` | packet inconsistent with tracked state | — |
| 136 | 93 | `tcp_seq_policy` | sequence-number policy violation | — |
| 137 | 94 | `tcp_ack_policy` | acknowledgment-number policy violation | — |
| 138 | 95 | `tcp_retransmit_rate` | retransmission threshold exceeded | — |
| 139 | 96 | `tcp_idle_timeout` | connection exceeded idle timeout | — |
| 140 | 97 | `tcp_source_conn_limit` | per-source connection limit exceeded | — |
| 141 | 98 | `tcp_dest_conn_limit` | per-destination connection limit exceeded | — |
| 142 | 99 | `tcp_handshake_timeout` | handshake did not complete in time | — |
| 143 | 100 | `tcp_blacklisted` | tcp source is on a denylist | — |
| 144 | 101 | `udp_truncated` | incomplete udp header | — |
| 145 | 102 | `udp_bad_length` | invalid udp length | — |
| 146 | 103 | `udp_bad_checksum` | invalid udp checksum | — |
| 147 | 104 | `udp_zero_checksum` | disallowed zero checksum | — |
| 148 | 105 | `udp_port_deny` | udp destination port denied | — |
| 149 | 106 | `udp_source_port_deny` | udp source port denied | — |
| 150 | 107 | `udp_rate` | udp packet rate limit exceeded | — |
| 151 | 108 | `udp_burst` | udp burst threshold exceeded | — |
| 152 | 109 | `udp_flood` | udp flood threshold exceeded | — |
| 153 | 110 | `udp_payload_limit` | udp payload exceeds configured limit | — |
| 154 | 111 | `udp_empty_payload` | empty udp payload rejected by policy | — |
| 155 | 112 | `udp_source_limit` | per-source udp limit exceeded | — |
| 156 | 113 | `udp_dest_limit` | per-destination udp limit exceeded | — |
| 157 | 114 | `udp_invalid_state` | unexpected udp flow state | — |
| 158 | 115 | `udp_denylist` | udp source is on a denylist | — |
| 159 | 116 | `udp_unknown_service` | udp traffic targets an unsupported service | — |
| 160 | 117 | `udp_amplification_policy` | traffic matches an amplification-mitigation rule | — |
| 161 | 118 | `udp_reflection_pattern` | traffic matches a reflection-attack rule | — |
| 162 | 119 | `udp_fragment_rate` | udp fragment rate limit exceeded | — |
| 163 | 120 | `udp_global_limit` | global udp rate limit exceeded | — |
| 164 | 121 | `mc_port_deny` | minecraft service port is denied | — |
| 165 | 122 | `mc_port_mismatch` | traffic targets an unexpected port | — |
| 166 | 123 | `mc_source_deny` | source address is denied for the service | — |
| 167 | 124 | `mc_dest_deny` | destination address is not allowed | — |
| 168 | 125 | `mc_ip_version` | ip version violates service policy | — |
| 169 | 126 | `mc_proto_unsupported` | unsupported transport protocol | — |
| 170 | 127 | `mc_non_tcp` | non-tcp traffic rejected on the java edition port | — |
| 171 | 128 | `mc_non_udp` | non-udp traffic rejected on a configured bedrock port | — |
| 172 | 129 | `mc_proxy_only` | direct traffic rejected on a proxy-only backend | — |
| 173 | 130 | `mc_proxy_source` | source is not an approved proxy | — |
| 174 | 131 | `mc_backend_deny` | backend destination is not allowed | — |
| 175 | 132 | `mc_wrong_interface` | packet arrived on an unauthorized interface | — |
| 176 | 133 | `mc_wrong_vlan` | vlan does not match service policy | — |
| 177 | 134 | `mc_draining` | new traffic rejected while draining a service | — |
| 178 | 135 | `mc_maintenance` | service is in maintenance mode | — |
| 179 | 136 | `mc_disabled` | minecraft service is disabled | — |
| 180 | 137 | `mc_source_limit` | per-source service limit exceeded | — |
| 181 | 138 | `mc_conn_rate` | minecraft connection rate exceeded | — |
| 182 | 139 | `mc_global_rate` | minecraft service-wide rate exceeded | — |
| 183 | 140 | `mc_policy_deny` | general minecraft traffic policy rejection | — |
| 184 | 141 | `mc_handshake_short` | incomplete handshake data | — |
| 185 | 142 | `mc_handshake_length` | invalid handshake length | — |
| 186 | 143 | `mc_handshake_varint` | malformed handshake varint | — |
| 187 | 144 | `mc_handshake_state` | invalid next-state value | — |
| 188 | 145 | `mc_handshake_protocol` | protocol version rejected by policy | — |
| 189 | 146 | `mc_handshake_host_length` | hostname exceeds configured limit | — |
| 190 | 147 | `mc_handshake_host_invalid` | invalid hostname encoding | — |
| 191 | 148 | `mc_handshake_port` | invalid handshake port | — |
| 192 | 149 | `mc_handshake_rate` | handshake rate limit exceeded | — |
| 193 | 150 | `mc_handshake_burst` | handshake burst limit exceeded | — |
| 194 | 151 | `mc_status_rate` | status request rate exceeded | — |
| 195 | 152 | `mc_status_burst` | status request burst exceeded | — |
| 196 | 153 | `mc_status_invalid` | malformed status request | — |
| 197 | 154 | `mc_status_repeat` | repeated status request violates policy | — |
| 198 | 155 | `mc_ping_rate` | ping request rate exceeded | — |
| 199 | 156 | `mc_ping_invalid` | invalid ping packet | — |
| 200 | 157 | `mc_ping_flood` | ping flood threshold exceeded | — |
| 201 | 158 | `mc_status_scan` | status scanning pattern detected | — |
| 202 | 159 | `mc_legacy_ping` | legacy ping rejected by policy | — |
| 203 | 160 | `mc_status_global` | global status endpoint limit exceeded | — |
| 204 | 161 | `mc_login_rate` | login attempt rate exceeded | — |
| 205 | 162 | `mc_login_burst` | login burst limit exceeded | — |
| 206 | 163 | `mc_login_flood` | login flood threshold exceeded | — |
| 207 | 164 | `mc_login_timeout` | login phase timed out | — |
| 208 | 165 | `mc_login_length` | login packet exceeds configured length | — |
| 209 | 166 | `mc_login_malformed` | malformed login packet | — |
| 210 | 167 | `mc_login_name_length` | username length violates policy | — |
| 211 | 168 | `mc_login_name_invalid` | username format rejected by policy | — |
| 212 | 169 | `mc_login_duplicate` | duplicate login attempt detected | — |
| 213 | 170 | `mc_login_source_limit` | per-source login limit exceeded | — |
| 214 | 171 | `mc_login_global_limit` | global login limit exceeded | — |
| 215 | 172 | `mc_login_queue_full` | login queue is full | — |
| 216 | 173 | `mc_login_backlog` | connection backlog policy triggered | — |
| 217 | 174 | `mc_auth_pending_limit` | pending authentication limit exceeded | — |
| 218 | 175 | `mc_auth_timeout` | authentication phase timed out | — |
| 219 | 176 | `mc_protocol_mismatch` | protocol does not match supported versions | — |
| 220 | 177 | `mc_compression_policy` | compression policy violation | — |
| 221 | 178 | `mc_encryption_policy` | encryption policy violation | — |
| 222 | 179 | `mc_login_retry` | excessive login retries | — |
| 223 | 180 | `mc_connection_churn` | repeated connect/disconnect behaviour exceeded limits | — |
| 224 | 181 | `mc_frame_empty` | empty minecraft frame | — |
| 225 | 182 | `mc_frame_short` | incomplete frame | — |
| 226 | 183 | `mc_frame_oversize` | frame exceeds configured maximum | — |
| 227 | 184 | `mc_frame_varint` | malformed frame-length varint | — |
| 228 | 185 | `mc_frame_negative` | invalid negative frame length | — |
| 229 | 186 | `mc_frame_zero` | zero-length frame rejected by policy | — |
| 230 | 187 | `mc_frame_length_mismatch` | frame length does not match available data | — |
| 231 | 188 | `mc_frame_incomplete` | full frame has not arrived yet | — |
| 232 | 189 | `mc_frame_nested` | unexpected nested framing | — |
| 233 | 190 | `mc_frame_state` | frame invalid in the current protocol state | — |
| 234 | 191 | `mc_packet_id` | unknown or disallowed packet id | — |
| 235 | 192 | `mc_packet_direction` | packet direction violates policy | — |
| 236 | 193 | `mc_packet_length` | packet-specific length is invalid | — |
| 237 | 194 | `mc_packet_order` | packet order violates protocol state | — |
| 238 | 195 | `mc_packet_rate` | packet rate limit exceeded | `xdp/minecraft_filter.c` |
| 239 | 196 | `mc_packet_burst` | packet burst threshold exceeded | — |
| 240 | 197 | `mc_packet_spam` | repeated packet pattern exceeds policy | — |
| 241 | 198 | `mc_packet_parse` | application packet parser failed | — |
| 242 | 199 | `mc_packet_state` | packet invalid for current connection state | — |
| 243 | 200 | `mc_packet_policy` | packet rejected by custom policy | — |
| 244 | 201 | `mc_move_rate` | movement packet rate exceeded | — |
| 245 | 202 | `mc_move_burst` | movement packet burst exceeded | — |
| 246 | 203 | `mc_move_invalid` | invalid movement packet | — |
| 247 | 204 | `mc_position_bounds` | position violates configured bounds | — |
| 248 | 205 | `mc_rotation_invalid` | invalid rotation data | — |
| 249 | 206 | `mc_chat_rate` | chat rate limit exceeded | — |
| 250 | 207 | `mc_chat_burst` | chat burst threshold exceeded | — |
| 251 | 208 | `mc_chat_length` | chat packet exceeds size limit | — |
| 252 | 209 | `mc_command_rate` | command rate limit exceeded | — |
| 253 | 210 | `mc_interact_rate` | interaction rate limit exceeded | — |
| 254 | 211 | `mc_attack_rate` | attack packet rate exceeded | — |
| 255 | 212 | `mc_use_item_rate` | item-use packet rate exceeded | — |
| 256 | 213 | `mc_inventory_rate` | inventory packet rate exceeded | — |
| 257 | 214 | `mc_click_spam` | excessive inventory clicks | — |
| 258 | 215 | `mc_entity_action_rate` | entity-action packet rate exceeded | — |
| 259 | 216 | `mc_keepalive_timeout` | keepalive timeout detected by connection tracker | — |
| 260 | 217 | `mc_keepalive_rate` | keepalive-related rate limit exceeded | — |
| 261 | 218 | `mc_plugin_message_size` | plugin-message size limit exceeded | — |
| 262 | 219 | `mc_custom_payload` | custom payload rejected by policy | — |
| 263 | 220 | `mc_play_state` | packet invalid for play state | — |
| 264 | 221 | `ddos_global_pps` | global packets-per-second threshold exceeded | — |
| 265 | 222 | `ddos_global_bps` | global bits-per-second threshold exceeded | — |
| 266 | 223 | `ddos_source_pps` | source packets-per-second limit exceeded | — |
| 267 | 224 | `ddos_source_bps` | source bandwidth limit exceeded | — |
| 268 | 225 | `ddos_prefix_rate` | source-prefix rate exceeded | — |
| 269 | 226 | `ddos_dest_rate` | destination rate exceeded | — |
| 270 | 227 | `ddos_syn_rate` | syn mitigation threshold exceeded | — |
| 271 | 228 | `ddos_udp_rate` | udp mitigation threshold exceeded | — |
| 272 | 229 | `ddos_icmp_rate` | icmp rate exceeded | — |
| 273 | 230 | `ddos_fragment_rate` | fragment flood threshold exceeded | — |
| 274 | 231 | `ddos_connection_rate` | connection creation rate exceeded | — |
| 275 | 232 | `ddos_new_flow_rate` | new-flow rate exceeded | — |
| 276 | 233 | `ddos_source_fanout` | one source contacts too many destinations | — |
| 277 | 234 | `ddos_dest_fanin` | too many sources target one destination | — |
| 278 | 235 | `ddos_packet_size` | packet-size distribution violates policy | — |
| 279 | 236 | `ddos_amplification` | amplification mitigation rule triggered | — |
| 280 | 237 | `ddos_reflection` | reflection traffic pattern detected | — |
| 281 | 238 | `ddos_spoofed_source` | source fails configured anti-spoofing checks | — |
| 282 | 239 | `ddos_syn_cookie_policy` | syn protection policy rejected traffic | — |
| 283 | 240 | `ddos_emergency_mode` | emergency mitigation rule is active | — |
| 284 | 241 | `acl_deny` | explicit access-control deny | — |
| 285 | 242 | `acl_default` | default-deny policy | — |
| 286 | 243 | `ip_blacklist` | source ip is blacklisted | — |
| 287 | 244 | `ip_prefix_blacklist` | source prefix is blacklisted | — |
| 288 | 245 | `ip_temp_block` | temporary ip block is active | — |
| 289 | 246 | `ip_reputation` | ip reputation policy rejected traffic | — |
| 290 | 247 | `ip_geo_policy` | geographic policy rejected traffic | — |
| 291 | 248 | `ip_asn_policy` | asn policy rejected traffic | — |
| 292 | 249 | `ip_spoof_check` | source validation failed | — |
| 293 | 250 | `ip_invalid_source` | source address is invalid | — |
| 294 | 251 | `ip_unroutable_source` | source range is disallowed | — |
| 295 | 252 | `ip_reserved_range` | reserved ip range rejected by policy | — |
| 296 | 253 | `ip_broadcast_source` | broadcast source rejected | — |
| 297 | 254 | `ip_multicast_source` | multicast source rejected | — |
| 298 | 255 | `ip_allowlist_required` | source is not on the allowlist | — |
| 299 | 256 | `ip_rate_quarantine` | source quarantined for rate abuse | — |
| 300 | 257 | `ip_recidivist` | repeated abuse policy triggered | — |
| 301 | 258 | `ip_manual_block` | administrator blocked the source | — |
| 302 | 259 | `ip_threat_feed` | threat-feed rule matched | — |
| 303 | 260 | `ip_policy_expired` | access policy is expired or invalid | — |
| 304 | 261 | `proxy_untrusted` | untrusted proxy source | `xdp/minecraft_filter.c` |
| 305 | 262 | `proxy_direct_access` | direct access to proxy-only backend | — |
| 306 | 263 | `proxy_source_mismatch` | source does not match proxy policy | — |
| 307 | 264 | `proxy_header_policy` | forwarding-header policy rejected traffic | — |
| 308 | 265 | `proxy_protocol_invalid` | invalid proxy protocol header | — |
| 309 | 266 | `proxy_protocol_missing` | required proxy protocol header absent | — |
| 310 | 267 | `proxy_protocol_length` | proxy protocol header length invalid | — |
| 311 | 268 | `proxy_backend_limit` | backend connection limit exceeded | — |
| 312 | 269 | `proxy_backend_unavailable` | backend is unavailable | — |
| 313 | 270 | `proxy_backend_drain` | backend is draining connections | — |
| 314 | 271 | `proxy_route_deny` | routing policy rejected traffic | — |
| 315 | 272 | `proxy_dest_mismatch` | destination does not match route | — |
| 316 | 273 | `proxy_source_limit` | proxy source connection limit exceeded | — |
| 317 | 274 | `proxy_global_limit` | global proxy limit exceeded | — |
| 318 | 275 | `proxy_loop_detected` | forwarding loop detected | — |
| 319 | 276 | `proxy_header_truncated` | incomplete forwarding header | — |
| 320 | 277 | `proxy_header_malformed` | malformed forwarding header | — |
| 321 | 278 | `proxy_policy_deny` | proxy policy rejected traffic | — |
| 322 | 279 | `backend_port_deny` | backend port denied | — |
| 323 | 280 | `backend_source_deny` | backend source is not authorized | — |
| 324 | 301 | `mc_bot_score` | configured bot score threshold exceeded | — |
| 325 | 302 | `mc_reconnect_loop` | reconnect frequency exceeded policy | — |
| 326 | 303 | `mc_status_bot` | status-query behaviour matched a bot rule | — |
| 327 | 304 | `mc_handshake_bot` | handshake behaviour matched a bot rule | — |
| 328 | 305 | `mc_login_bot` | login behaviour matched a bot rule | — |
| 329 | 306 | `mc_source_fanout` | source generated too many connection attempts | — |
| 330 | 307 | `mc_port_scan` | port scanning behaviour detected | — |
| 331 | 308 | `mc_service_scan` | service scanning behaviour detected | — |
| 332 | 309 | `mc_protocol_scan` | protocol probing behaviour detected | — |
| 333 | 310 | `mc_invalid_host` | host field rejected by configured policy | — |
| 334 | 311 | `mc_host_not_allowed` | virtual host is not on the allowlist | — |
| 335 | 312 | `mc_version_policy` | minecraft version policy rejected connection | — |
| 336 | 313 | `mc_rate_quarantine` | source quarantined for excessive traffic | — |
| 337 | 314 | `mc_temp_ban` | temporary minecraft traffic ban | — |
| 338 | 315 | `mc_perm_ban` | permanent traffic deny rule | — |
| 339 | 316 | `mc_global_conn_limit` | global minecraft connection limit exceeded | — |
| 340 | 317 | `mc_pending_limit` | pending minecraft connection limit exceeded | — |
| 341 | 318 | `mc_idle_policy` | idle connection policy triggered | — |
| 342 | 319 | `mc_mitigation_mode` | minecraft-specific mitigation mode rejected traffic | — |
| 343 | 320 | `mc_custom_rule` | custom minecraft rule matched | — |
| 344 | 321 | `mc_nullping` | login-slot flood: valid handshake+login at churn rates | — |

<!-- END GENERATED: registry -->

## Gaps and artifacts in the registry

Kept here so the numbering can be traced back to the source registry without
guessing:

- **Registry numbers 281–300 are missing** from the source list this enum was
  transcribed from. The values are simply absent — no entry was renamed, and
  no slot moved.
- The source table had a header row (`# Drop name / Reason`) that is not a
  reason; it has no value.
- Values 345–511 exist only as zeroed slots in `struct statistics`; nothing
  documents them yet, so a zero there is not meaningful either.
- `DROP_AUTOBLOCK` and `DROP_BLOCKLIST` can fire on legitimate traffic when
  the auto-blocker is wrong (that is why the auto-blocker has its own export
  file, strike counters and a dry-run default) and `DROP_THROTTLE_LIMIT` can
  fire at the top edge of a legitimate burst. Treat those three as the
  "possible false positive" family when reading dashboards.

## Regenerating

Both tables are generated from the enum in `xdp/stats.h`:

```sh
python3 xdp/tests/gen_drop_reason_docs.py          # rewrite this file
python3 xdp/tests/gen_drop_reason_docs.py --check  # fail if stale
```

The emitted set is computed mechanically: a reason counts as emitted when its
name appears in a compiled file under `xdp/` (a header or `.c`; test programs
under `xdp/tests/` do not count, and a mention in a comment still counts — the
column names the files so a suspicious entry can be eyeballed). To add a
reason: append it to the enum in `xdp/stats.h` (with a description), wire it in
the kernel code, then run the generator.
