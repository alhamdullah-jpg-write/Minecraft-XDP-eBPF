#ifndef STATS_H
#define STATS_H

#include <linux/types.h>

#include "config.h"

// selects which statistics count_stats() increments; a bitmask so related
// counters can be bumped in one call (e.g. DROPPED_PACKET | DROPPED_BYTES)
enum stats_mask
{
    VERIFIED          = 1u << 0,
    DROPPED_PACKET    = 1u << 1,
    STATE_SWITCH      = 1u << 2,
    DROP_CONNECTION   = 1u << 3,
    SYN_RECEIVE       = 1u << 4,
    TCP_BYPASS        = 1u << 5,
    INCOMING_BYTES    = 1u << 6,
    DROPPED_BYTES     = 1u << 7,
    VERIFIED_PACKET   = 1u << 8,
    IPV6_TRAFFIC      = 1u << 9,
    ALLOWLIST_PASS    = 1u << 10,
    UDP_TRAFFIC       = 1u << 11,
    EGRESS_ERRORS     = 1u << 12,
};

/*
 * Why a packet was dropped, one counter per reason in stats_map. The values
 * double as the index into `struct statistics.reason[]` and are the ABI of
 * the `minecraft_drop_reason` metric labels: never renumber existing
 * entries, only append. The loader derives the label list from this enum at
 * build time (build.rs), so the two can not drift apart; the human-readable
 * registry behind every name lives in docs/drop-reasons.md.
 *
 * Values 0..43 are the reasons this filter has always emitted. Values 44+
 * are the transcribed operator registry: their names are documented and
 * stable, most of them are reserved (no code path increments them yet), and
 * a few are already wired (DROP_PROXY_UNTRUSTED, DROP_MC_PACKET_RATE). The
 * authoritative emitted/reserved split is generated in docs/drop-reasons.md
 * from this enum and the code; do not hand-maintain it here.
 *
 * DROP_EMPTY_ACK is the one expected reason: the filter always drops the
 * empty ACK that finishes the TCP handshake, so a healthy server sees a
 * boring stream of them in dry-run/debug output.
 *
 * DROP_AUTOBLOCK / DROP_BLOCKLIST can fire on legitimate traffic when the
 * auto-blocker is wrong; both are therefore always visible as separate
 * counters and the auto-blocker runs in dry-run mode by default.
 */
enum drop_reason
{
    DROP_ETH_MALFORMED      = 0,  // frame shorter than the ethernet header / bad vlan tag
    DROP_IP_MALFORMED       = 1,  // bad version, ihl, total length, or truncated frame
    DROP_IP_FRAGMENT        = 2,  // first fragment towards an inspected port
    DROP_TCP_MALFORMED      = 3,  // tcp header truncated or doff < 5
    DROP_RESERVED_SOURCE    = 4,  // 0/8, 169.254/16, multicast, reserved
    DROP_PRIVATE_SOURCE     = 5,  // rfc1918, loopback, cgnat (optional)
    DROP_TCP_FLAGS          = 6,  // flags that clients never send
    DROP_SYN_PAYLOAD        = 7,  // SYN carrying data (tcp fast open)
    DROP_THROTTLE_LIMIT     = 8,  // per-ip new-connection window exceeded
    DROP_THROTTLE_STATE     = 9,  // throttle map full / insert or timer failure
    DROP_TRACK_STATE        = 10, // conntrack insert failed (lru map full)
    DROP_NOT_TRACKED        = 11, // no state for this flow (ack/rst/fin flood)
    DROP_BAD_ACK            = 12, // payload without ACK mid-handshake
    DROP_SEQUENCE_MISMATCH  = 13, // retransmission or out-of-order packet
    DROP_OUT_OF_ORDER_LIMIT = 14, // too many mismatches, whole connection dropped
    DROP_HANDSHAKE_INVALID  = 15, // minecraft handshake packet invalid
    DROP_LEGACY_PING        = 16, // pre-1.7 ping (0xFE)
    DROP_STATUS_INVALID     = 17, // status request packet invalid
    DROP_PING_INVALID       = 18, // ping request packet invalid
    DROP_LOGIN_INVALID      = 19, // login start packet invalid
    DROP_PING_EXTRA         = 20, // more data after a finished ping flow
    DROP_EMPTY_ACK          = 21, // the expected drop of the empty final ACK
    DROP_EMPTY_SEGMENT      = 22, // empty segment while the handshake is pending
    DROP_VERIFY_FAILED      = 23, // player map insert or timer setup failed
    DROP_VERIFY_MAP_FULL    = 24, // player map exhausted (raise max_player_connections)
    DROP_IPV6_MALFORMED     = 25, // bad ipv6 header, extension header chain, or length
    DROP_IPV6_FRAGMENT      = 26, // first fragment of an ipv6 fragmented packet
    DROP_UDP_MALFORMED      = 27, // udp header truncated or length mismatch
    DROP_BEDROCK_INVALID    = 28, // raknet handshake packet with wrong magic/length/mtu
    DROP_BEDROCK_UNTRACKED  = 29, // bedrock traffic without a matching egress pinhole
    DROP_VOICE_INVALID      = 30, // voice packet shape check failed
    DROP_VOICE_UNVERIFIED   = 31, // voice source ip has no verified minecraft connection
    DROP_RULE               = 32, // explicit drop rule matched
    DROP_RULE_MAGIC         = 33, // rule magic/length check failed
    DROP_RULE_RATE          = 34, // rule per-source rate exceeded
    DROP_SUBNET_LIMIT       = 35, // per-subnet new-connection window exceeded
    DROP_GLOBAL_LIMIT       = 36, // host-wide new-connection window exceeded
    DROP_UDP_LIMIT          = 37, // per-source udp packet window exceeded
    DROP_UNSOLICITED        = 38, // default-deny: no egress pinhole for this flow
    DROP_PROTO_DENY         = 39, // default-deny: protocol is not tracked at all
    DROP_BLOCKLIST          = 40, // operator blocklist entry
    DROP_AUTOBLOCK          = 41, // auto-block / ml block entry
    DROP_EGRESS_SEQ         = 42, // tcp sequence outside the egress-tracked window
    DROP_RATE_STATE         = 43, // rate map full / timer failure

    /* ---- reserved registry ------------------------------------------
     * Names below come from the operator-facing reason registry
     * (docs/drop-reasons.md). They keep a stable slot so planned
     * detections can use the documentation name without renumbering.
     * Most are reserved: NO code path increments the slot in this build,
     * so a zero counter does not prove the traffic was absent. The wired
     * exceptions (DROP_PROXY_UNTRUSTED, DROP_MC_PACKET_RATE) show up in
     * the emitted set that docs/drop-reasons.md generates from the code.
     */
    DROP_ETH_TRUNCATED                    = 44, // #1 ethernet header incomplete
    DROP_ETH_INVALID_LEN                  = 45, // #2 invalid ethernet frame length
    DROP_ETH_UNSUPPORTED_TYPE             = 46, // #3 unsupported ethertype
    DROP_ETH_UNKNOWN_PROTO                = 47, // #4 unknown network protocol
    DROP_ETH_BAD_HEADER                   = 48, // #5 malformed ethernet header
    DROP_ETH_SHORT_FRAME                  = 49, // #6 frame shorter than required
    DROP_ETH_TOO_LARGE                    = 50, // #7 frame exceeds configured limit
    DROP_ETH_VLAN_LIMIT                   = 51, // #8 too many vlan headers
    DROP_ETH_VLAN_MALFORMED               = 52, // #9 malformed vlan header
    DROP_ETH_DOUBLE_TAG                   = 53, // #10 unexpected double vlan tagging
    DROP_ETH_BAD_OFFSET                   = 54, // #11 invalid packet-header offset
    DROP_PKT_EMPTY                        = 55, // #12 empty packet
    DROP_PKT_TRUNCATED                    = 56, // #13 packet ends unexpectedly
    DROP_PKT_LENGTH_MISMATCH              = 57, // #14 declared and actual lengths disagree
    DROP_PKT_INVALID_BOUNDS               = 58, // #15 header exceeds packet boundaries
    DROP_PKT_UNSUPPORTED_FORMAT           = 59, // #16 unsupported packet format
    DROP_PKT_PARSE_FAILURE                = 60, // #17 general packet parsing failure
    DROP_PKT_HEADER_OVERFLOW              = 61, // #18 header length exceeds safe bounds
    DROP_PKT_INVALID_OFFSET               = 62, // #19 invalid field offset
    DROP_PKT_POLICY_REJECT                = 63, // #20 packet rejected by configured policy
    DROP_IPV4_TRUNCATED                   = 64, // #21 incomplete ipv4 header
    DROP_IPV4_BAD_VERSION                 = 65, // #22 invalid ip version field
    DROP_IPV4_BAD_IHL                     = 66, // #23 invalid ipv4 header length
    DROP_IPV4_BAD_TOTLEN                  = 67, // #24 invalid total length
    DROP_IPV4_BAD_CHECKSUM                = 68, // #25 invalid ipv4 header checksum
    DROP_IPV4_TTL_EXPIRED                 = 69, // #26 ttl policy rejected packet
    DROP_IPV4_RESERVED_FLAG               = 70, // #27 reserved flag rejected by policy
    DROP_IPV4_BAD_OPTIONS                 = 71, // #28 invalid ipv4 options
    DROP_IPV4_SOURCE_DENY                 = 72, // #29 source address is denied
    DROP_IPV4_DEST_DENY                   = 73, // #30 destination address is denied
    DROP_IPV4_BROADCAST                   = 74, // #31 disallowed broadcast traffic
    DROP_IPV4_MULTICAST                   = 75, // #32 disallowed multicast traffic
    DROP_IPV4_ZERO_SOURCE                 = 76, // #33 invalid zero source address
    DROP_IPV4_MARTIAN_SOURCE              = 77, // #34 invalid or unexpected source range
    DROP_IPV6_TRUNCATED                   = 78, // #35 incomplete ipv6 header
    DROP_IPV6_BAD_VERSION                 = 79, // #36 invalid ip version
    DROP_IPV6_BAD_PAYLOAD_LEN             = 80, // #37 invalid payload length
    DROP_IPV6_BAD_EXT_HEADER              = 81, // #38 malformed extension header
    DROP_IPV6_EXT_LIMIT                   = 82, // #39 extension-header count exceeds limit
    DROP_IPV6_HOP_LIMIT                   = 83, // #40 hop-limit policy rejected packet
    DROP_IP_FRAG_DENY                     = 84, // #41 ip fragmentation disabled by policy
    DROP_IP_FRAG_FIRST                    = 85, // #42 first fragment rejected by policy
    DROP_IP_FRAG_NONFIRST                 = 86, // #43 non-initial fragment cannot be validated
    DROP_IP_FRAG_OVERLAP                  = 87, // #44 fragment overlap detected
    DROP_IP_FRAG_TINY                     = 88, // #45 fragment below the configured minimum
    DROP_IP_FRAG_LIMIT                    = 89, // #46 fragment limit exceeded
    DROP_IP_FRAG_TIMEOUT                  = 90, // #47 fragment reassembly timeout
    DROP_IP_FRAG_BAD_OFFSET               = 91, // #48 invalid fragment offset
    DROP_IP_FRAG_BAD_LENGTH               = 92, // #49 invalid fragment length
    DROP_IP_FRAG_RATE                     = 93, // #50 fragment rate limit exceeded
    DROP_IPV6_FRAG_DENY                   = 94, // #51 ipv6 fragmentation prohibited by policy
    DROP_IPV6_FRAG_BAD                    = 95, // #52 malformed ipv6 fragment header
    DROP_IPV6_FRAG_LIMIT                  = 96, // #53 ipv6 fragment limit exceeded
    DROP_IPV6_ROUTING_HEADER              = 97, // #54 disallowed routing header
    DROP_IPV6_HOP_BY_HOP                  = 98, // #55 invalid hop-by-hop header
    DROP_IPV6_DEST_OPTIONS                = 99, // #56 invalid destination options
    DROP_IPV6_AH_HEADER                   = 100, // #57 disallowed authentication header
    DROP_IPV6_ESP_HEADER                  = 101, // #58 unsupported esp traffic
    DROP_IPV6_JUMBOGRAM                   = 102, // #59 unsupported jumbogram
    DROP_IP_REASSEMBLY_UNSUPPORTED        = 103, // #60 required reassembly not supported at this layer
    DROP_TCP_TRUNCATED                    = 104, // #61 incomplete tcp header
    DROP_TCP_BAD_DOFF                     = 105, // #62 invalid tcp data offset
    DROP_TCP_BAD_CHECKSUM                 = 106, // #63 invalid tcp checksum
    DROP_TCP_ZERO_PORT                    = 107, // #64 invalid zero port
    DROP_TCP_PORT_DENY                    = 108, // #65 destination port denied
    DROP_TCP_SOURCE_PORT_DENY             = 109, // #66 source port denied by policy
    DROP_TCP_SYN_DENY                     = 110, // #67 syn packet rejected by policy
    DROP_TCP_RST_POLICY                   = 111, // #68 reset packet rejected by policy
    DROP_TCP_FIN_POLICY                   = 112, // #69 fin packet rejected by policy
    DROP_TCP_NULL_FLAGS                   = 113, // #70 tcp null scan pattern detected
    DROP_TCP_XMAS_FLAGS                   = 114, // #71 tcp xmas scan pattern detected
    DROP_TCP_BAD_FLAGS                    = 115, // #72 invalid or forbidden flag combination
    DROP_TCP_SYN_FIN                      = 116, // #73 syn and fin flags combined
    DROP_TCP_SYN_RST                      = 117, // #74 syn and rst flags combined
    DROP_TCP_HEADER_OPTIONS               = 118, // #75 malformed tcp options
    DROP_TCP_OPTION_LIMIT                 = 119, // #76 tcp option count or length limit exceeded
    DROP_TCP_URG_POLICY                   = 120, // #77 urgent flag rejected by policy
    DROP_TCP_ECE_POLICY                   = 121, // #78 ece flag rejected by policy
    DROP_TCP_CWR_POLICY                   = 122, // #79 cwr flag rejected by policy
    DROP_TCP_INVALID_WINDOW               = 123, // #80 tcp window violates configured policy
    DROP_TCP_SYN_RATE                     = 124, // #81 syn rate limit exceeded
    DROP_TCP_SYN_BURST                    = 125, // #82 syn burst limit exceeded
    DROP_TCP_SYN_FLOOD                    = 126, // #83 syn flood threshold exceeded
    DROP_TCP_ACK_FLOOD                    = 127, // #84 ack flood threshold exceeded
    DROP_TCP_RST_FLOOD                    = 128, // #85 rst flood threshold exceeded
    DROP_TCP_FIN_FLOOD                    = 129, // #86 fin flood threshold exceeded
    DROP_TCP_PSH_FLOOD                    = 130, // #87 psh traffic threshold exceeded
    DROP_TCP_CONN_LIMIT                   = 131, // #88 connection limit exceeded
    DROP_TCP_NEW_CONN_LIMIT               = 132, // #89 new connection limit exceeded
    DROP_TCP_HALFOPEN_LIMIT               = 133, // #90 half-open connection limit exceeded
    DROP_TCP_BAD_STATE                    = 134, // #91 invalid connection state
    DROP_TCP_STATE_MISMATCH               = 135, // #92 packet inconsistent with tracked state
    DROP_TCP_SEQ_POLICY                   = 136, // #93 sequence-number policy violation
    DROP_TCP_ACK_POLICY                   = 137, // #94 acknowledgment-number policy violation
    DROP_TCP_RETRANSMIT_RATE              = 138, // #95 retransmission threshold exceeded
    DROP_TCP_IDLE_TIMEOUT                 = 139, // #96 connection exceeded idle timeout
    DROP_TCP_SOURCE_CONN_LIMIT            = 140, // #97 per-source connection limit exceeded
    DROP_TCP_DEST_CONN_LIMIT              = 141, // #98 per-destination connection limit exceeded
    DROP_TCP_HANDSHAKE_TIMEOUT            = 142, // #99 handshake did not complete in time
    DROP_TCP_BLACKLISTED                  = 143, // #100 tcp source is on a denylist
    DROP_UDP_TRUNCATED                    = 144, // #101 incomplete udp header
    DROP_UDP_BAD_LENGTH                   = 145, // #102 invalid udp length
    DROP_UDP_BAD_CHECKSUM                 = 146, // #103 invalid udp checksum
    DROP_UDP_ZERO_CHECKSUM                = 147, // #104 disallowed zero checksum
    DROP_UDP_PORT_DENY                    = 148, // #105 udp destination port denied
    DROP_UDP_SOURCE_PORT_DENY             = 149, // #106 udp source port denied
    DROP_UDP_RATE                         = 150, // #107 udp packet rate limit exceeded
    DROP_UDP_BURST                        = 151, // #108 udp burst threshold exceeded
    DROP_UDP_FLOOD                        = 152, // #109 udp flood threshold exceeded
    DROP_UDP_PAYLOAD_LIMIT                = 153, // #110 udp payload exceeds configured limit
    DROP_UDP_EMPTY_PAYLOAD                = 154, // #111 empty udp payload rejected by policy
    DROP_UDP_SOURCE_LIMIT                 = 155, // #112 per-source udp limit exceeded
    DROP_UDP_DEST_LIMIT                   = 156, // #113 per-destination udp limit exceeded
    DROP_UDP_INVALID_STATE                = 157, // #114 unexpected udp flow state
    DROP_UDP_DENYLIST                     = 158, // #115 udp source is on a denylist
    DROP_UDP_UNKNOWN_SERVICE              = 159, // #116 udp traffic targets an unsupported service
    DROP_UDP_AMPLIFICATION_POLICY         = 160, // #117 traffic matches an amplification-mitigation rule
    DROP_UDP_REFLECTION_PATTERN           = 161, // #118 traffic matches a reflection-attack rule
    DROP_UDP_FRAGMENT_RATE                = 162, // #119 udp fragment rate limit exceeded
    DROP_UDP_GLOBAL_LIMIT                 = 163, // #120 global udp rate limit exceeded
    DROP_MC_PORT_DENY                     = 164, // #121 minecraft service port is denied
    DROP_MC_PORT_MISMATCH                 = 165, // #122 traffic targets an unexpected port
    DROP_MC_SOURCE_DENY                   = 166, // #123 source address is denied for the service
    DROP_MC_DEST_DENY                     = 167, // #124 destination address is not allowed
    DROP_MC_IP_VERSION                    = 168, // #125 ip version violates service policy
    DROP_MC_PROTO_UNSUPPORTED             = 169, // #126 unsupported transport protocol
    DROP_MC_NON_TCP                       = 170, // #127 non-tcp traffic rejected on the java edition port
    DROP_MC_NON_UDP                       = 171, // #128 non-udp traffic rejected on a configured bedrock port
    DROP_MC_PROXY_ONLY                    = 172, // #129 direct traffic rejected on a proxy-only backend
    DROP_MC_PROXY_SOURCE                  = 173, // #130 source is not an approved proxy
    DROP_MC_BACKEND_DENY                  = 174, // #131 backend destination is not allowed
    DROP_MC_WRONG_INTERFACE               = 175, // #132 packet arrived on an unauthorized interface
    DROP_MC_WRONG_VLAN                    = 176, // #133 vlan does not match service policy
    DROP_MC_DRAINING                      = 177, // #134 new traffic rejected while draining a service
    DROP_MC_MAINTENANCE                   = 178, // #135 service is in maintenance mode
    DROP_MC_DISABLED                      = 179, // #136 minecraft service is disabled
    DROP_MC_SOURCE_LIMIT                  = 180, // #137 per-source service limit exceeded
    DROP_MC_CONN_RATE                     = 181, // #138 minecraft connection rate exceeded
    DROP_MC_GLOBAL_RATE                   = 182, // #139 minecraft service-wide rate exceeded
    DROP_MC_POLICY_DENY                   = 183, // #140 general minecraft traffic policy rejection
    DROP_MC_HANDSHAKE_SHORT               = 184, // #141 incomplete handshake data
    DROP_MC_HANDSHAKE_LENGTH              = 185, // #142 invalid handshake length
    DROP_MC_HANDSHAKE_VARINT              = 186, // #143 malformed handshake varint
    DROP_MC_HANDSHAKE_STATE               = 187, // #144 invalid next-state value
    DROP_MC_HANDSHAKE_PROTOCOL            = 188, // #145 protocol version rejected by policy
    DROP_MC_HANDSHAKE_HOST_LENGTH         = 189, // #146 hostname exceeds configured limit
    DROP_MC_HANDSHAKE_HOST_INVALID        = 190, // #147 invalid hostname encoding
    DROP_MC_HANDSHAKE_PORT                = 191, // #148 invalid handshake port
    DROP_MC_HANDSHAKE_RATE                = 192, // #149 handshake rate limit exceeded
    DROP_MC_HANDSHAKE_BURST               = 193, // #150 handshake burst limit exceeded
    DROP_MC_STATUS_RATE                   = 194, // #151 status request rate exceeded
    DROP_MC_STATUS_BURST                  = 195, // #152 status request burst exceeded
    DROP_MC_STATUS_INVALID                = 196, // #153 malformed status request
    DROP_MC_STATUS_REPEAT                 = 197, // #154 repeated status request violates policy
    DROP_MC_PING_RATE                     = 198, // #155 ping request rate exceeded
    DROP_MC_PING_INVALID                  = 199, // #156 invalid ping packet
    DROP_MC_PING_FLOOD                    = 200, // #157 ping flood threshold exceeded
    DROP_MC_STATUS_SCAN                   = 201, // #158 status scanning pattern detected
    DROP_MC_LEGACY_PING                   = 202, // #159 legacy ping rejected by policy
    DROP_MC_STATUS_GLOBAL                 = 203, // #160 global status endpoint limit exceeded
    DROP_MC_LOGIN_RATE                    = 204, // #161 login attempt rate exceeded
    DROP_MC_LOGIN_BURST                   = 205, // #162 login burst limit exceeded
    DROP_MC_LOGIN_FLOOD                   = 206, // #163 login flood threshold exceeded
    DROP_MC_LOGIN_TIMEOUT                 = 207, // #164 login phase timed out
    DROP_MC_LOGIN_LENGTH                  = 208, // #165 login packet exceeds configured length
    DROP_MC_LOGIN_MALFORMED               = 209, // #166 malformed login packet
    DROP_MC_LOGIN_NAME_LENGTH             = 210, // #167 username length violates policy
    DROP_MC_LOGIN_NAME_INVALID            = 211, // #168 username format rejected by policy
    DROP_MC_LOGIN_DUPLICATE               = 212, // #169 duplicate login attempt detected
    DROP_MC_LOGIN_SOURCE_LIMIT            = 213, // #170 per-source login limit exceeded
    DROP_MC_LOGIN_GLOBAL_LIMIT            = 214, // #171 global login limit exceeded
    DROP_MC_LOGIN_QUEUE_FULL              = 215, // #172 login queue is full
    DROP_MC_LOGIN_BACKLOG                 = 216, // #173 connection backlog policy triggered
    DROP_MC_AUTH_PENDING_LIMIT            = 217, // #174 pending authentication limit exceeded
    DROP_MC_AUTH_TIMEOUT                  = 218, // #175 authentication phase timed out
    DROP_MC_PROTOCOL_MISMATCH             = 219, // #176 protocol does not match supported versions
    DROP_MC_COMPRESSION_POLICY            = 220, // #177 compression policy violation
    DROP_MC_ENCRYPTION_POLICY             = 221, // #178 encryption policy violation
    DROP_MC_LOGIN_RETRY                   = 222, // #179 excessive login retries
    DROP_MC_CONNECTION_CHURN              = 223, // #180 repeated connect/disconnect behaviour exceeded limits
    DROP_MC_FRAME_EMPTY                   = 224, // #181 empty minecraft frame
    DROP_MC_FRAME_SHORT                   = 225, // #182 incomplete frame
    DROP_MC_FRAME_OVERSIZE                = 226, // #183 frame exceeds configured maximum
    DROP_MC_FRAME_VARINT                  = 227, // #184 malformed frame-length varint
    DROP_MC_FRAME_NEGATIVE                = 228, // #185 invalid negative frame length
    DROP_MC_FRAME_ZERO                    = 229, // #186 zero-length frame rejected by policy
    DROP_MC_FRAME_LENGTH_MISMATCH         = 230, // #187 frame length does not match available data
    DROP_MC_FRAME_INCOMPLETE              = 231, // #188 full frame has not arrived yet
    DROP_MC_FRAME_NESTED                  = 232, // #189 unexpected nested framing
    DROP_MC_FRAME_STATE                   = 233, // #190 frame invalid in the current protocol state
    DROP_MC_PACKET_ID                     = 234, // #191 unknown or disallowed packet id
    DROP_MC_PACKET_DIRECTION              = 235, // #192 packet direction violates policy
    DROP_MC_PACKET_LENGTH                 = 236, // #193 packet-specific length is invalid
    DROP_MC_PACKET_ORDER                  = 237, // #194 packet order violates protocol state
    DROP_MC_PACKET_RATE                   = 238, // #195 packet rate limit exceeded
    DROP_MC_PACKET_BURST                  = 239, // #196 packet burst threshold exceeded
    DROP_MC_PACKET_SPAM                   = 240, // #197 repeated packet pattern exceeds policy
    DROP_MC_PACKET_PARSE                  = 241, // #198 application packet parser failed
    DROP_MC_PACKET_STATE                  = 242, // #199 packet invalid for current connection state
    DROP_MC_PACKET_POLICY                 = 243, // #200 packet rejected by custom policy
    DROP_MC_MOVE_RATE                     = 244, // #201 movement packet rate exceeded
    DROP_MC_MOVE_BURST                    = 245, // #202 movement packet burst exceeded
    DROP_MC_MOVE_INVALID                  = 246, // #203 invalid movement packet
    DROP_MC_POSITION_BOUNDS               = 247, // #204 position violates configured bounds
    DROP_MC_ROTATION_INVALID              = 248, // #205 invalid rotation data
    DROP_MC_CHAT_RATE                     = 249, // #206 chat rate limit exceeded
    DROP_MC_CHAT_BURST                    = 250, // #207 chat burst threshold exceeded
    DROP_MC_CHAT_LENGTH                   = 251, // #208 chat packet exceeds size limit
    DROP_MC_COMMAND_RATE                  = 252, // #209 command rate limit exceeded
    DROP_MC_INTERACT_RATE                 = 253, // #210 interaction rate limit exceeded
    DROP_MC_ATTACK_RATE                   = 254, // #211 attack packet rate exceeded
    DROP_MC_USE_ITEM_RATE                 = 255, // #212 item-use packet rate exceeded
    DROP_MC_INVENTORY_RATE                = 256, // #213 inventory packet rate exceeded
    DROP_MC_CLICK_SPAM                    = 257, // #214 excessive inventory clicks
    DROP_MC_ENTITY_ACTION_RATE            = 258, // #215 entity-action packet rate exceeded
    DROP_MC_KEEPALIVE_TIMEOUT             = 259, // #216 keepalive timeout detected by connection tracker
    DROP_MC_KEEPALIVE_RATE                = 260, // #217 keepalive-related rate limit exceeded
    DROP_MC_PLUGIN_MESSAGE_SIZE           = 261, // #218 plugin-message size limit exceeded
    DROP_MC_CUSTOM_PAYLOAD                = 262, // #219 custom payload rejected by policy
    DROP_MC_PLAY_STATE                    = 263, // #220 packet invalid for play state
    DROP_DDOS_GLOBAL_PPS                  = 264, // #221 global packets-per-second threshold exceeded
    DROP_DDOS_GLOBAL_BPS                  = 265, // #222 global bits-per-second threshold exceeded
    DROP_DDOS_SOURCE_PPS                  = 266, // #223 source packets-per-second limit exceeded
    DROP_DDOS_SOURCE_BPS                  = 267, // #224 source bandwidth limit exceeded
    DROP_DDOS_PREFIX_RATE                 = 268, // #225 source-prefix rate exceeded
    DROP_DDOS_DEST_RATE                   = 269, // #226 destination rate exceeded
    DROP_DDOS_SYN_RATE                    = 270, // #227 syn mitigation threshold exceeded
    DROP_DDOS_UDP_RATE                    = 271, // #228 udp mitigation threshold exceeded
    DROP_DDOS_ICMP_RATE                   = 272, // #229 icmp rate exceeded
    DROP_DDOS_FRAGMENT_RATE               = 273, // #230 fragment flood threshold exceeded
    DROP_DDOS_CONNECTION_RATE             = 274, // #231 connection creation rate exceeded
    DROP_DDOS_NEW_FLOW_RATE               = 275, // #232 new-flow rate exceeded
    DROP_DDOS_SOURCE_FANOUT               = 276, // #233 one source contacts too many destinations
    DROP_DDOS_DEST_FANIN                  = 277, // #234 too many sources target one destination
    DROP_DDOS_PACKET_SIZE                 = 278, // #235 packet-size distribution violates policy
    DROP_DDOS_AMPLIFICATION               = 279, // #236 amplification mitigation rule triggered
    DROP_DDOS_REFLECTION                  = 280, // #237 reflection traffic pattern detected
    DROP_DDOS_SPOOFED_SOURCE              = 281, // #238 source fails configured anti-spoofing checks
    DROP_DDOS_SYN_COOKIE_POLICY           = 282, // #239 syn protection policy rejected traffic
    DROP_DDOS_EMERGENCY_MODE              = 283, // #240 emergency mitigation rule is active
    DROP_ACL_DENY                         = 284, // #241 explicit access-control deny
    DROP_ACL_DEFAULT                      = 285, // #242 default-deny policy
    DROP_IP_BLACKLIST                     = 286, // #243 source ip is blacklisted
    DROP_IP_PREFIX_BLACKLIST              = 287, // #244 source prefix is blacklisted
    DROP_IP_TEMP_BLOCK                    = 288, // #245 temporary ip block is active
    DROP_IP_REPUTATION                    = 289, // #246 ip reputation policy rejected traffic
    DROP_IP_GEO_POLICY                    = 290, // #247 geographic policy rejected traffic
    DROP_IP_ASN_POLICY                    = 291, // #248 asn policy rejected traffic
    DROP_IP_SPOOF_CHECK                   = 292, // #249 source validation failed
    DROP_IP_INVALID_SOURCE                = 293, // #250 source address is invalid
    DROP_IP_UNROUTABLE_SOURCE             = 294, // #251 source range is disallowed
    DROP_IP_RESERVED_RANGE                = 295, // #252 reserved ip range rejected by policy
    DROP_IP_BROADCAST_SOURCE              = 296, // #253 broadcast source rejected
    DROP_IP_MULTICAST_SOURCE              = 297, // #254 multicast source rejected
    DROP_IP_ALLOWLIST_REQUIRED            = 298, // #255 source is not on the allowlist
    DROP_IP_RATE_QUARANTINE               = 299, // #256 source quarantined for rate abuse
    DROP_IP_RECIDIVIST                    = 300, // #257 repeated abuse policy triggered
    DROP_IP_MANUAL_BLOCK                  = 301, // #258 administrator blocked the source
    DROP_IP_THREAT_FEED                   = 302, // #259 threat-feed rule matched
    DROP_IP_POLICY_EXPIRED                = 303, // #260 access policy is expired or invalid
    DROP_PROXY_UNTRUSTED                  = 304, // #261 untrusted proxy source
    DROP_PROXY_DIRECT_ACCESS              = 305, // #262 direct access to proxy-only backend
    DROP_PROXY_SOURCE_MISMATCH            = 306, // #263 source does not match proxy policy
    DROP_PROXY_HEADER_POLICY              = 307, // #264 forwarding-header policy rejected traffic
    DROP_PROXY_PROTOCOL_INVALID           = 308, // #265 invalid proxy protocol header
    DROP_PROXY_PROTOCOL_MISSING           = 309, // #266 required proxy protocol header absent
    DROP_PROXY_PROTOCOL_LENGTH            = 310, // #267 proxy protocol header length invalid
    DROP_PROXY_BACKEND_LIMIT              = 311, // #268 backend connection limit exceeded
    DROP_PROXY_BACKEND_UNAVAILABLE        = 312, // #269 backend is unavailable
    DROP_PROXY_BACKEND_DRAIN              = 313, // #270 backend is draining connections
    DROP_PROXY_ROUTE_DENY                 = 314, // #271 routing policy rejected traffic
    DROP_PROXY_DEST_MISMATCH              = 315, // #272 destination does not match route
    DROP_PROXY_SOURCE_LIMIT               = 316, // #273 proxy source connection limit exceeded
    DROP_PROXY_GLOBAL_LIMIT               = 317, // #274 global proxy limit exceeded
    DROP_PROXY_LOOP_DETECTED              = 318, // #275 forwarding loop detected
    DROP_PROXY_HEADER_TRUNCATED           = 319, // #276 incomplete forwarding header
    DROP_PROXY_HEADER_MALFORMED           = 320, // #277 malformed forwarding header
    DROP_PROXY_POLICY_DENY                = 321, // #278 proxy policy rejected traffic
    DROP_BACKEND_PORT_DENY                = 322, // #279 backend port denied
    DROP_BACKEND_SOURCE_DENY              = 323, // #280 backend source is not authorized
    DROP_MC_BOT_SCORE                     = 324, // #301 configured bot score threshold exceeded
    DROP_MC_RECONNECT_LOOP                = 325, // #302 reconnect frequency exceeded policy
    DROP_MC_STATUS_BOT                    = 326, // #303 status-query behaviour matched a bot rule
    DROP_MC_HANDSHAKE_BOT                 = 327, // #304 handshake behaviour matched a bot rule
    DROP_MC_LOGIN_BOT                     = 328, // #305 login behaviour matched a bot rule
    DROP_MC_SOURCE_FANOUT                 = 329, // #306 source generated too many connection attempts
    DROP_MC_PORT_SCAN                     = 330, // #307 port scanning behaviour detected
    DROP_MC_SERVICE_SCAN                  = 331, // #308 service scanning behaviour detected
    DROP_MC_PROTOCOL_SCAN                 = 332, // #309 protocol probing behaviour detected
    DROP_MC_INVALID_HOST                  = 333, // #310 host field rejected by configured policy
    DROP_MC_HOST_NOT_ALLOWED              = 334, // #311 virtual host is not on the allowlist
    DROP_MC_VERSION_POLICY                = 335, // #312 minecraft version policy rejected connection
    DROP_MC_RATE_QUARANTINE               = 336, // #313 source quarantined for excessive traffic
    DROP_MC_TEMP_BAN                      = 337, // #314 temporary minecraft traffic ban
    DROP_MC_PERM_BAN                      = 338, // #315 permanent traffic deny rule
    DROP_MC_GLOBAL_CONN_LIMIT             = 339, // #316 global minecraft connection limit exceeded
    DROP_MC_PENDING_LIMIT                 = 340, // #317 pending minecraft connection limit exceeded
    DROP_MC_IDLE_POLICY                   = 341, // #318 idle connection policy triggered
    DROP_MC_MITIGATION_MODE               = 342, // #319 minecraft-specific mitigation mode rejected traffic
    DROP_MC_CUSTOM_RULE                   = 343, // #320 custom minecraft rule matched
    DROP_MC_NULLPING                      = 344, // #321 login-slot flood: valid handshake+login at churn rates
};

// size of `struct statistics.reason[]`; power of two so the index can be
// masked (the verifier needs a provably in-bounds array index)
#define DROP_REASON_SLOTS 512

// one per-cpu slot of stats_map; must match `Statistics` in loader/metrics.rs
struct statistics
{
    __u64 verified;          // connections promoted to the verified fast path
    __u64 verified_packets;  // packets passed on the verified fast path
    __u64 dropped_packets;
    __u64 state_switches;
    __u64 drop_connection;
    __u64 syn;
    __u64 tcp_bypass;
    __u64 incoming_bytes;    // frame bytes on the filtered ports
    __u64 dropped_bytes;     // frame bytes dropped
    __u64 ipv6_packets;      // ipv6 packets seen on inspected ports (v4-only setups show 0)
    __u64 udp_packets;       // udp packets seen on the bedrock/voice ports
    __u64 egress_errors;     // egress tc program: packets it could not parse/track
    __u64 reason[DROP_REASON_SLOTS];
};
_Static_assert(sizeof(struct statistics) == 4192, "statistics size mismatch!");

/*
 * Adds `amount` to every counter selected by `bitmask`.
 *
 * stats_ptr is NULL whenever metrics are disabled (get_stats() returns NULL),
 * and the bitmasks are compile-time constants at every call site, so each
 * call reduces to the few increments that are actually selected.
 */
static __always_inline void count_stats(struct statistics *stats_ptr, const __u32 bitmask, const __u64 amount)
{
    if (!stats_ptr)
    {
        return;
    }

    if (bitmask & INCOMING_BYTES)
    {
        stats_ptr->incoming_bytes += amount;
    }

    if (bitmask & DROPPED_BYTES)
    {
        stats_ptr->dropped_bytes += amount;
    }

    if (bitmask & VERIFIED)
    {
        stats_ptr->verified += amount;
    }

    if (bitmask & VERIFIED_PACKET)
    {
        stats_ptr->verified_packets += amount;
    }

    if (bitmask & DROPPED_PACKET)
    {
        stats_ptr->dropped_packets += amount;
    }

    if (bitmask & STATE_SWITCH)
    {
        stats_ptr->state_switches += amount;
    }

    if (bitmask & DROP_CONNECTION)
    {
        stats_ptr->drop_connection += amount;
    }

    if (bitmask & SYN_RECEIVE)
    {
        stats_ptr->syn += amount;
    }

    if (bitmask & TCP_BYPASS)
    {
        stats_ptr->tcp_bypass += amount;
    }

    if (bitmask & IPV6_TRAFFIC)
    {
        stats_ptr->ipv6_packets += amount;
    }

    if (bitmask & UDP_TRAFFIC)
    {
        stats_ptr->udp_packets += amount;
    }

    if (bitmask & EGRESS_ERRORS)
    {
        stats_ptr->egress_errors += amount;
    }
}

#endif
