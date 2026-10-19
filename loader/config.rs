use anyhow::{Context, Result, bail};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Default configuration file written on first run, with documentation for
/// every option. Mirrors [`Config::default`].
pub const DEFAULT_CONFIG_TOML: &str = r#"# Minecraft XDP filter configuration.
# This file is applied at load time; restart the loader after editing.
# Every option is listed with its default value.

[filter]
# Inclusive TCP destination port range to protect.
# Use the same value for both to protect a single port.
start_port = 25565
end_port = 25565

# Sliding-window limits enforced in-kernel (see [autotune] for the runtime
# control loop). One window covers all of them; the window length is in
# milliseconds and capped at 4000 because of the kernel-side arithmetic.
# 0 disables the respective limit.
#
# Per-source IP new connections (SYNs) per window. Too low and a NAT/proxy
# shared by many players gets throttled; 10/s is a good starting point.
host_connection_limit = 10
# Per-subnet (/24 for IPv4, /64 for IPv6) new connections per window: bounds
# one abusive block without letting it eat the whole host-wide budget.
subnet_connection_limit = 64
# Host-wide admission limit for new connections per window (0 = disabled).
# During a flood this sheds new work while verified players keep playing.
# [autotune] can manage this value when enabled.
global_connection_limit = 0
# Per-source packet limit on the bedrock/voice UDP ports (0 = disabled).
udp_packet_limit = 0
# Fallback per-source packet limit for rate rules without their own
# max_rate (0 = disabled: such rules only match, they do not limit).
rule_packet_limit = 0
# Rate limit window length, 1..=4000 milliseconds.
window_ms = 1000

# Idle timeout for verified connections in seconds; an entry is removed
# in-kernel after one to two intervals without packets. Maps to
# `PLAYER_IDLE_NS` (converted to ns).
player_idle_timeout_secs = 60

# Enforce online-mode (<= 16 char) usernames. Maps to `ONLINE_NAMES`.
online_names = true

# Drop a PROXY protocol header at the start of a connection unless the
# source is allowlisted. A real proxy in front of the filter belongs on the
# allowlist anyway; from anyone else the header can only be an attempt to
# make a trusting backend believe the connection comes from another
# address. Maps to `REJECT_PROXY_HEADER`.
reject_proxy_header = true

# Abuse cap for the verified fast path (0 = off): packets / bytes a single
# verified connection may send per rate window before its packets are
# dropped. Way above any real client rate (~20 packets/s idle), it catches
# post-handshake packet floods (spam bots that passed the handshake). The
# packets are dropped, the connection is not killed, so a legitimate burst
# recovers in the next window. Maps to `VERIFIED_PPS_LIMIT` /
# `VERIFIED_BPS_LIMIT`.
verified_pps_limit = 0
verified_bps_limit = 0

# Count (and log) drops without enforcing them. Maps to `DRY_RUN`.
dry_run = false

# Drop sources from 0/8, 169.254/16, multicast and reserved space.
# Maps to `DROP_RESERVED_SOURCES`.
drop_reserved_sources = true

# Also drop sources from RFC1918, loopback and CGNAT. Maps to
# `DROP_PRIVATE_SOURCES`; off by default so same-host proxies and LAN
# monitoring keep working.
drop_private_sources = false

[xdp]
# Attach mode: "auto" (native with generic fallback), "driver" (native
# only) or "skb" (generic). Native mode is strongly recommended.
mode = "auto"

# Capacity of conntrack_map: concurrent unverified (mid-handshake)
# connections, oldest evicted when full.
max_pending_connections = 16384
# Capacity of player_connection_map: concurrent verified connections.
max_player_connections = 65535
# Capacity of the host throttle/udp throttle windows: source IPs with an
# active rate-limit window.
max_throttled_ips = 65535
# Capacity of subnet_throttle (per /24 or /64 windows).
max_throttled_subnets = 16384
# Capacity of rule_rates (per-source, per-rule windows).
max_rule_rate_entries = 16384
# Capacity of the verified_sources map (source IPs with a verified
# minecraft connection; used by the voice gate and the ML labels).
max_verified_sources = 16384
# Capacity of the sampled top-talkers map.
max_talkers = 65536
# Capacity of the egress flow map (only used with [ingress] egress_tracking).
max_egress_flows = 65536
# Capacity of the autoblock map (kernel-inserted blocks).
max_autoblock_entries = 65536

# Optional file with source addresses (IPv4/IPv6/CIDR, one per line) that
# bypass all inspection; re-read on SIGHUP.
# allowlist_file = "/etc/minecraft-xdp/allowlist.txt"
# Capacity of the allowlist map.
max_allowlist_entries = 4096

[bedrock]
# Minecraft Bedrock (RakNet) UDP protection. Validates the offline
# handshake messages statelessly and (with [ingress] egress_tracking)
# requires connected traffic to match a server-sent flow.
enabled = false
# UDP port of the bedrock listener.
port = 19132
# Enforce the protocol version window below on handshake packets. Off by
# default: forks and proxies may use any version, and a wrong window would
# break real players while adding little (random garbage never matches the
# exact handshake shape).
strict_protocol_version = false
protocol_min = 0
protocol_max = 0
# Plausible MTU values in RakNet handshake packets.
mtu_min = 576
mtu_max = 1500

[voice]
# Simple Voice Chat UDP protection. The strong gate is require_verified_ip:
# the source IP must have passed a full minecraft (Java) connection.
enabled = false
port = 24454
require_verified_ip = false
# Upper bound for the first payload byte (shape heuristic, permissive).
max_packet_type = 63

[ingress]
# Default-deny: traffic to ports that are not explicitly opened (rules
# below, the minecraft range, bedrock/voice ports) is dropped unless it
# matches a flow the host sent on (see egress_tracking). Attackers cannot
# guess such flows, so this seals every unlisted service and every
# reflection/amplification vector. Start with dry_run = true in [filter]
# to see what it would drop before enforcing.
default_deny = false

# Track egress flows with a tc/clsact program on the same interface. The
# ingress side then accepts replies to flows the host itself opened (TCP
# additionally checks that the ack falls inside the sequence space the
# host sent, which defeats blind spoofing). Adds a clsact qdisc to the
# interface.
egress_tracking = false
# Idle lifetime of an egress flow (seconds) used as the ingress pinhole.
egress_timeout_secs = 300

# ICMP policy: "allow" (pass everything, default), "smart" (pass error
# messages needed for PMTU, drop unsolicited echo requests, require an
# egress pinhole for echo replies; recommended with default_deny) or
# "drop" (drop all ICMP - only for hosts that really need none).
icmp = "allow"

# Extra ports to accept in default-deny mode, as plain rules. Use the
# [[rules]] sections below for anything more complex.
open_tcp_ports = []
open_udp_ports = []

[blocklist]
# Optional file with addresses/CIDRs to block (one per line, IPv4 or IPv6).
# Entries are permanent until removed from the file and SIGHUP is sent.
# blocklist_file = "/etc/minecraft-xdp/blocklist.txt"
max_entries = 65536

# Auto-block: the kernel itself records rate-limit violations and (after
# `autoblock_strikes` violations) blocks the source for an escalating
# duration. A quiet period longer than autoblock_decay_secs forgets the
# history. This is opt-in because a wrong limit turns into wrong blocks.
autoblock = false
autoblock_strikes = 3
autoblock_base_ttl_secs = 60
autoblock_max_ttl_secs = 86400
autoblock_decay_secs = 600

# Optional path to export the current auto-blocks (one address per line,
# with strike count and remaining ttl as comments) for upstream
# enforcement (nftables, blackhole routes, provider APIs). The file is
# rewritten atomically whenever the set changes.
# export_file = "/var/lib/minecraft-xdp/blocked.txt"

# Declarative rules for ports/protocols outside the minecraft range.
# action: "allow" (pass, with optional checks), "drop" (always drop) or
# "rate" (per-source packet window, max_rate packets per window_ms).
# proto: "tcp", "udp" or an IP protocol number.
# magic: hex string (up to 8 bytes) that the payload must start with at
# magic_offset (default 0); min_len/max_len bound the payload length.
# stateful: require an egress flow (see [ingress] egress_tracking).
#
# [[rules]]
# name = "voice-signalling"
# proto = "udp"
# port = 24454
# action = "rate"
# max_rate = 200
#
# [[rules]]
# name = "admin-ssh"
# proto = "tcp"
# port = 22
# action = "allow"
# stateful = true

[autotune]
# Userspace control loop that adjusts the in-kernel limits at runtime
# (see docs/autotune.md). It relaxes per-source limits when legitimate
# players hit them, and tightens them towards the configured minimum when
# the SYN rate indicates a flood. Changes are damped (max one step per
# interval), bounded and logged.
enabled = false
# Start with dry_run = true: the loop only logs what it would change.
dry_run = true
interval_ms = 1000

# Bounds the loop moves the limits within.
host_limit_min = 2
host_limit_max = 512
subnet_limit_min = 16
subnet_limit_max = 4096
global_limit_min = 4
global_limit_max = 65536

# Relax the per-source limit when drops happen but the SYN rate is below
# relax_syn_per_sec; tighten it while the SYN rate stays above
# tighten_syn_per_sec.
relax_syn_per_sec = 8.0
tighten_syn_per_sec = 64.0

# Auto-block strike threshold bounds (the loop lowers it under attack).
strike_threshold_min = 1
strike_threshold_max = 6

# Persists the last applied values across restarts.
# state_file = "/var/lib/minecraft-xdp/autotune.toml"

[ml]
# Per-source risk scoring (logistic regression on the sampled talker
# counters: packet rate, drop ratio, average size, SYN/UDP ratio, and
# similar). Runs in the loader, weights are trained online from the
# kernel's own labels (verified players = benign, auto-blocked sources =
# malicious) and persisted to model_file.
#
# mode = "shadow" only publishes scores, "enforce" also auto-blocks
# sources above the threshold (always bounded by max_block_ttl_secs).
enabled = false
mode = "shadow"
threshold = 0.90
# Ignore sources below this smoothed packet rate (the model needs
# statistics to be meaningful).
min_packet_rate = 5.0
interval_secs = 60
# model_file = "/var/lib/minecraft-xdp/ml_model.toml"
train = true
max_block_ttl_secs = 3600

[advisor]
# Log sizing/NIC recommendations at startup and warnings while running
# (e.g. "player map full, raise max_player_connections").
enabled = true

[metrics]
# Publish the in-kernel statistics as Prometheus metrics.
enabled = false

# Address to expose Prometheus metrics on (only used when enabled = true).
# Leave commented out to collect stats without starting the HTTP server.
# The endpoint has no authentication, so only bind to a public address
# (e.g. "0.0.0.0:1999") if you really want it reachable from outside.
# addr = "127.0.0.1:1999"

# How often the in-kernel statistics are read and published, in seconds.
poll_secs = 10

[logging]
# Verbosity of console and file logging:
# "off", "error", "warn", "info", "debug" or "trace".
# The RUST_LOG environment variable overrides this setting at runtime.
level = "info"

# The log file (xdp-loader.log) is rotated once it grows past this many
# megabytes; the 5 most recent rotated files are kept.
file_max_mb = 100
"#;

/// Runtime configuration for the XDP filter, grouped like the TOML file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub filter: FilterConfig,
    pub xdp: XdpConfig,
    pub bedrock: BedrockConfig,
    pub voice: VoiceConfig,
    pub ingress: IngressConfig,
    pub blocklist: BlocklistConfig,
    #[serde(rename = "rules")]
    pub rules: Vec<RuleConfig>,
    pub autotune: AutotuneConfig,
    pub ml: MlConfig,
    pub advisor: AdvisorConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
}

/// `[filter]` — which traffic is filtered and how strictly.
///
/// These fields are pushed into the eBPF program's `volatile const` globals at
/// load time; see `load_and_attach` in `loader/ebpf.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilterConfig {
    /// First port of the inclusive filtered range. Maps to `START_PORT`.
    pub start_port: u16,
    /// Last port of the inclusive filtered range. Maps to `END_PORT`.
    pub end_port: u16,
    /// Max new connections (SYNs) per source IP per window (0 = disabled).
    /// Written into the runtime-tunable `tunables_map`, not .rodata.
    #[serde(alias = "hit_count")]
    pub host_connection_limit: u32,
    /// Max new connections per /24 (IPv4) or /64 (IPv6) per window.
    pub subnet_connection_limit: u32,
    /// Host-wide admission limit for new connections per window (0 = disabled).
    pub global_connection_limit: u32,
    /// Per-source packet limit on the bedrock/voice UDP ports (0 = disabled).
    pub udp_packet_limit: u32,
    /// Fallback per-source packet limit for rate rules without their own
    /// `max_rate` (0 = disabled).
    pub rule_packet_limit: u32,
    /// Rate limit window length in milliseconds (1..=4000).
    pub window_ms: u32,
    /// Idle timeout for verified connections in seconds; an entry is removed
    /// in-kernel after one to two intervals without packets. Maps to
    /// `PLAYER_IDLE_NS` (converted to ns).
    pub player_idle_timeout_secs: u64,
    /// Enforce online-mode (<= 16 char) usernames. Maps to `ONLINE_NAMES`.
    pub online_names: bool,
    /// Drop a PROXY protocol header (v1 "PROXY ..." / the v2 signature) at
    /// the start of a connection, unless the source is allowlisted (a real
    /// proxy belongs on the allowlist anyway). Such a header is a proxy →
    /// backend protocol: from anyone else it is an attempt to make a
    /// trusting backend believe the connection comes from another address.
    /// Maps to `REJECT_PROXY_HEADER`.
    pub reject_proxy_header: bool,
    /// Abuse cap for the verified fast path: max packets a single verified
    /// connection may send per rate window (0 = off) before its packets are
    /// dropped. Way above any real client rate; catches post-handshake
    /// packet floods (spam bots that passed the handshake). Maps to
    /// `VERIFIED_PPS_LIMIT`.
    pub verified_pps_limit: u32,
    /// Same as `verified_pps_limit`, in bytes per window (0 = off). Maps to
    /// `VERIFIED_BPS_LIMIT`.
    pub verified_bps_limit: u32,
    /// Count (and log) drops without enforcing them. Maps to `DRY_RUN`.
    pub dry_run: bool,
    /// Drop sources from 0/8, 169.254/16, multicast and reserved space.
    /// Maps to `DROP_RESERVED_SOURCES`.
    pub drop_reserved_sources: bool,
    /// Also drop sources from RFC1918, loopback and CGNAT. Maps to
    /// `DROP_PRIVATE_SOURCES`; off by default so same-host proxies and LAN
    /// monitoring keep working.
    pub drop_private_sources: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            start_port: 25565,
            end_port: 25565,
            host_connection_limit: 10,
            subnet_connection_limit: 64,
            global_connection_limit: 0,
            udp_packet_limit: 0,
            rule_packet_limit: 0,
            window_ms: 1000,
            player_idle_timeout_secs: 60,
            online_names: true,
            reject_proxy_header: true,
            verified_pps_limit: 0,
            verified_bps_limit: 0,
            dry_run: false,
            drop_reserved_sources: true,
            drop_private_sources: false,
        }
    }
}

impl FilterConfig {
    fn validate(&self) -> Result<()> {
        if self.start_port == 0 {
            bail!("[filter] start_port must be >= 1");
        }
        if self.start_port > self.end_port {
            bail!(
                "[filter] start_port ({}) must be <= end_port ({})",
                self.start_port,
                self.end_port
            );
        }
        // the sliding-window estimate multiplies the previous window's
        // counter (u32) with the remaining nanoseconds, so the window has to
        // stay well below 2^32 ns
        check_range("[filter] window_ms", self.window_ms as u64, 1, 4000)?;
        check_range(
            "[filter] player_idle_timeout_secs",
            self.player_idle_timeout_secs,
            1,
            86_400,
        )?;
        // the abuse caps exist to stop floods that are orders of magnitude
        // above real play traffic, so refuse values that would fight normal
        // gameplay: a quiet client alone is ~20 packets/s and plugin
        // payload bursts are a few KB, so anything below these floors is a
        // misconfiguration waiting to drop legitimate players
        if self.verified_pps_limit != 0 {
            check_range(
                "[filter] verified_pps_limit",
                self.verified_pps_limit as u64,
                50,
                10_000_000,
            )?;
        }
        if self.verified_bps_limit != 0 {
            check_range(
                "[filter] verified_bps_limit",
                self.verified_bps_limit as u64,
                4096,
                10_000_000_000,
            )?;
        }
        Ok(())
    }
}

/// `[xdp]` — how the program attaches and the capacity of its maps.
///
/// The capacities override the placeholder `max_entries` of the corresponding
/// map in `xdp/minecraft_filter.c` at load time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XdpConfig {
    /// XDP attach mode.
    pub mode: ConfigXdpMode,
    /// Capacity of `conntrack_map`: concurrent unverified (mid-handshake)
    /// connections, oldest evicted when full.
    pub max_pending_connections: u32,
    /// Capacity of `player_connection_map`: concurrent verified connections.
    pub max_player_connections: u32,
    /// Capacity of the hash-backed rate windows: source IPs with an active
    /// window.
    pub max_throttled_ips: u32,
    /// Capacity of `subnet_throttle`: subnets with an active window.
    pub max_throttled_subnets: u32,
    /// Capacity of `rule_rates`: per-source, per-rule windows.
    pub max_rule_rate_entries: u32,
    /// Capacity of `verified_sources`.
    pub max_verified_sources: u32,
    /// Capacity of the sampled top-talkers map.
    pub max_talkers: u32,
    /// Capacity of `egress_flows` (only used with egress tracking).
    pub max_egress_flows: u32,
    /// Capacity of `autoblock_map`.
    pub max_autoblock_entries: u32,
    /// Optional file with source addresses (IPv4/IPv6 or CIDR, one per line)
    /// that bypass all inspection; re-read on SIGHUP.
    pub allowlist_file: Option<String>,
    /// Capacity of `allowlist_map`.
    pub max_allowlist_entries: u32,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            mode: ConfigXdpMode::Auto,
            max_pending_connections: 16384,
            max_player_connections: 65535,
            max_throttled_ips: 65535,
            max_throttled_subnets: 16384,
            max_rule_rate_entries: 16384,
            max_verified_sources: 16384,
            max_talkers: 65536,
            max_egress_flows: 65536,
            max_autoblock_entries: 65536,
            allowlist_file: None,
            max_allowlist_entries: 4096,
        }
    }
}

impl XdpConfig {
    fn validate(&self) -> Result<()> {
        const MAX_ENTRIES: u64 = 1 << 20;
        for (option, value) in [
            ("max_pending_connections", self.max_pending_connections),
            ("max_player_connections", self.max_player_connections),
            ("max_throttled_ips", self.max_throttled_ips),
            ("max_throttled_subnets", self.max_throttled_subnets),
            ("max_rule_rate_entries", self.max_rule_rate_entries),
            ("max_verified_sources", self.max_verified_sources),
            ("max_talkers", self.max_talkers),
            ("max_egress_flows", self.max_egress_flows),
            ("max_autoblock_entries", self.max_autoblock_entries),
            ("max_allowlist_entries", self.max_allowlist_entries),
        ] {
            check_range(
                &format!("[xdp] {option}"),
                value as u64,
                1,
                MAX_ENTRIES,
            )?;
        }
        if let Some(path) = &self.allowlist_file {
            if path.trim().is_empty() {
                bail!("[xdp] allowlist_file must not be empty (remove the option to disable it)");
            }
        }
        Ok(())
    }
}

/// XDP attach mode, the `mode` option in `[xdp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigXdpMode {
    /// Native driver mode when the NIC supports it, automatic fallback to
    /// generic mode otherwise.
    Auto,
    /// Force native driver mode, fail when unsupported.
    Driver,
    /// Force generic (skb) mode.
    Skb,
}

impl fmt::Display for ConfigXdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConfigXdpMode::Auto => "auto",
            ConfigXdpMode::Driver => "driver",
            ConfigXdpMode::Skb => "skb",
        })
    }
}

/// `[bedrock]` — RakNet UDP protection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BedrockConfig {
    /// Enable the bedrock path. Maps to `BEDROCK_ENABLED`.
    pub enabled: bool,
    /// UDP port of the bedrock listener. Maps to `BEDROCK_PORT`.
    pub port: u16,
    /// Enforce `protocol_min..=protocol_max` on handshake packets. Maps to
    /// `BEDROCK_STRICT_VERSION`. The RakNet handshake carries one protocol
    /// version *byte*, so the window is 0..=255 and forks that bumped it
    /// need the window widened (or left off, the default).
    pub strict_protocol_version: bool,
    /// Inclusive protocol version byte window, only used in strict mode.
    pub protocol_min: u32,
    pub protocol_max: u32,
    /// Plausible RakNet MTU bounds. Maps to `BEDROCK_MTU_MIN/MAX`.
    pub mtu_min: u32,
    pub mtu_max: u32,
}

impl Default for BedrockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 19132,
            strict_protocol_version: false,
            protocol_min: 0,
            protocol_max: 0,
            mtu_min: 576,
            mtu_max: 1500,
        }
    }
}

impl BedrockConfig {
    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.port == 0 {
            bail!("[bedrock] port must be >= 1");
        }
        check_range("[bedrock] mtu_min", self.mtu_min as u64, 576, 65535)?;
        check_range("[bedrock] mtu_max", self.mtu_max as u64, 576, 65535)?;
        if self.mtu_min > self.mtu_max {
            bail!(
                "[bedrock] mtu_min ({}) must be <= mtu_max ({})",
                self.mtu_min,
                self.mtu_max
            );
        }
        if self.strict_protocol_version {
            check_range("[bedrock] protocol_min", self.protocol_min as u64, 0, 255)?;
            check_range("[bedrock] protocol_max", self.protocol_max as u64, 1, 255)?;
            if self.protocol_min > self.protocol_max {
                bail!(
                    "[bedrock] protocol_min ({}) must be <= protocol_max ({})",
                    self.protocol_min,
                    self.protocol_max
                );
            }
        }
        Ok(())
    }
}

/// `[voice]` — Simple Voice Chat UDP protection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VoiceConfig {
    /// Enable the voice path. Maps to `VOICE_ENABLED`.
    pub enabled: bool,
    /// UDP port of the voice listener. Maps to `VOICE_PORT`.
    pub port: u16,
    /// Require the source IP to have a verified minecraft connection. Maps
    /// to `VOICE_REQUIRE_VERIFIED`.
    pub require_verified_ip: bool,
    /// Upper bound for the first payload byte. Maps to `VOICE_MAX_TYPE`.
    pub max_packet_type: u32,
}

impl Default for VoiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 24454,
            require_verified_ip: false,
            max_packet_type: 63,
        }
    }
}

impl VoiceConfig {
    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.port == 0 {
            bail!("[voice] port must be >= 1");
        }
        check_range(
            "[voice] max_packet_type",
            self.max_packet_type as u64,
            1,
            255,
        )
    }
}

/// ICMP policy, the `icmp` option in `[ingress]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IcmpPolicy {
    /// Pass all ICMP/ICMPv6.
    #[default]
    Allow,
    /// Pass error types needed for PMTU, drop unsolicited echo requests,
    /// require an egress pinhole for echo replies, always pass IPv6
    /// neighbor discovery.
    Smart,
    /// Drop all ICMP/ICMPv6 (breaks PMTU, opt-in only).
    Drop,
}

impl IcmpPolicy {
    /// Value pushed into the `ICMP_MODE` global.
    pub fn mode(self) -> u8 {
        match self {
            IcmpPolicy::Allow => 0,
            IcmpPolicy::Smart => 1,
            IcmpPolicy::Drop => 2,
        }
    }
}

impl fmt::Display for IcmpPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IcmpPolicy::Allow => "allow",
            IcmpPolicy::Smart => "smart",
            IcmpPolicy::Drop => "drop",
        })
    }
}

/// `[ingress]` — default-deny and egress state tracking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IngressConfig {
    /// Drop traffic that matches no rule/open port and no egress flow. Maps
    /// to `DEFAULT_DENY`.
    pub default_deny: bool,
    /// Attach the tc egress program that records outgoing flows. Maps to
    /// `EGRESS_TRACK_ENABLED`.
    pub egress_tracking: bool,
    /// Idle lifetime of a recorded egress flow in seconds. Maps to
    /// `EGRESS_TIMEOUT_NS` (converted to ns).
    pub egress_timeout_secs: u64,
    /// ICMP policy. Maps to `ICMP_MODE`.
    pub icmp: IcmpPolicy,
    /// Extra TCP ports accepted in default-deny mode (sugar for allow rules).
    pub open_tcp_ports: Vec<u16>,
    /// Extra UDP ports accepted in default-deny mode (sugar for allow rules).
    pub open_udp_ports: Vec<u16>,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            default_deny: false,
            egress_tracking: false,
            egress_timeout_secs: 300,
            icmp: IcmpPolicy::Allow,
            open_tcp_ports: Vec::new(),
            open_udp_ports: Vec::new(),
        }
    }
}

impl IngressConfig {
    fn validate(&self) -> Result<()> {
        check_range(
            "[ingress] egress_timeout_secs",
            self.egress_timeout_secs,
            1,
            86_400,
        )?;
        if self.default_deny && !self.egress_tracking {
            bail!(
                "[ingress] default_deny requires egress_tracking: without it there is no \
                 flow state to match replies against, and every reply on a closed port \
                 is dropped. Enable egress_tracking or disable default_deny"
            );
        }
        // smart icmp without default-deny is allowed (it still drops scans),
        // it is just mentioned in the docs: without state to check echo
        // replies against they pass like in "allow" mode
        for (name, ports) in [
            ("open_tcp_ports", &self.open_tcp_ports),
            ("open_udp_ports", &self.open_udp_ports),
        ] {
            for port in ports {
                if *port == 0 {
                    bail!("[ingress] {name} must not contain port 0");
                }
            }
        }
        Ok(())
    }
}

/// `[blocklist]` — operator blocklist and auto-blocking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlocklistConfig {
    /// Optional file with addresses/CIDRs to block (one per line). Maps to
    /// `BLOCKLIST_ENABLED` (enabled when set).
    pub blocklist_file: Option<String>,
    /// Capacity of the blocklist trie.
    pub max_entries: u32,
    /// Kernel-side auto-blocking of repeated rate-limit violators. Maps to
    /// `AUTOBLOCK_ENABLED`.
    pub autoblock: bool,
    /// Violations before the first auto-block (runtime-tunable start value).
    pub autoblock_strikes: u32,
    /// First auto-block duration in seconds; doubles per escalation step.
    pub autoblock_base_ttl_secs: u32,
    /// Ceiling for the auto-block duration in seconds.
    pub autoblock_max_ttl_secs: u32,
    /// Quiet time after which strike history is forgotten.
    pub autoblock_decay_secs: u32,
    /// Optional path to export current auto-blocks for upstream enforcement.
    pub export_file: Option<String>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            blocklist_file: None,
            max_entries: 65536,
            autoblock: false,
            autoblock_strikes: 3,
            autoblock_base_ttl_secs: 60,
            autoblock_max_ttl_secs: 86_400,
            autoblock_decay_secs: 600,
            export_file: None,
        }
    }
}

impl BlocklistConfig {
    fn validate(&self) -> Result<()> {
        check_range("[blocklist] max_entries", self.max_entries as u64, 1, 1 << 20)?;
        if let Some(path) = &self.blocklist_file {
            if path.trim().is_empty() {
                bail!("[blocklist] blocklist_file must not be empty (remove the option to disable it)");
            }
        }
        if self.autoblock {
            check_range(
                "[blocklist] autoblock_strikes",
                self.autoblock_strikes as u64,
                1,
                31,
            )?;
            check_range(
                "[blocklist] autoblock_base_ttl_secs",
                self.autoblock_base_ttl_secs as u64,
                1,
                1 << 20,
            )?;
            check_range(
                "[blocklist] autoblock_max_ttl_secs",
                self.autoblock_max_ttl_secs as u64,
                1,
                1 << 25,
            )?;
            if self.autoblock_max_ttl_secs < self.autoblock_base_ttl_secs {
                bail!(
                    "[blocklist] autoblock_max_ttl_secs ({}) must be >= autoblock_base_ttl_secs ({})",
                    self.autoblock_max_ttl_secs,
                    self.autoblock_base_ttl_secs
                );
            }
        }
        if let Some(path) = &self.export_file {
            if path.trim().is_empty() {
                bail!("[blocklist] export_file must not be empty (remove the option to disable it)");
            }
        }
        Ok(())
    }
}

/// What a rule does with matching packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Pass, after the optional length/magic/stateful checks.
    Allow,
    /// Always drop.
    Drop,
    /// Per-source packet window, then pass.
    Rate,
}

/// One `[[rules]]` entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Optional label used in logs and metric labels.
    #[serde(default)]
    pub name: Option<String>,
    /// "tcp", "udp" or an IP protocol number.
    pub proto: String,
    /// Destination port to match (1..=65535).
    pub port: u16,
    pub action: RuleAction,
    /// Per-source packet limit per window for action = "rate" (0 uses
    /// [filter] rule fallback = udp/rule limit).
    #[serde(default)]
    pub max_rate: u32,
    /// Inclusive bounds on the L4 payload length (0 = unbounded).
    #[serde(default)]
    pub min_len: u16,
    #[serde(default)]
    pub max_len: u16,
    /// Hex string (up to 8 bytes = 16 hex chars) the payload must start
    /// with at magic_offset.
    #[serde(default)]
    pub magic: Option<String>,
    /// Offset of the magic bytes inside the payload (0..=255).
    #[serde(default)]
    pub magic_offset: u8,
    /// Require an egress flow (only enforced with egress tracking enabled).
    #[serde(default)]
    pub stateful: bool,
}

impl RuleConfig {
    fn validate(&self) -> Result<()> {
        let label = match &self.name {
            Some(name) => format!("[[rules]] '{name}'"),
            None => format!("[[rules]] proto={} port={}", self.proto, self.port),
        };
        if self.port == 0 {
            bail!("{label}: port must be >= 1");
        }
        if proto_number(&self.proto).is_none() {
            bail!(
                "{label}: proto must be \"tcp\", \"udp\" or an IP protocol \
                 number between 1 and 255 (got '{}')",
                self.proto
            );
        }
        if let Some(magic) = &self.magic {
            let clean: String = magic.chars().filter(|c| !c.is_whitespace()).collect();
            if clean.is_empty() || clean.len() > 16 || clean.len() % 2 != 0 {
                bail!("{label}: magic must be 1..=8 bytes as hex (got '{magic}')");
            }
            if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("{label}: magic must be hexadecimal (got '{magic}')");
            }
            if self.magic_offset as usize + clean.len() / 2 > 8.max(self.magic_offset as usize + 8) {
                // the kernel compares exactly 8 bytes starting at magic_offset
                // and masks the bytes beyond magic_len; the check above keeps
                // magic_offset + 8 within packet bounds cheaply
            }
        }
        if self.min_len != 0 && self.max_len != 0 && self.min_len > self.max_len {
            bail!(
                "{label}: min_len ({}) must be <= max_len ({})",
                self.min_len,
                self.max_len
            );
        }
        if self.action == RuleAction::Rate && self.max_rate == 0 {
            // allowed: falls back to the runtime-configured rule limit
        }
        Ok(())
    }

    /// Protocol number and whether it is a transport protocol with ports.
    pub fn proto_number_and_ports(&self) -> (u8, bool) {
        let proto = proto_number(&self.proto).expect("validated proto");
        let has_ports = proto == 6 || proto == 17; // tcp/udp
        (proto, has_ports)
    }

    /// Decoded magic bytes and their mask (empty when no magic configured).
    pub fn magic_bytes(&self) -> (u64, u64) {
        let Some(magic) = &self.magic else {
            return (0, 0);
        };
        let clean: String = magic.chars().filter(|c| !c.is_whitespace()).collect();
        let mut word: u64 = 0;
        let mut mask: u64 = 0;
        for (index, pair) in clean.as_bytes().chunks(2).enumerate() {
            let byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16)
                .expect("validated hex");
            word |= (byte as u64) << (8 * index);
            mask |= 0xffu64 << (8 * index);
        }
        (word, mask)
    }
}

/// Maps "tcp"/"udp"/number to a protocol number.
pub fn proto_number(proto: &str) -> Option<u8> {
    match proto.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        other => other.parse::<u8>().ok().filter(|value| *value != 0),
    }
}

/// `[autotune]` — the userspace control loop for the in-kernel limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutotuneConfig {
    pub enabled: bool,
    /// Only log what would change, never write the tunables map.
    pub dry_run: bool,
    pub interval_ms: u64,
    pub host_limit_min: u32,
    pub host_limit_max: u32,
    pub subnet_limit_min: u32,
    pub subnet_limit_max: u32,
    pub global_limit_min: u32,
    pub global_limit_max: u32,
    /// Relax the per-source limit when throttle drops happen while the SYN
    /// rate stays below this value (connections/s).
    pub relax_syn_per_sec: f64,
    /// Tighten the per-source limit while the SYN rate stays above this value.
    pub tighten_syn_per_sec: f64,
    pub strike_threshold_min: u32,
    pub strike_threshold_max: u32,
    pub state_file: Option<String>,
}

impl Default for AutotuneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            interval_ms: 1000,
            host_limit_min: 2,
            host_limit_max: 512,
            subnet_limit_min: 16,
            subnet_limit_max: 4096,
            global_limit_min: 4,
            global_limit_max: 65536,
            relax_syn_per_sec: 8.0,
            tighten_syn_per_sec: 64.0,
            strike_threshold_min: 1,
            strike_threshold_max: 6,
            state_file: None,
        }
    }
}

impl AutotuneConfig {
    fn validate(&self, filter: &FilterConfig) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        check_range("[autotune] interval_ms", self.interval_ms, 100, 60_000)?;
        for (name, min, max) in [
            ("host_limit", self.host_limit_min, self.host_limit_max),
            ("subnet_limit", self.subnet_limit_min, self.subnet_limit_max),
            ("global_limit", self.global_limit_min, self.global_limit_max),
            (
                "strike_threshold",
                self.strike_threshold_min,
                self.strike_threshold_max,
            ),
        ] {
            if min == 0 {
                bail!("[autotune] {name}_min must be >= 1");
            }
            if min > max {
                bail!("[autotune] {name}_min ({min}) must be <= {name}_max ({max})");
            }
        }
        if !(self.relax_syn_per_sec.is_finite() && self.relax_syn_per_sec >= 0.0) {
            bail!("[autotune] relax_syn_per_sec must be a positive number");
        }
        if !(self.tighten_syn_per_sec.is_finite() && self.tighten_syn_per_sec > 0.0) {
            bail!("[autotune] tighten_syn_per_sec must be a positive number");
        }
        if self.tighten_syn_per_sec <= self.relax_syn_per_sec {
            bail!(
                "[autotune] tighten_syn_per_sec ({}) must be greater than relax_syn_per_sec ({})",
                self.tighten_syn_per_sec,
                self.relax_syn_per_sec
            );
        }
        if filter.host_connection_limit == 0 {
            bail!(
                "[autotune] requires a nonzero [filter] host_connection_limit to tune from \
                 (the loop never enables a disabled limit)"
            );
        }
        if let Some(path) = &self.state_file {
            if path.trim().is_empty() {
                bail!("[autotune] state_file must not be empty (remove the option to disable it)");
            }
        }
        Ok(())
    }
}

/// How the ML scorer is allowed to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MlMode {
    /// Disabled (also the effect of enabled = false).
    Off,
    /// Score and publish, never block.
    #[default]
    Shadow,
    /// Block sources above the threshold (bounded by max_block_ttl_secs).
    Enforce,
}

/// `[ml]` — per-source risk scoring in the loader.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MlConfig {
    pub enabled: bool,
    pub mode: MlMode,
    /// Decision threshold on the model output (0..1).
    pub threshold: f64,
    /// Ignore sources below this smoothed packet rate (packets/s).
    pub min_packet_rate: f64,
    pub interval_secs: u64,
    pub model_file: Option<String>,
    /// Train the model online from the kernel's labels.
    pub train: bool,
    /// Cap for ML-driven auto-blocks in seconds.
    pub max_block_ttl_secs: u32,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: MlMode::Shadow,
            threshold: 0.90,
            min_packet_rate: 5.0,
            interval_secs: 60,
            model_file: None,
            train: true,
            max_block_ttl_secs: 3600,
        }
    }
}

impl MlConfig {
    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        check_range("[ml] interval_secs", self.interval_secs, 1, 3600)?;
        if !(0.0..=1.0).contains(&self.threshold) {
            bail!("[ml] threshold must be between 0.0 and 1.0");
        }
        if !(self.min_packet_rate.is_finite() && self.min_packet_rate >= 0.0) {
            bail!("[ml] min_packet_rate must be a non-negative number");
        }
        check_range(
            "[ml] max_block_ttl_secs",
            self.max_block_ttl_secs as u64,
            1,
            1 << 25,
        )?;
        if let Some(path) = &self.model_file {
            if path.trim().is_empty() {
                bail!("[ml] model_file must not be empty (remove the option to disable it)");
            }
        }
        Ok(())
    }
}

/// `[advisor]` — sizing/NIC recommendations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdvisorConfig {
    pub enabled: bool,
}

impl Default for AdvisorConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// `[metrics]` — statistics collection and the Prometheus endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Collect statistics inside the eBPF program. Maps to `PROMETHEUS`.
    pub enabled: bool,
    /// Optional address for the Prometheus HTTP endpoint (e.g. `127.0.0.1:1999`).
    pub addr: Option<String>,
    /// Seconds between reads of the in-kernel statistics map.
    pub poll_secs: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: None,
            poll_secs: 10,
        }
    }
}

impl MetricsConfig {
    fn validate(&self) -> Result<()> {
        check_range("[metrics] poll_secs", self.poll_secs, 1, 3_600)
    }
}

/// `[logging]` — console/file log verbosity and rotation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log verbosity, overridable at runtime via the `RUST_LOG` env variable.
    pub level: LogLevel,
    /// Rotate the log file once it grows past this size in megabytes.
    pub file_max_mb: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file_max_mb: 100,
        }
    }
}

impl LoggingConfig {
    fn validate(&self) -> Result<()> {
        check_range("[logging] file_max_mb", self.file_max_mb, 1, 10_240)
    }
}

/// Log verbosity, the `level` option in `[logging]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

impl Config {
    /// Load the configuration from `path`, creating a documented default file if
    /// it does not exist yet.
    ///
    /// Runs before logging is initialized (the log level lives in here), so the
    /// "wrote defaults" notice goes to stderr directly.
    pub fn load(path: &Path) -> Result<Config> {
        if !path.exists() {
            eprintln!(
                "Config file '{}' not found, writing documented defaults",
                path.display()
            );
            std::fs::write(path, DEFAULT_CONFIG_TOML).with_context(|| {
                format!("failed to write default config to '{}'", path.display())
            })?;
        }

        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file '{}'", path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file '{}'", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Reject values the eBPF program or loader cannot represent sensibly.
    pub(crate) fn validate(&self) -> Result<()> {
        self.filter.validate()?;
        self.xdp.validate()?;
        self.bedrock.validate()?;
        self.voice.validate()?;
        self.ingress.validate()?;
        self.blocklist.validate()?;
        for rule in &self.rules {
            rule.validate()?;
        }
        if !self.rules.is_empty() && self.rules.len() > 256 {
            bail!(
                "at most 256 [[rules]] are supported (got {}), the rule map has 256 slots",
                self.rules.len()
            );
        }
        self.autotune.validate(&self.filter)?;
        self.ml.validate()?;
        // the dedicated paths (minecraft range for tcp, bedrock/voice for
        // udp) are consulted before the rule engine, so a rule or open port
        // that targets one of those ports would silently never fire
        for (proto, port, what) in self
            .ingress
            .open_tcp_ports
            .iter()
            .map(|port| (6u8, *port, "[ingress] open_tcp_ports"))
            .chain(
                self.ingress
                    .open_udp_ports
                    .iter()
                    .map(|port| (17u8, *port, "[ingress] open_udp_ports")),
            )
            .chain(
                self.rules
                    .iter()
                    .map(|rule| (rule.proto_number_and_ports().0, rule.port, "[[rules]]")),
            )
        {
            let owner = if proto == 6
                && port >= self.filter.start_port
                && port <= self.filter.end_port
            {
                Some("the minecraft range")
            } else if proto == 17 && self.bedrock.enabled && port == self.bedrock.port {
                Some("the bedrock port")
            } else if proto == 17 && self.voice.enabled && port == self.voice.port {
                Some("the voice port")
            } else {
                None
            };
            if let Some(owner) = owner {
                bail!("{what} contains port {port} which is already handled by {owner}");
            }
        }
        // ML enforcement inserts blocks through the auto-block table, so the
        // kernel side has to be enabled for them to take effect
        if self.ml.enabled && self.ml.mode == MlMode::Enforce && !self.blocklist.autoblock {
            bail!(
                "[ml] mode = \"enforce\" requires [blocklist] autoblock = true \
                 (enforced blocks live in the same auto-block table)"
            );
        }
        self.metrics.validate()?;
        self.logging.validate()?;
        Ok(())
    }
}

/// Bail with a uniform message unless `min <= value <= max`.
fn check_range(option: &str, value: u64, min: u64, max: u64) -> Result<()> {
    if value < min || value > max {
        bail!("{option} must be between {min} and {max} (got {value})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_default_matches_struct_default() {
        // The documented template shipped to users must parse and agree with
        // Config::default (metrics addr is commented out -> None).
        let parsed: Config = toml::from_str(DEFAULT_CONFIG_TOML).expect("default toml parses");
        assert_eq!(parsed, Config::default());
        parsed.validate().expect("default config is valid");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("nonsense_key = 1").unwrap_err();
        assert!(err.to_string().contains("nonsense_key"));
        // also inside a section
        assert!(toml::from_str::<Config>("[filter]\nnonsense_key = 1").is_err());
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        let cfg: Config =
            toml::from_str("[filter]\nhost_connection_limit = 0\n\n[metrics]\nenabled = true")
                .unwrap();
        assert_eq!(cfg.filter.host_connection_limit, 0); // throttle disabled
        assert!(cfg.metrics.enabled);
        assert_eq!(cfg.filter.start_port, 25565); // default preserved
        assert_eq!(cfg.xdp.mode, ConfigXdpMode::Auto); // untouched section defaulted
    }

    #[test]
    fn legacy_hit_count_alias_still_parses() {
        let cfg: Config = toml::from_str("[filter]\nhit_count = 7").unwrap();
        assert_eq!(cfg.filter.host_connection_limit, 7);
    }

    #[test]
    fn rejects_inverted_port_range() {
        let cfg: Config = toml::from_str("[filter]\nstart_port = 30000\nend_port = 25565").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_start_port() {
        let cfg: Config = toml::from_str("[filter]\nstart_port = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_or_oversized_window() {
        for window in [0u32, 4001] {
            let cfg: Config = toml::from_str(&format!("[filter]\nwindow_ms = {window}")).unwrap();
            assert!(cfg.validate().is_err(), "window_ms = {window} must be rejected");
        }
    }

    #[test]
    fn rejects_zero_idle_timeout() {
        let cfg: Config = toml::from_str("[filter]\nplayer_idle_timeout_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_oversized_idle_timeout() {
        let cfg: Config = toml::from_str("[filter]\nplayer_idle_timeout_secs = 86401").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_xdp_mode() {
        let err = toml::from_str::<Config>("[xdp]\nmode = \"hardware\"").unwrap_err();
        assert!(err.to_string().contains("hardware"));
    }

    #[test]
    fn rejects_zero_map_capacity() {
        for option in [
            "max_pending_connections",
            "max_player_connections",
            "max_throttled_ips",
            "max_allowlist_entries",
            "max_talkers",
            "max_egress_flows",
        ] {
            let cfg: Config = toml::from_str(&format!("[xdp]\n{option} = 0")).unwrap();
            assert!(cfg.validate().is_err(), "{option} = 0 must be rejected");
        }
    }

    #[test]
    fn hardened_defaults_are_safe() {
        let cfg = Config::default();
        assert!(!cfg.filter.dry_run, "dry run must be opt-in");
        assert!(
            cfg.filter.drop_reserved_sources,
            "reserved source filtering is safe and on by default"
        );
        assert!(
            !cfg.filter.drop_private_sources,
            "private sources must stay allowed (same-host proxies)"
        );
        assert!(cfg.xdp.allowlist_file.is_none());
        assert!(!cfg.ingress.default_deny, "default-deny must be opt-in");
        assert!(!cfg.ingress.egress_tracking, "tc attach must be opt-in");
        assert!(!cfg.blocklist.autoblock, "auto-blocking must be opt-in");
        assert!(cfg.autotune.dry_run, "autotune must start in dry-run");
        assert_eq!(cfg.ml.mode, MlMode::Shadow, "ml must start in shadow mode");
    }

    #[test]
    fn allowlist_file_is_validated() {
        let cfg: Config = toml::from_str("[xdp]\nallowlist_file = \"  \"").unwrap();
        assert!(cfg.validate().is_err());

        let cfg: Config = toml::from_str("[xdp]\nallowlist_file = \"/etc/mc/allow.txt\"").unwrap();
        assert_eq!(cfg.xdp.allowlist_file.as_deref(), Some("/etc/mc/allow.txt"));
        cfg.validate().unwrap();
    }

    #[test]
    fn default_deny_requires_egress_tracking() {
        let cfg: Config = toml::from_str("[ingress]\ndefault_deny = true").unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err:#}").contains("egress_tracking"), "{err:#}");

        let cfg: Config =
            toml::from_str("[ingress]\ndefault_deny = true\negress_tracking = true").unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn open_ports_are_validated() {
        let cfg: Config =
            toml::from_str("[ingress]\nopen_tcp_ports = [25565]").unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err:#}").contains("minecraft range"), "{err:#}");

        let cfg: Config = toml::from_str(
            "[ingress]\negress_tracking = true\ndefault_deny = true\nopen_tcp_ports = [8080]",
        )
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn bedrock_bounds_are_validated() {
        let cfg: Config =
            toml::from_str("[bedrock]\nenabled = true\nmtu_min = 1500\nmtu_max = 576").unwrap();
        assert!(cfg.validate().is_err());

        let cfg: Config =
            toml::from_str("[bedrock]\nenabled = true\nstrict_protocol_version = true\nprotocol_min = 800\nprotocol_max = 700")
                .unwrap();
        assert!(cfg.validate().is_err());

        // disabled sections are not validated
        let cfg: Config =
            toml::from_str("[bedrock]\nmtu_min = 1500\nmtu_max = 576").unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn rules_are_validated() {
        let cfg: Config =
            toml::from_str("[[rules]]\nproto = \"sctp\"\nport = 9\naction = \"drop\"").unwrap();
        assert!(cfg.validate().is_err());

        let cfg: Config =
            toml::from_str("[[rules]]\nproto = \"udp\"\nport = 0\naction = \"drop\"").unwrap();
        assert!(cfg.validate().is_err());

        let cfg: Config =
            toml::from_str("[[rules]]\nproto = \"udp\"\nport = 27015\naction = \"rate\"\nmax_rate = 100\nmagic = \"abcd\"\nmin_len = 10\nmax_len = 4")
                .unwrap();
        assert!(cfg.validate().is_err());

        let cfg: Config = toml::from_str(
            "[[rules]]\nname = \"game\"\nproto = \"udp\"\nport = 27015\naction = \"rate\"\nmax_rate = 100\nmagic = \"0a0b\"\nmin_len = 2\nmax_len = 1200",
        )
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn magic_is_decoded_little_endian() {
        let cfg: Config =
            toml::from_str("[[rules]]\nproto = \"udp\"\nport = 1\naction = \"allow\"\nmagic = \"0102\"")
                .unwrap();
        let (word, mask) = cfg.rules[0].magic_bytes();
        assert_eq!(word, 0x0201);
        assert_eq!(mask, 0xffff);

        let cfg: Config = toml::from_str("[[rules]]\nproto = \"udp\"\nport = 1\naction = \"allow\"")
            .unwrap();
        assert_eq!(cfg.rules[0].magic_bytes(), (0, 0));
    }

    #[test]
    fn autotune_bounds_are_validated() {
        let cfg: Config = toml::from_str(
            "[autotune]\nenabled = true\nhost_limit_min = 100\nhost_limit_max = 50",
        )
        .unwrap();
        assert!(cfg.validate().is_err());

        let cfg: Config =
            toml::from_str("[autotune]\nenabled = true\nrelax_syn_per_sec = 100.0\ntighten_syn_per_sec = 10.0")
                .unwrap();
        assert!(cfg.validate().is_err());

        // disabled autotune is never validated
        let cfg: Config =
            toml::from_str("[autotune]\nhost_limit_min = 100\nhost_limit_max = 50").unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn autotune_requires_a_nonzero_starting_limit() {
        let cfg: Config = toml::from_str(
            "[filter]\nhost_connection_limit = 0\n\n[autotune]\nenabled = true",
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_poll_interval() {
        let cfg: Config = toml::from_str("[metrics]\npoll_secs = 0").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ml_enforce_requires_autoblock() {
        let cfg: Config = toml::from_str(
            "[ml]\nenabled = true\nmode = \"enforce\"\n\n[blocklist]\nautoblock = false",
        )
        .unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err:#}").contains("autoblock"), "{err:#}");

        let cfg: Config = toml::from_str(
            "[ml]\nenabled = true\nmode = \"enforce\"\n\n[blocklist]\nautoblock = true",
        )
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_log_level() {
        let err = toml::from_str::<Config>("[logging]\nlevel = \"verbose\"").unwrap_err();
        assert!(err.to_string().contains("verbose"));
    }

    #[test]
    fn icmp_policy_parses() {
        for (text, expected) in [
            ("allow", IcmpPolicy::Allow),
            ("smart", IcmpPolicy::Smart),
            ("drop", IcmpPolicy::Drop),
        ] {
            let cfg: Config = toml::from_str(&format!("[ingress]\nicmp = \"{text}\"")).unwrap();
            assert_eq!(cfg.ingress.icmp, expected);
        }
        let err = toml::from_str::<Config>("[ingress]\nicmp = \"sometimes\"").unwrap_err();
        assert!(err.to_string().contains("sometimes"));
    }
}
