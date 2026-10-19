use anyhow::{Context, Result};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode, tc};
use aya::{Ebpf, EbpfLoader, include_bytes_aligned};
use log::{debug, info};

use crate::config::{Config, ConfigXdpMode};
use crate::tunables::{Tunables, TunablesHandle};

/// The loaded and attached filter: the `Ebpf` handle owns every attachment
/// (dropping it detaches) and the tunables handle owns the runtime limits.
pub struct Attached {
    pub ebpf: Ebpf,
    pub tunables: TunablesHandle,
    /// The XDP mode that actually worked (auto may have fallen back).
    pub mode: ConfigXdpMode,
}

/// Appended to attach failures. The feature switches live in `.rodata` and
/// the verifier only explores the code paths a value keeps reachable, so a
/// program that verified with default values can still be rejected for a
/// config that enables another path - the verifier log in the error below
/// says which bounds check failed.
const VERIFIER_HINT: &str = "if the verifier log is in this error, the config enabled a code \
     path the verifier rejects (the shipped object is verified in \
     xdp/tests/verifier_load.sh with defaults and in tests/e2e_loader.sh with every \
     feature on): narrow it down by re-enabling features one at a time";

/// Loads the embedded eBPF object, applies the runtime configuration,
/// attaches the XDP program to `interface` and - when egress tracking is
/// enabled - the tc egress program that records the pinhole flows.
///
/// The returned handle owns the attachments: dropping it detaches the
/// filter. No userspace involvement is needed while it runs, all map cleanup
/// (throttle windows, idle player connections, block expiry) happens
/// in-kernel via `bpf_timer` or is bounded by `expires_ns`.
pub fn load_and_attach(interface: &str, config: &Config) -> Result<Attached> {
    let object = include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/xdp/minecraft_filter.o"
    ));
    info!("Loaded BPF object ({} bytes)", object.len());

    // The tunables are derived first: several globals below depend on which
    // limits are active.
    let tunables = Tunables::from_config(config);

    // Push the runtime configuration into the program's `volatile const`
    // globals (BPF .rodata). Each Rust type MUST match its C declaration in
    // xdp/config.h exactly, since override_global() patches size_of::<T>()
    // bytes at the symbol's offset. `must_exist = true` fails loudly if a
    // symbol is missing (e.g. renamed on the C side) instead of silently
    // ignoring the configured value.
    let filter = &config.filter;
    // the statistics map feeds metrics, auto-tuning, ML labels and the
    // advisor: any of them needs the counters
    let prometheus: u8 = (config.metrics.enabled
        || config.autotune.enabled
        || config.ml.enabled
        || config.advisor.enabled) as u8;
    let online_names: u8 = filter.online_names as u8;
    let reject_proxy_header: u8 = filter.reject_proxy_header as u8;
    let verified_pps_limit: u32 = filter.verified_pps_limit;
    let verified_bps_limit: u32 = filter.verified_bps_limit;
    let start_port: u32 = filter.start_port as u32;
    let end_port: u32 = filter.end_port as u32;
    let player_idle_ns: u64 = filter.player_idle_timeout_secs * 1_000_000_000;
    let dry_run: u8 = filter.dry_run as u8;
    let drop_reserved_sources: u8 = filter.drop_reserved_sources as u8;
    let drop_private_sources: u8 = filter.drop_private_sources as u8;
    let allowlist_enabled: u8 = config.xdp.allowlist_file.is_some() as u8;

    let rate_limits_enabled: u8 = (tunables.any_limit_enabled() || config.autotune.enabled) as u8;
    let blocklist_enabled: u8 = config.blocklist.blocklist_file.is_some() as u8;
    let autoblock_enabled: u8 = config.blocklist.autoblock as u8;

    let egress_track_enabled: u8 = config.ingress.egress_tracking as u8;
    let default_deny: u8 = config.ingress.default_deny as u8;
    let egress_timeout_ns: u64 = config.ingress.egress_timeout_secs * 1_000_000_000;
    let egress_window_ns: u64 = 0; // reserved, see xdp/config.h
    let icmp_mode: u8 = config.ingress.icmp.mode();

    let rules_enabled: u8 = (!config.rules.is_empty()
        || !config.ingress.open_tcp_ports.is_empty()
        || !config.ingress.open_udp_ports.is_empty()) as u8;

    let talkers_enabled: u8 = (config.ml.enabled || config.metrics.enabled || config.advisor.enabled) as u8;
    let talker_sample_mask: u32 = 15; // one in 16 packets

    let bedrock_enabled: u8 = config.bedrock.enabled as u8;
    let bedrock_port: u32 = config.bedrock.port as u32;
    let bedrock_strict_version: u8 = config.bedrock.strict_protocol_version as u8;
    let bedrock_proto_min: u32 = config.bedrock.protocol_min;
    let bedrock_proto_max: u32 = config.bedrock.protocol_max;
    let bedrock_mtu_min: u32 = config.bedrock.mtu_min;
    let bedrock_mtu_max: u32 = config.bedrock.mtu_max;

    let voice_enabled: u8 = config.voice.enabled as u8;
    let voice_port: u32 = config.voice.port as u32;
    let voice_require_verified: u8 = config.voice.require_verified_ip as u8;
    let voice_max_type: u32 = config.voice.max_packet_type;

    // verified addresses are the voice gate's evidence and the ML labels;
    // the kernel refreshes them from the player idle timer while a
    // connection lives, so three idle intervals of TTL leave a margin
    let verified_sources_enabled: u8 =
        (config.voice.require_verified_ip || config.ml.enabled) as u8;
    let verified_sources_ttl_ns: u64 = player_idle_ns.saturating_mul(3).max(60_000_000_000);

    let mut ebpf = EbpfLoader::new()
        .override_global("PROMETHEUS", &prometheus, true)
        .override_global("ONLINE_NAMES", &online_names, true)
        .override_global("REJECT_PROXY_HEADER", &reject_proxy_header, true)
        .override_global("VERIFIED_PPS_LIMIT", &verified_pps_limit, true)
        .override_global("VERIFIED_BPS_LIMIT", &verified_bps_limit, true)
        .override_global("DRY_RUN", &dry_run, true)
        .override_global("DROP_RESERVED_SOURCES", &drop_reserved_sources, true)
        .override_global("DROP_PRIVATE_SOURCES", &drop_private_sources, true)
        .override_global("ALLOWLIST_ENABLED", &allowlist_enabled, true)
        .override_global("START_PORT", &start_port, true)
        .override_global("END_PORT", &end_port, true)
        .override_global("PLAYER_IDLE_NS", &player_idle_ns, true)
        .override_global("RATE_LIMITS_ENABLED", &rate_limits_enabled, true)
        .override_global("BLOCKLIST_ENABLED", &blocklist_enabled, true)
        .override_global("AUTOBLOCK_ENABLED", &autoblock_enabled, true)
        .override_global("EGRESS_TRACK_ENABLED", &egress_track_enabled, true)
        .override_global("DEFAULT_DENY", &default_deny, true)
        .override_global("EGRESS_TIMEOUT_NS", &egress_timeout_ns, true)
        .override_global("EGRESS_WINDOW_NS", &egress_window_ns, true)
        .override_global("ICMP_MODE", &icmp_mode, true)
        .override_global("RULES_ENABLED", &rules_enabled, true)
        .override_global("TALKERS_ENABLED", &talkers_enabled, true)
        .override_global("TALKER_SAMPLE_MASK", &talker_sample_mask, true)
        .override_global("BEDROCK_ENABLED", &bedrock_enabled, true)
        .override_global("BEDROCK_PORT", &bedrock_port, true)
        .override_global("BEDROCK_STRICT_VERSION", &bedrock_strict_version, true)
        .override_global("BEDROCK_PROTO_MIN", &bedrock_proto_min, true)
        .override_global("BEDROCK_PROTO_MAX", &bedrock_proto_max, true)
        .override_global("BEDROCK_MTU_MIN", &bedrock_mtu_min, true)
        .override_global("BEDROCK_MTU_MAX", &bedrock_mtu_max, true)
        .override_global("VOICE_ENABLED", &voice_enabled, true)
        .override_global("VOICE_PORT", &voice_port, true)
        .override_global("VOICE_REQUIRE_VERIFIED", &voice_require_verified, true)
        .override_global("VOICE_MAX_TYPE", &voice_max_type, true)
        .override_global("VERIFIED_SOURCES_ENABLED", &verified_sources_enabled, true)
        .override_global("VERIFIED_SOURCES_TTL_NS", &verified_sources_ttl_ns, true)
        // Replace the placeholder map capacities baked into the object with
        // the configured ones. The names must match the map definitions in
        // xdp/maps.h; unlike set_global() there is no must_exist flag, a
        // mismatched name would be silently ignored.
        .map_max_entries("conntrack_map", config.xdp.max_pending_connections)
        .map_max_entries("player_connection_map", config.xdp.max_player_connections)
        .map_max_entries("host_throttle", config.xdp.max_throttled_ips)
        .map_max_entries("udp_throttle", config.xdp.max_throttled_ips)
        .map_max_entries("subnet_throttle", config.xdp.max_throttled_subnets)
        .map_max_entries("rule_rates", config.xdp.max_rule_rate_entries)
        .map_max_entries("verified_sources", config.xdp.max_verified_sources)
        .map_max_entries("talkers_map", config.xdp.max_talkers)
        .map_max_entries("egress_flows", config.xdp.max_egress_flows)
        .map_max_entries("autoblock_map", config.xdp.max_autoblock_entries)
        .map_max_entries("blocklist_map", config.blocklist.max_entries)
        .map_max_entries("allowlist_map", config.xdp.max_allowlist_entries)
        .load(object)
        .context("failed to load BPF program")?;

    // Write the runtime limits before anything can execute: attaching the
    // program with the placeholder limits would briefly filter with
    // everything off.
    let tunables = TunablesHandle::init(&mut ebpf, config)?;

    let program: &mut Xdp = ebpf
        .program_mut("minecraft_filter")
        .context("program 'minecraft_filter' not found")?
        .try_into()?;
    program.load()?;

    // Auto does its own driver -> skb fallback instead of leaving the choice
    // to the kernel, so the mode that is actually active can be logged.
    let (link, mode) = match config.xdp.mode {
        ConfigXdpMode::Auto => match program.attach(interface, XdpMode::Driver) {
            Ok(link) => (link, ConfigXdpMode::Driver),
            Err(err) => {
                info!("'{interface}' does not support native XDP ({err}), using generic skb mode");
                let link = program
                    .attach(interface, XdpMode::Skb)
                    .with_context(|| {
                        format!("failed to attach to interface '{interface}'; {VERIFIER_HINT}")
                    })?;
                (link, ConfigXdpMode::Skb)
            }
        },
        ConfigXdpMode::Driver => {
            let link = program
                .attach(interface, XdpMode::Driver)
                .with_context(|| {
                    format!(
                        "failed to attach to interface '{interface}' in native driver mode \
                     (the NIC driver may not support XDP; try mode = \"skb\"); {VERIFIER_HINT}"
                    )
                })?;
            (link, ConfigXdpMode::Driver)
        }
        ConfigXdpMode::Skb => {
            let link = program.attach(interface, XdpMode::Skb).with_context(|| {
                format!("failed to attach to interface '{interface}' in skb mode; {VERIFIER_HINT}")
            })?;
            (link, ConfigXdpMode::Skb)
        }
    };
    info!("BPF program attached to interface {interface} in {mode} mode ({link:?})");
    if config.ingress.egress_tracking {
        attach_egress(interface, &mut ebpf)?;
    }

    for (name, _) in ebpf.maps() {
        debug!("Found map: {name}");
    }

    Ok(Attached {
        ebpf,
        tunables,
        mode,
    })
}

/// Attaches the tc egress tracker. On kernels >= 6.6 aya uses a TCX link and
/// the clsact qdisc is not needed; older kernels fall back to netlink, where
/// it is. Adding the qdisc is therefore best-effort: "already attached" is
/// the normal outcome and anything else is retried implicitly by the attach
/// below failing with the netlink error.
fn attach_egress(interface: &str, ebpf: &mut Ebpf) -> Result<()> {
    if let Err(error) = tc::qdisc_add_clsact(interface) {
        debug!("clsact qdisc on {interface}: {error} (fine on kernels using TCX)");
    }
    let program: &mut SchedClassifier = ebpf
        .program_mut("tc_egress_track")
        .context("program 'tc_egress_track' not found")?
        .try_into()?;
    program
        .load()
        .context(format!("failed to load the tc egress program; {VERIFIER_HINT}"))?;
    program
        .attach(interface, TcAttachType::Egress)
        .with_context(|| {
            format!("failed to attach the tc egress program to '{interface}'")
        })?;
    info!("Egress flow tracking attached to {interface} (tc egress)");
    Ok(())
}
