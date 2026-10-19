//! Sizing and NIC advice.
//!
//! Two jobs, both read-only:
//!
//!  - at startup: print an estimate of the map memory the configuration
//!    allocates plus pointers for the values that look off (generic XDP mode,
//!    tiny maps for a public server, missing metrics, ...).
//!  - while running: watch the drop reasons that mean "a map or a limit was
//!    too small" and warn once per interval with the option to raise.
//!
//! The advisor never changes anything - the auto-tuner owns the limits, this
//! only explains what the counters mean.

use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use aya::maps::{MapData, PerCpuArray};
use log::{debug, info, warn};

use crate::config::{Config, ConfigXdpMode, IcmpPolicy};
use crate::metrics::{self, Statistics};
use crate::shutdown::Shutdown;

/// How often the running advisor compares reason counters.
const CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Approximate bytes of map bookkeeping per entry on top of key + value
/// (hash buckets, LRU lists, timer callbacks). Deliberately an estimate: the
/// kernel rounds maps up, and the point of the number is picking the right
/// order of magnitude when sizing a host.
const PER_ENTRY_OVERHEAD: u64 = 64;

/// One map's sizing input: name, entries, key and value size.
struct MapSize {
    name: &'static str,
    entries: u64,
    key: u64,
    value: u64,
    /// LRU/hash maps pay per-entry overhead; the array-like maps do not.
    hash: bool,
}

/// Logs the sizing estimate and the recommendations for `config` on
/// `interface`. `mode` is the attach mode that actually worked.
pub fn startup(interface: &str, mode: ConfigXdpMode, config: &Config) {
    let maps = [
        MapSize {
            name: "conntrack_map",
            entries: config.xdp.max_pending_connections as u64,
            key: 40,
            value: 12,
            hash: true,
        },
        MapSize {
            name: "player_connection_map",
            entries: config.xdp.max_player_connections as u64,
            key: 40,
            value: 32,
            hash: true,
        },
        MapSize {
            name: "host_throttle",
            entries: config.xdp.max_throttled_ips as u64,
            key: 20,
            value: 40,
            hash: true,
        },
        MapSize {
            name: "udp_throttle",
            entries: config.xdp.max_throttled_ips as u64,
            key: 20,
            value: 40,
            hash: true,
        },
        MapSize {
            name: "subnet_throttle",
            entries: config.xdp.max_throttled_subnets as u64,
            key: 20,
            value: 40,
            hash: true,
        },
        MapSize {
            name: "rule_rates",
            entries: config.xdp.max_rule_rate_entries as u64,
            key: 24,
            value: 40,
            hash: true,
        },
        MapSize {
            name: "verified_sources",
            entries: config.xdp.max_verified_sources as u64,
            key: 20,
            value: 32,
            hash: true,
        },
        MapSize {
            name: "talkers_map",
            entries: config.xdp.max_talkers as u64,
            key: 20,
            value: 40,
            hash: true,
        },
        MapSize {
            name: "egress_flows",
            entries: config.xdp.max_egress_flows as u64,
            key: 40,
            value: 32,
            hash: true,
        },
        MapSize {
            name: "autoblock_map",
            entries: config.xdp.max_autoblock_entries as u64,
            key: 20,
            value: 24,
            hash: true,
        },
        MapSize {
            name: "allowlist_map",
            entries: config.xdp.max_allowlist_entries as u64,
            key: 20,
            value: 1,
            hash: false,
        },
        MapSize {
            name: "blocklist_map",
            entries: config.blocklist.max_entries as u64,
            key: 20,
            value: 24,
            hash: false,
        },
    ];
    let mut total = 0u64;
    for map in &maps {
        let per_entry = map.key + map.value + if map.hash { PER_ENTRY_OVERHEAD } else { 32 };
        let bytes = map.entries * per_entry;
        total += bytes;
        debug!(
            "Advisor: {}: {} entries x ~{} B = ~{} KiB",
            map.name,
            map.entries,
            per_entry,
            bytes / 1024
        );
    }
    info!(
        "Advisor: map memory estimate ~{:.1} MiB ({} entries, key+value+bookkeeping)",
        total as f64 / (1024.0 * 1024.0),
        maps.iter().map(|map| map.entries).sum::<u64>()
    );

    if mode == ConfigXdpMode::Skb {
        if is_physical(interface) {
            warn!(
                "Advisor: '{interface}' runs in generic (skb) XDP mode: packets are copied before \
                 the filter sees them and GRO coalesces segments. Use a NIC/driver with native \
                 XDP support for the full benefit (native mode inspects every segment)"
            );
        } else {
            info!(
                "Advisor: '{interface}' is a virtual interface and runs in generic (skb) mode - \
                 normal here, the numbers still hold for testing and for veth/virtio setups"
            );
        }
    } else {
        info!("Advisor: '{interface}' runs in native driver mode (per-packet inspection)");
    }
    if let Some(queues) = rx_queue_count(interface) {
        info!("Advisor: '{interface}' has {queues} RX queue(s); spread the IRQs across cores for scale");
    }
    if config.filter.dry_run {
        info!("Advisor: dry_run = true - drops are only counted, remove it when the numbers look right");
    }
    if config.metrics.enabled && config.metrics.addr.is_none() {
        info!("Advisor: [metrics] enabled without addr: counters are collected but not published");
    }
    if !config.metrics.enabled {
        info!("Advisor: enable [metrics] to see per-reason counters while tuning");
    }
    if config.xdp.max_player_connections < 1024 {
        warn!(
            "Advisor: [xdp] max_player_connections = {} is small for a public server; \
             a full map shows up as the verify_map_full drop reason",
            config.xdp.max_player_connections
        );
    }
    if config.blocklist.autoblock && config.blocklist.export_file.is_none() {
        info!(
            "Advisor: auto-blocking is on without [blocklist] export_file: blocks stay local. \
             Export them to enforce upstream (nftables, blackhole routes, provider APIs)"
        );
    }
    if config.bedrock.enabled && config.filter.udp_packet_limit == 0 {
        info!(
            "Advisor: [bedrock] enabled with udp_packet_limit = 0: handshake validation is on, \
             but a UDP flood is not rate limited. Consider e.g. 300"
        );
    }
    if config.ingress.icmp == IcmpPolicy::Allow && config.ingress.default_deny {
        info!("Advisor: default_deny with icmp = \"allow\" leaves echo floods open; \"smart\" is stricter");
    }
}

/// Starts the periodic capacity warnings. Returns `None` when the advisor is
/// disabled (the startup advice is logged by `startup` either way).
pub fn start(
    stats: Option<Arc<PerCpuArray<MapData, Statistics>>>,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>, anyhow::Error> {
    if !config.advisor.enabled {
        return Ok(None);
    }
    let Some(stats) = stats else {
        // without the stats map there is nothing to watch; the loader only
        // gets here when PROMETHEUS is off for every other consumer
        return Ok(None);
    };
    let shutdown = shutdown.clone();
    let interval = CHECK_INTERVAL;
    let handle = thread::Builder::new()
        .name("advisor".into())
        .spawn(move || run(stats, shutdown, interval))?;
    Ok(Some(handle))
}

fn run(
    stats: Arc<PerCpuArray<MapData, Statistics>>,
    shutdown: Arc<Shutdown>,
    interval: Duration,
) {
    let mut previous: Option<Statistics> = None;
    loop {
        if !shutdown.sleep(interval) {
            return;
        }
        let total = match metrics::read(&stats) {
            Ok(total) => total,
            Err(error) => {
                warn!("Advisor: {error:#}");
                continue;
            }
        };
        if let Some(previous) = &previous {
            for (reason, advice) in [
                (
                    "verify_map_full",
                    "raise [xdp] max_player_connections (or shed: the map is at capacity)",
                ),
                (
                    "throttle_state",
                    "raise [xdp] max_throttled_ips: the per-source throttle map is full",
                ),
                (
                    "rate_state",
                    "raise [xdp] max_throttled_ips / max_rule_rate_entries: a rate map is full",
                ),
                (
                    "track_state",
                    "the conntrack map is full: expected under flood, raise max_pending_connections if it persists in quiet periods",
                ),
                (
                    "ip_malformed",
                    "malformed IP packets: verify NIC checksum/segmentation offloads if this grows in quiet periods",
                ),
                (
                    "bedrock_invalid",
                    "invalid raknet handshakes: either a bedrock flood or a fork with an unexpected handshake shape",
                ),
            ] {
                let index = metrics::drop_reason_index(reason).expect("known reason");
                let delta = total
                    .reason_count(index)
                    .saturating_sub(previous.reason_count(index));
                if delta > 0 {
                    warn!(
                        "Advisor: {delta} packet(s) hit '{reason}' since the last check - {advice}"
                    );
                }
            }
        }
        previous = Some(total);
    }
}

/// Number of RX queues of `interface` from sysfs, when readable.
fn rx_queue_count(interface: &str) -> Option<u64> {
    let path = format!("/sys/class/net/{interface}/queues");
    let entries = std::fs::read_dir(path).ok()?;
    let count = entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("rx-"))
        .count();
    (count > 0).then_some(count as u64)
}

/// True when `interface` is a real device (has a backing `device` link).
pub fn is_physical(interface: &str) -> bool {
    Path::new(&format!("/sys/class/net/{interface}/device")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_runs_for_the_default_config() {
        // must not panic on the defaults (no interface exists in CI)
        startup("lo", ConfigXdpMode::Skb, &Config::default());
    }

    #[test]
    fn physical_detection_never_panics() {
        let _ = is_physical("lo");
        let _ = rx_queue_count("lo");
    }
}
