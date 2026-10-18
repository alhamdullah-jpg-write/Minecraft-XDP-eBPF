use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray};
use aya::{Ebpf, Pod};
use log::{debug, error, info, warn};
use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGauge, TextEncoder, register_int_counter,
    register_int_counter_vec, register_int_gauge,
};

use crate::config::Config;
use crate::shutdown::Shutdown;

/// Number of drop-reason slots in `struct statistics.reason[]` (xdp/stats.h).
const DROP_REASON_SLOTS: usize = 32;

/// Names of the drop reasons, indexed like the `enum drop_reason` in
/// xdp/stats.h. The order (and length) must match that enum - reasons are
/// only ever compared by index, so reordering this list silently mislabels
/// every metric. Adding a reason on the C side means adding it here too.
const DROP_REASONS: [&str; 25] = [
    "eth_malformed",
    "ip_malformed",
    "ip_fragment",
    "tcp_malformed",
    "reserved_source",
    "private_source",
    "tcp_flags",
    "syn_payload",
    "throttle_limit",
    "throttle_state",
    "track_state",
    "not_tracked",
    "bad_ack",
    "sequence_mismatch",
    "out_of_order_limit",
    "handshake_invalid",
    "legacy_ping",
    "status_invalid",
    "ping_invalid",
    "login_invalid",
    "ping_extra",
    "empty_ack",
    "empty_segment",
    "verify_failed",
    "verify_map_full",
];

// the listed reasons cover every value the C code can produce; the remaining
// slots in struct statistics.reason[] are never incremented (the drop reason
// is masked into the array by drop_verdict)
const _: () = assert!(DROP_REASONS.len() <= DROP_REASON_SLOTS);

/// Userspace mirror of `struct statistics` (xdp/stats.h). Field order and
/// types must match the C struct exactly; the size assertion below mirrors
/// the `_Static_assert` in xdp/stats.h so layout drift fails the build here
/// as well as in the C build.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Statistics {
    pub verified: u64,
    pub verified_packets: u64,
    pub dropped_packets: u64,
    pub state_switches: u64,
    pub drop_connection: u64,
    pub syn: u64,
    pub tcp_bypass: u64,
    pub incoming_bytes: u64,
    pub dropped_bytes: u64,
    pub ipv6_packets: u64,
    pub reason: [u64; DROP_REASON_SLOTS],
}

// SAFETY: repr(C) struct of plain u64 fields without padding, valid for any
// bit pattern read from the map.
unsafe impl Pod for Statistics {}

impl Statistics {
    fn add(&mut self, other: &Statistics) {
        self.verified += other.verified;
        self.verified_packets += other.verified_packets;
        self.dropped_packets += other.dropped_packets;
        self.state_switches += other.state_switches;
        self.drop_connection += other.drop_connection;
        self.syn += other.syn;
        self.tcp_bypass += other.tcp_bypass;
        self.incoming_bytes += other.incoming_bytes;
        self.dropped_bytes += other.dropped_bytes;
        self.ipv6_packets += other.ipv6_packets;
        for (total, value) in self.reason.iter_mut().zip(other.reason) {
            *total += value;
        }
    }
}

// compile-time layout check, mirrors the _Static_assert in xdp/stats.h
const _: () = assert!(std::mem::size_of::<Statistics>() == 336);

/// 1 while the filter runs in dry-run mode (counts drops, drops nothing).
/// Published so a dashboard can never mistake would-be drops for real ones.
static DRY_RUN: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "minecraft_dry_run",
        "1 when the filter runs in dry-run mode (nothing is dropped)"
    )
    .expect("register minecraft_dry_run")
});

/// Number of source addresses currently in the allowlist map; maintained by
/// `allowlist.rs` on every (re)load.
pub static ALLOWLIST_ENTRIES: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "minecraft_allowlist_entries",
        "Source addresses currently in the eBPF allowlist"
    )
    .expect("register minecraft_allowlist_entries")
});

/// The Prometheus counters the statistics map is published to.
struct Counters {
    verified: IntCounter,
    verified_packets: IntCounter,
    dropped_packets: IntCounter,
    state_switches: IntCounter,
    drop_connection: IntCounter,
    syn: IntCounter,
    tcp_bypass: IntCounter,
    incoming_bytes: IntCounter,
    dropped_bytes: IntCounter,
    ipv6_packets: IntCounter,
    reason: IntCounterVec,
}

impl Counters {
    fn new() -> Self {
        // in dry run the per-reason counters count packets that *would* have
        // been dropped; a separate name keeps them out of drop rate alerting
        let reason_name = if DRY_RUN.get() == 1 {
            "minecraft_would_drop_reason"
        } else {
            "minecraft_drop_reason"
        };
        Self {
            verified: register_int_counter!(
                "minecraft_verified_connections",
                "Total verified connections"
            )
            .unwrap(),
            verified_packets: register_int_counter!(
                "minecraft_verified_packets",
                "Packets passed on the verified fast path"
            )
            .unwrap(),
            dropped_packets: register_int_counter!(
                "minecraft_dropped_packets",
                "Total dropped packets"
            )
            .unwrap(),
            state_switches: register_int_counter!(
                "minecraft_state_switches",
                "Total connection state switches"
            )
            .unwrap(),
            drop_connection: register_int_counter!(
                "minecraft_dropped_connections",
                "Total drop-connection verdicts"
            )
            .unwrap(),
            syn: register_int_counter!("minecraft_syn_packets", "Total SYN packets").unwrap(),
            tcp_bypass: register_int_counter!(
                "minecraft_tcp_bypass",
                "Total TCP bypass attempts (packets that skip the parser)"
            )
            .unwrap(),
            incoming_bytes: register_int_counter!(
                "minecraft_incoming_bytes",
                "Total incoming bytes on the filtered ports"
            )
            .unwrap(),
            dropped_bytes: register_int_counter!(
                "minecraft_dropped_bytes",
                "Total dropped bytes"
            )
            .unwrap(),
            ipv6_packets: register_int_counter!(
                "minecraft_ipv6_packets",
                "IPv6 packets seen on the filtered ports (not filtered yet)"
            )
            .unwrap(),
            reason: register_int_counter_vec!(
                reason_name,
                "Dropped packets per drop reason",
                &["reason"]
            )
            .unwrap(),
        }
    }

    /// Publishes cumulative map totals as counter increments. The unpinned
    /// stats map and this process always die together, so publishing the
    /// delta since the last poll keeps proper counter semantics; on restart
    /// both reset together, which Prometheus handles as a regular counter
    /// reset.
    fn publish(&self, total: &Statistics) {
        Self::inc_delta(&self.verified, total.verified);
        Self::inc_delta(&self.verified_packets, total.verified_packets);
        Self::inc_delta(&self.dropped_packets, total.dropped_packets);
        Self::inc_delta(&self.state_switches, total.state_switches);
        Self::inc_delta(&self.drop_connection, total.drop_connection);
        Self::inc_delta(&self.syn, total.syn);
        Self::inc_delta(&self.tcp_bypass, total.tcp_bypass);
        Self::inc_delta(&self.incoming_bytes, total.incoming_bytes);
        Self::inc_delta(&self.dropped_bytes, total.dropped_bytes);
        Self::inc_delta(&self.ipv6_packets, total.ipv6_packets);
        for (index, name) in DROP_REASONS.iter().enumerate() {
            let counter = self.reason.with_label_values(&[name]);
            counter.inc_by(total.reason[index].saturating_sub(counter.get()));
        }
    }

    fn inc_delta(counter: &IntCounter, total: u64) {
        counter.inc_by(total.saturating_sub(counter.get()));
    }
}

/// Starts the metrics machinery if enabled in the config: takes ownership of
/// the stats map, spawns the polling thread and (when an address is
/// configured) the HTTP endpoint. Returns the polling thread's handle.
pub fn start(
    ebpf: &mut Ebpf,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    // set this even when the endpoint is disabled: the gauge also drives the
    // dry-run/would-drop naming of the reason counter
    DRY_RUN.set(config.filter.dry_run as i64);
    if config.filter.dry_run {
        warn!(
            "Dry-run mode is enabled: the filter counts and logs drops but lets every packet through"
        );
    }

    if !config.metrics.enabled {
        return Ok(None);
    }

    let map = ebpf
        .take_map("stats_map")
        .context("can't take map 'stats_map'")?;
    let stats = PerCpuArray::try_from(map)?;

    match &config.metrics.addr {
        Some(addr) => serve_http(addr.clone()),
        None => info!("Metrics collection enabled but no addr set; HTTP endpoint disabled"),
    }

    let poll_interval = Duration::from_secs(config.metrics.poll_secs);
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("track-stats".into())
        .spawn(move || poll_loop(stats, shutdown, poll_interval))?;
    Ok(Some(handle))
}

/// Sums the per-cpu slices of the stats map and publishes the totals every
/// `poll_interval` until shutdown ends the loop. Read errors are logged and
/// retried next interval: metrics are auxiliary and must never take down the
/// filter itself.
fn poll_loop(
    stats: PerCpuArray<MapData, Statistics>,
    shutdown: Arc<Shutdown>,
    poll_interval: Duration,
) {
    loop {
        match stats.get(&0, 0) {
            Ok(per_cpu) => {
                let mut total = Statistics::default();
                for cpu_stats in per_cpu.iter() {
                    total.add(cpu_stats);
                }
                debug!("Stats: {total:?}");
                COUNTERS.publish(&total);
            }
            Err(e) => {
                error!("Failed to read stats map (retrying next interval): {e}");
            }
        }
        if !shutdown.sleep(poll_interval) {
            return;
        }
    }
}

static COUNTERS: LazyLock<Counters> = LazyLock::new(Counters::new);

/// Serves the Prometheus text endpoint on `addr` from its own thread.
fn serve_http(addr: String) {
    thread::spawn(move || {
        let server = match tiny_http::Server::http(&addr) {
            Ok(server) => server,
            Err(e) => {
                error!("Failed to start metrics server: {e}");
                return;
            }
        };
        info!("Prometheus metrics server running on {addr}/metrics");
        for request in server.incoming_requests() {
            if request.url() != "/metrics" {
                let _ = request.respond(tiny_http::Response::empty(404));
                continue;
            }
            debug!("Received metrics request from {:?}", request.remote_addr());
            let mut buffer = vec![];
            if let Err(e) = TextEncoder::new().encode(&prometheus::gather(), &mut buffer) {
                error!("Failed to encode metrics: {e}");
                continue;
            }
            let response = tiny_http::Response::from_data(buffer).with_header(
                tiny_http::Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/plain; version=0.0.4; charset=utf-8"[..],
                )
                .unwrap(),
            );
            let _ = request.respond(response);
        }
    });
}
