//! Auto-tuning of the in-kernel rate limits.
//!
//! The control loop watches the statistics map and moves the limits in the
//! `tunables_map` within the configured bounds:
//!
//!  - per-source limit: relaxed while legitimate traffic hits it at a low
//!    SYN rate (NAT/proxy with many players), tightened while the SYN rate
//!    stays above `tighten_syn_per_sec` (flood).
//!  - per-subnet limit: tightened under flood, relaxed back towards the
//!    configured value otherwise.
//!  - host-wide limit (only managed when a starting value is configured):
//!    `4 x smoothed verified-connection rate + headroom`, so a flood cannot
//!    starve the verified fast path while bursts of new players still fit.
//!  - strike threshold: lowered during a flood (block repeat offenders
//!    sooner), raised back in quiet periods.
//!
//! Every field is bounded by its configured min/max, changes at most one
//! step per interval, and waits out a cooldown after each change so the loop
//! cannot oscillate. A limit configured as `0` stays disabled: the loop only
//! manages limits the operator started with a nonzero value. `dry_run = true`
//! logs the changes without applying them; the state file keeps the tuned
//! values across restarts.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray};
use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::config::{AutotuneConfig, Config};
use crate::metrics::{self, Statistics};
use crate::shutdown::Shutdown;
use crate::tunables::{Tunables, TunablesHandle};

/// Exponential moving average factor: 0.3 keeps the reaction inside a few
/// intervals without making a single spike move the limits.
const EMA_ALPHA: f64 = 0.3;
/// A field only moves again after this many intervals.
const COOLDOWN_INTERVALS: u32 = 5;

// indices into the per-field cooldown table
const FIELD_HOST: usize = 0;
const FIELD_SUBNET: usize = 1;
const FIELD_GLOBAL: usize = 2;
const FIELD_UDP: usize = 3;
const FIELD_STRIKES: usize = 4;
const FIELDS: usize = 5;

/// Persisted tuned values (also serves as a partial config file).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PersistedState {
    host_limit: u32,
    subnet_limit: u32,
    global_limit: u32,
    udp_limit: u32,
    rule_limit: u32,
    strike_threshold: u32,
}

impl PersistedState {
    fn from_tunables(tunables: &Tunables) -> PersistedState {
        PersistedState {
            host_limit: tunables.host_limit,
            subnet_limit: tunables.subnet_limit,
            global_limit: tunables.global_limit,
            udp_limit: tunables.udp_limit,
            rule_limit: tunables.rule_limit,
            strike_threshold: tunables.strike_threshold,
        }
    }

    /// Applies the persisted values within the configured bounds; values
    /// outside are ignored (they were written under an older configuration).
    fn apply(&self, tunables: &mut Tunables, config: &AutotuneConfig, managed: Managed) {
        let clamp = |value: u32, min: u32, max: u32| value.clamp(min, max);
        if managed.host && self.host_limit != 0 {
            tunables.host_limit = clamp(self.host_limit, config.host_limit_min, config.host_limit_max);
        }
        if managed.subnet && self.subnet_limit != 0 {
            tunables.subnet_limit =
                clamp(self.subnet_limit, config.subnet_limit_min, config.subnet_limit_max);
        }
        if managed.global && self.global_limit != 0 {
            tunables.global_limit =
                clamp(self.global_limit, config.global_limit_min, config.global_limit_max);
        }
        if self.udp_limit != 0 {
            tunables.udp_limit = self.udp_limit;
        }
        if self.rule_limit != 0 {
            tunables.rule_limit = self.rule_limit;
        }
        if self.strike_threshold != 0 {
            tunables.strike_threshold = self
                .strike_threshold
                .clamp(config.strike_threshold_min, config.strike_threshold_max);
        }
    }
}

/// Per-field cooldown gates.
#[derive(Default)]
struct Cooldowns([Option<Instant>; FIELDS]);

impl Cooldowns {
    fn due(&self, field: usize, now: Instant, cooldown: Duration) -> bool {
        match self.0[field] {
            Some(last) => now.duration_since(last) >= cooldown,
            None => true,
        }
    }

    fn touch(&mut self, field: usize, now: Instant) {
        self.0[field] = Some(now);
    }
}

/// Which limits the control loop may move. Only limits the operator started
/// with a nonzero value are managed: `0` means "disabled", and a tuner that
/// switched a limit back on under attack would cause exactly the collateral
/// drops the operator opted out of.
#[derive(Debug, Clone, Copy)]
struct Managed {
    host: bool,
    subnet: bool,
    global: bool,
}

impl Managed {
    fn from_config(config: &Config) -> Self {
        Self {
            host: config.filter.host_connection_limit != 0,
            subnet: config.filter.subnet_connection_limit != 0,
            global: config.filter.global_connection_limit != 0,
        }
    }
}

/// Per-interval deltas derived from the statistics map.
#[derive(Debug, Default, Clone, Copy)]
struct Deltas {
    syn_rate: f64,
    verified_rate: f64,
    udp_rate: f64,
    throttle_drops: f64,
    udp_drops: f64,
    bedrock_invalid: f64,
}

/// Starts the control loop. `stats` must stay readable (PROMETHEUS is
/// enabled whenever auto-tuning is on) and `tunables` is the handle written
/// by `tunables::init`.
pub fn start(
    tunables: TunablesHandle,
    stats: Arc<PerCpuArray<MapData, Statistics>>,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    if !config.autotune.enabled {
        return Ok(None);
    }

    let mut tunables = tunables;
    let config = config.clone();
    let managed = Managed::from_config(&config);
    if let Some(path) = &config.autotune.state_file {
        let path = PathBuf::from(path);
        if path.exists() {
            match load_state(&path).and_then(|state| {
                let mut next = tunables.current();
                state.apply(&mut next, &config.autotune, managed);
                tunables.apply(next)?;
                Ok(state)
            }) {
                Ok(_) => info!("Auto-tuner: restored state from '{}'", path.display()),
                Err(error) => warn!(
                    "Auto-tuner: ignoring unreadable state file '{}': {error:#}",
                    path.display()
                ),
            }
        }
    }
    if config.autotune.dry_run {
        warn!("Auto-tuner runs in dry-run mode: changes are logged but not applied");
    }

    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("autotune".into())
        .spawn(move || run(tunables, stats, config, shutdown, managed))?;
    Ok(Some(handle))
}

fn run(
    mut tunables: TunablesHandle,
    stats: Arc<PerCpuArray<MapData, Statistics>>,
    config: Config,
    shutdown: Arc<Shutdown>,
    managed: Managed,
) {
    let autotune = &config.autotune;
    let interval = Duration::from_millis(autotune.interval_ms.max(100));
    let cooldown = interval * COOLDOWN_INTERVALS;
    let starting = tunables.current();
    let mut cooldowns = Cooldowns::default();
    let mut previous: Option<(Statistics, Instant)> = None;
    let (mut syn_ema, mut verified_ema, mut udp_ema) = (0.0, 0.0, 0.0);
    let mut persisted: Option<PersistedState> = None;

    loop {
        if !shutdown.sleep(interval) {
            return;
        }
        let now = Instant::now();
        let total = match metrics::read(&stats) {
            Ok(total) => total,
            Err(error) => {
                warn!("Auto-tuner: {error:#}");
                continue;
            }
        };
        let deltas = match previous {
            Some((previous, previous_time)) => {
                deltas(&previous, &total, now.duration_since(previous_time).as_secs_f64())
            }
            None => Deltas::default(),
        };
        previous = Some((total, now));
        syn_ema = ema(syn_ema, deltas.syn_rate);
        verified_ema = ema(verified_ema, deltas.verified_rate);
        udp_ema = ema(udp_ema, deltas.udp_rate);

        let current = tunables.current();
        let mut next = current;
        let mut changes: Vec<String> = Vec::new();
        let attack = syn_ema > autotune.tighten_syn_per_sec;
        let quiet = syn_ema < autotune.relax_syn_per_sec;
        let step = |value: u32, numerator: u32| (value / numerator).max(1);

        // per-source: relax when legitimate traffic is being throttled at a
        // low SYN rate, tighten while the flood is on
        if managed.host && cooldowns.due(FIELD_HOST, now, cooldown) {
            let target = if quiet && deltas.throttle_drops > 0.0 {
                (next.host_limit + step(next.host_limit, 8))
                    .min(autotune.host_limit_max)
            } else if attack {
                next.host_limit
                    .saturating_sub(step(next.host_limit, 4))
                    .max(autotune.host_limit_min)
            } else {
                next.host_limit
            };
            if target != next.host_limit {
                changes.push(format!(
                    "host_limit {} -> {} (syn {:.1}/s, throttle drops {:.0}/s)",
                    next.host_limit, target, syn_ema, deltas.throttle_drops
                ));
                next.host_limit = target;
                cooldowns.touch(FIELD_HOST, now);
            }
        }

        // per-subnet: tighten towards the minimum under flood, drift back
        // towards the configured value in quiet periods
        if managed.subnet && cooldowns.due(FIELD_SUBNET, now, cooldown) {
            let target = if attack {
                next.subnet_limit
                    .saturating_sub(step(next.subnet_limit, 4))
                    .max(autotune.subnet_limit_min)
            } else if quiet && next.subnet_limit < config.filter.subnet_connection_limit {
                (next.subnet_limit + step(next.subnet_limit, 8))
                    .min(config.filter.subnet_connection_limit)
                    .min(autotune.subnet_limit_max)
            } else {
                next.subnet_limit
            };
            if target != next.subnet_limit {
                changes.push(format!(
                    "subnet_limit {} -> {} (syn {:.1}/s)",
                    next.subnet_limit, target, syn_ema
                ));
                next.subnet_limit = target;
                cooldowns.touch(FIELD_SUBNET, now);
            }
        }

        // host-wide admission: 4x the smoothed verified rate plus a burst
        // headroom, only when the operator configured a starting value
        if managed.global && cooldowns.due(FIELD_GLOBAL, now, cooldown) {
            let target = (verified_ema * 4.0 + 8.0).round() as u32;
            let target = target.clamp(autotune.global_limit_min, autotune.global_limit_max);
            if target != next.global_limit {
                changes.push(format!(
                    "global_limit {} -> {} (verified {:.1}/s)",
                    next.global_limit, target, verified_ema
                ));
                next.global_limit = target;
                cooldowns.touch(FIELD_GLOBAL, now);
            }
        }

        // udp (bedrock/voice ports): only managed when enabled; relax on
        // drops at a low SYN rate, tighten while handshakes look invalid
        let udp_managed = starting.udp_limit != 0;
        if udp_managed && cooldowns.due(FIELD_UDP, now, cooldown) {
            let target = if quiet && deltas.udp_drops > 0.0 {
                (next.udp_limit + step(next.udp_limit, 8)).min(next.udp_limit.max(2000))
            } else if deltas.bedrock_invalid > 0.0 && udp_ema > 200.0 {
                next.udp_limit
                    .saturating_sub(step(next.udp_limit, 4))
                    .max(16)
            } else {
                next.udp_limit
            };
            if target != next.udp_limit {
                changes.push(format!(
                    "udp_limit {} -> {} (udp {:.0}/s, invalid handshakes {:.0}/s)",
                    next.udp_limit, target, udp_ema, deltas.bedrock_invalid,
                ));
                next.udp_limit = target;
                cooldowns.touch(FIELD_UDP, now);
            }
        }

        // strike threshold: block sooner during a flood, forget sooner after
        if cooldowns.due(FIELD_STRIKES, now, cooldown) && next.strike_threshold != 0 {
            let target = if attack {
                next.strike_threshold
                    .saturating_sub(1)
                    .max(autotune.strike_threshold_min)
            } else if quiet && next.strike_threshold < autotune.strike_threshold_max {
                next.strike_threshold + 1
            } else {
                next.strike_threshold
            };
            if target != next.strike_threshold {
                changes.push(format!(
                    "strike_threshold {} -> {} (syn {:.1}/s)",
                    next.strike_threshold, target, syn_ema
                ));
                next.strike_threshold = target;
                cooldowns.touch(FIELD_STRIKES, now);
            }
        }

        if next == current {
            continue;
        }
        for change in &changes {
            if autotune.dry_run {
                info!("Auto-tuner would change: {change}");
            } else {
                info!("Auto-tuner: {change}");
            }
        }
        if autotune.dry_run {
            continue;
        }
        if let Err(error) = tunables.apply(next) {
            warn!("Auto-tuner: failed to apply the new limits: {error:#}");
            continue;
        }
        metrics::AUTOTUNE_CHANGES.inc_by(changes.len() as u64);
        if let Some(path) = &config.autotune.state_file {
            let state = PersistedState::from_tunables(&next);
            if persisted.as_ref() != Some(&state) {
                match save_state(&PathBuf::from(path), &state) {
                    Ok(()) => persisted = Some(state),
                    Err(error) => warn!("Auto-tuner: failed to persist state: {error:#}"),
                }
            }
        }
    }
}

/// Compares two reads of the statistics map and turns them into rates.
fn deltas(previous: &Statistics, current: &Statistics, seconds: f64) -> Deltas {
    if seconds <= 0.0 {
        return Deltas::default();
    }
    let rate = |previous: u64, current: u64| {
        (current.saturating_sub(previous) as f64) / seconds
    };
    Deltas {
        syn_rate: rate(previous.syn, current.syn),
        verified_rate: rate(previous.verified, current.verified),
        udp_rate: rate(previous.udp_packets, current.udp_packets),
        throttle_drops: rate(
            previous.reason_count(reason_index("throttle_limit")),
            current.reason_count(reason_index("throttle_limit")),
        ),
        udp_drops: rate(
            previous.reason_count(reason_index("udp_limit")),
            current.reason_count(reason_index("udp_limit")),
        ),
        bedrock_invalid: rate(
            previous.reason_count(reason_index("bedrock_invalid")),
            current.reason_count(reason_index("bedrock_invalid")),
        ),
    }
}

fn reason_index(name: &str) -> usize {
    metrics::drop_reason_index(name).expect("known drop reason")
}

fn ema(current: f64, sample: f64) -> f64 {
    current * (1.0 - EMA_ALPHA) + sample * EMA_ALPHA
}

fn load_state(path: &std::path::Path) -> Result<PersistedState> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;
    let state: PersistedState = toml::from_str(&contents)
        .with_context(|| format!("failed to parse '{}'", path.display()))?;
    Ok(state)
}

fn save_state(path: &std::path::Path, state: &PersistedState) -> Result<()> {
    let contents = format!(
        "# written by the xdp-loader auto-tuner; delete to start from the\n\
         # configured limits again\n\
         host_limit = {}\n\
         subnet_limit = {}\n\
         global_limit = {}\n\
         udp_limit = {}\n\
         rule_limit = {}\n\
         strike_threshold = {}\n",
        state.host_limit,
        state.subnet_limit,
        state.global_limit,
        state.udp_limit,
        state.rule_limit,
        state.strike_threshold,
    );
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, contents)
        .with_context(|| format!("failed to write '{}'", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("failed to move '{}' into place", temporary.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deltas_compute_rates() {
        let mut previous = Statistics::default();
        previous.syn = 100;
        previous.udp_packets = 50;
        previous.reason[reason_index("throttle_limit")] = 10;
        let mut current = previous;
        current.syn = 200;
        current.udp_packets = 60;
        current.reason[reason_index("throttle_limit")] = 30;

        let deltas = deltas(&previous, &current, 2.0);
        assert_eq!(deltas.syn_rate, 50.0);
        assert_eq!(deltas.udp_rate, 5.0);
        assert_eq!(deltas.throttle_drops, 10.0);
    }

    #[test]
    fn deltas_ignore_counter_resets() {
        let mut previous = Statistics::default();
        previous.syn = 1_000;
        let mut current = Statistics::default();
        current.syn = 5; // reader restarted / map reset
        let deltas = deltas(&previous, &current, 1.0);
        assert_eq!(deltas.syn_rate, 0.0);
    }

    #[test]
    fn persisted_state_respects_bounds() {
        let autotune = AutotuneConfig {
            enabled: true,
            host_limit_min: 2,
            host_limit_max: 100,
            subnet_limit_min: 10,
            subnet_limit_max: 200,
            global_limit_min: 4,
            global_limit_max: 1_000,
            strike_threshold_min: 1,
            strike_threshold_max: 6,
            ..AutotuneConfig::default()
        };
        let state = PersistedState {
            host_limit: 5_000,     // out of bounds: clamped
            subnet_limit: 0,       // unset: kept
            global_limit: 50,
            strike_threshold: 99,  // clamped
            ..PersistedState::default()
        };
        let mut tunables = Tunables {
            host_limit: 12,
            subnet_limit: 64,
            global_limit: 0,
            strike_threshold: 3,
            ..Tunables::default()
        };
        state.apply(&mut tunables, &autotune, Managed { host: true, subnet: true, global: true });
        assert_eq!(tunables.host_limit, 100);
        assert_eq!(tunables.subnet_limit, 64);
        assert_eq!(tunables.global_limit, 50);
        assert_eq!(tunables.strike_threshold, 6);

        // unmanaged fields keep the configured values even when the state
        // file has something else (0 = the operator disabled the limit)
        let mut tunables = Tunables {
            host_limit: 12,
            subnet_limit: 64,
            global_limit: 0,
            strike_threshold: 3,
            ..Tunables::default()
        };
        state.apply(&mut tunables, &autotune, Managed { host: false, subnet: false, global: false });
        assert_eq!(tunables.host_limit, 12);
        assert_eq!(tunables.subnet_limit, 64);
        assert_eq!(tunables.global_limit, 0);
        assert_eq!(tunables.strike_threshold, 6);
    }

    #[test]
    fn only_configured_limits_are_managed() {
        let mut config = Config::default();
        assert!(Managed::from_config(&config).host);
        assert!(Managed::from_config(&config).subnet);
        assert!(!Managed::from_config(&config).global); // off by default
        config.filter.host_connection_limit = 0;
        config.filter.subnet_connection_limit = 0;
        config.filter.global_connection_limit = 100;
        let managed = Managed::from_config(&config);
        assert!(!managed.host);
        assert!(!managed.subnet);
        assert!(managed.global);
    }

    #[test]
    fn cooldowns_gate_changes() {
        let mut cooldowns = Cooldowns::default();
        let now = Instant::now();
        let cooldown = Duration::from_secs(5);
        assert!(cooldowns.due(FIELD_HOST, now, cooldown));
        cooldowns.touch(FIELD_HOST, now);
        assert!(!cooldowns.due(FIELD_HOST, now, cooldown));
        assert!(cooldowns.due(FIELD_HOST, now + cooldown, cooldown));
        assert!(cooldowns.due(FIELD_SUBNET, now, cooldown));
    }

    #[test]
    fn ema_moves_towards_the_sample() {
        let mut value = 0.0;
        for _ in 0..20 {
            value = ema(value, 10.0);
        }
        assert!(value > 9.0, "{value}");
    }
}
