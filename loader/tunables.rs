//! Runtime-tunable limits (`tunables_map` in xdp/maps.h).
//!
//! Unlike the load-time `.rodata` globals these live in an ARRAY map so the
//! auto-tuner (and, if needed, an operator) can change them while the filter
//! runs. The packet path reads the whole struct once per packet; map
//! writes are a single 40 byte copy, so a torn read is impossible.
//!
//! This module owns the initial write: it happens inside
//! `ebpf::load_and_attach` right after the object is loaded and *before*
//! the program is attached, so the filter never runs with the all-zero
//! placeholder limits.

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::{Array, MapData};
use aya::Pod;

use crate::config::Config;
use crate::metrics;

/// Userspace mirror of `struct tunables` (xdp/maps.h): ten `u32` limits,
/// order and names must match the C struct.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Tunables {
    /// Per-source new connections (SYNs) per window; 0 disables.
    pub host_limit: u32,
    /// Per-/24 (v4) or /64 (v6) new connections per window; 0 disables.
    pub subnet_limit: u32,
    /// Host-wide new connections per window; 0 disables.
    pub global_limit: u32,
    /// Per-source UDP packets on the bedrock/voice ports per window; 0 disables.
    pub udp_limit: u32,
    /// Fallback per-source packet limit for rate rules without `max_rate`.
    pub rule_limit: u32,
    /// Sliding window length in milliseconds (1..=4000, see rate.h).
    pub window_ms: u32,
    /// Violations before the kernel auto-blocks a source; 0 disables.
    pub strike_threshold: u32,
    /// First auto-block duration in seconds.
    pub block_base_ttl_s: u32,
    /// Auto-block duration ceiling in seconds.
    pub block_max_ttl_s: u32,
    /// Idle time after which strike history is forgotten, in seconds.
    pub strike_decay_s: u32,
}

// SAFETY: repr(C) struct of plain u32 fields without padding, valid for any
// bit pattern.
unsafe impl Pod for Tunables {}

// compile-time layout check, mirrors the _Static_assert in xdp/maps.h
const _: () = assert!(std::mem::size_of::<Tunables>() == 40);

impl Tunables {
    /// The configured starting limits. The auto-tuner moves them from here.
    pub fn from_config(config: &Config) -> Tunables {
        Tunables {
            host_limit: config.filter.host_connection_limit,
            subnet_limit: config.filter.subnet_connection_limit,
            global_limit: config.filter.global_connection_limit,
            udp_limit: config.filter.udp_packet_limit,
            rule_limit: config.filter.rule_packet_limit,
            window_ms: config.filter.window_ms,
            // 0 disables the in-kernel auto-blocker even when
            // AUTOBLOCK_ENABLED is set; both have to agree by construction
            strike_threshold: if config.blocklist.autoblock {
                config.blocklist.autoblock_strikes
            } else {
                0
            },
            block_base_ttl_s: config.blocklist.autoblock_base_ttl_secs,
            block_max_ttl_s: config.blocklist.autoblock_max_ttl_secs,
            strike_decay_s: config.blocklist.autoblock_decay_secs,
        }
    }

    /// True when any per-window limit is nonzero (any of them needs the
    /// rate-limit code paths).
    pub fn any_limit_enabled(&self) -> bool {
        self.host_limit != 0
            || self.subnet_limit != 0
            || self.global_limit != 0
            || self.udp_limit != 0
            || self.rule_limit != 0
    }

    /// Clamps the fields the eBPF side cannot work with outside a range.
    /// Returns an error instead of silently accepting an unusable value.
    pub fn validate(&self) -> Result<()> {
        if self.window_ms == 0 || self.window_ms > 4000 {
            anyhow::bail!(
                "window_ms must be between 1 and 4000 (got {}), see rate.h",
                self.window_ms
            );
        }
        Ok(())
    }
}

/// Owns the `tunables_map` slot and mirrors the values last written.
pub struct TunablesHandle {
    map: Array<MapData, Tunables>,
    current: Tunables,
}

impl TunablesHandle {
    /// Takes the map out of `ebpf`, writes the configured limits and
    /// publishes them as gauges. Called before the XDP program is attached.
    pub fn init(ebpf: &mut Ebpf, config: &Config) -> Result<TunablesHandle> {
        let tunables = Tunables::from_config(config);
        tunables.validate()?;

        let map = ebpf
            .take_map("tunables_map")
            .context("can't take map 'tunables_map'")?;
        let mut map: Array<MapData, Tunables> = Array::try_from(map)?;
        map.set(0, &tunables, 0)
            .context("failed to write the initial tunables")?;

        let handle = TunablesHandle {
            map,
            current: tunables,
        };
        handle.publish();
        Ok(handle)
    }

    /// The values the kernel is currently using.
    pub fn current(&self) -> Tunables {
        self.current
    }

    /// Writes new limits (sandboxed by [`Tunables::validate`]) and refreshes
    /// the gauges. A failed write leaves `current` untouched.
    pub fn apply(&mut self, tunables: Tunables) -> Result<()> {
        tunables.validate()?;
        self.map
            .set(0, &tunables, 0)
            .context("failed to write the tunables map")?;
        self.current = tunables;
        self.publish();
        Ok(())
    }

    fn publish(&self) {
        let t = &self.current;
        metrics::LIMIT_HOST.set(t.host_limit as i64);
        metrics::LIMIT_SUBNET.set(t.subnet_limit as i64);
        metrics::LIMIT_GLOBAL.set(t.global_limit as i64);
        metrics::LIMIT_UDP.set(t.udp_limit as i64);
        metrics::LIMIT_RULE.set(t.rule_limit as i64);
        metrics::LIMIT_STRIKE_THRESHOLD.set(t.strike_threshold as i64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_maps_every_field() {
        let mut config = Config::default();
        config.filter.host_connection_limit = 7;
        config.filter.subnet_connection_limit = 70;
        config.filter.global_connection_limit = 700;
        config.filter.udp_packet_limit = 100;
        config.filter.rule_packet_limit = 200;
        config.filter.window_ms = 250;
        config.blocklist.autoblock = true;
        config.blocklist.autoblock_strikes = 4;
        config.blocklist.autoblock_base_ttl_secs = 30;
        config.blocklist.autoblock_max_ttl_secs = 600;
        config.blocklist.autoblock_decay_secs = 120;

        let tunables = Tunables::from_config(&config);
        assert_eq!(tunables.host_limit, 7);
        assert_eq!(tunables.subnet_limit, 70);
        assert_eq!(tunables.global_limit, 700);
        assert_eq!(tunables.udp_limit, 100);
        assert_eq!(tunables.rule_limit, 200);
        assert_eq!(tunables.window_ms, 250);
        assert_eq!(tunables.strike_threshold, 4);
        assert_eq!(tunables.block_base_ttl_s, 30);
        assert_eq!(tunables.block_max_ttl_s, 600);
        assert_eq!(tunables.strike_decay_s, 120);
    }

    #[test]
    fn autoblock_off_zeroes_the_threshold() {
        let config = Config::default();
        assert!(!config.blocklist.autoblock);
        assert_eq!(Tunables::from_config(&config).strike_threshold, 0);
    }

    #[test]
    fn validate_rejects_unusable_windows() {
        let mut tunables = Tunables {
            window_ms: 1,
            ..Tunables::default()
        };
        tunables.validate().unwrap();
        tunables.window_ms = 4000;
        tunables.validate().unwrap();
        for bad in [0u32, 4001, u32::MAX] {
            tunables.window_ms = bad;
            assert!(tunables.validate().is_err(), "window_ms = {bad}");
        }
    }

    #[test]
    fn any_limit_enabled_tracks_every_limit() {
        assert!(!Tunables::default().any_limit_enabled());
        for set in [
            |t: &mut Tunables| t.host_limit = 1,
            |t: &mut Tunables| t.subnet_limit = 1,
            |t: &mut Tunables| t.global_limit = 1,
            |t: &mut Tunables| t.udp_limit = 1,
            |t: &mut Tunables| t.rule_limit = 1,
        ] {
            let mut tunables = Tunables::default();
            set(&mut tunables);
            assert!(tunables.any_limit_enabled());
        }
    }
}
