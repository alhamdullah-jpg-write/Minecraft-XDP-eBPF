//! ML risk scoring for source addresses.
//!
//! The kernel samples one in sixteen packets into `talkers_map` (see
//! xdp/talkers.h); this module turns those counters into per-source features,
//! scores them with a logistic-regression model and - in `mode = "enforce"` -
//! blocks the sources above the threshold through the same auto-block table
//! the kernel uses.
//!
//! The model trains online from labels the filter already produces:
//!
//!  - benign: the source passed a full minecraft connection
//!    (`verified_sources`, maintained by the kernel).
//!  - malicious: the kernel (or a previous ML pass) auto-blocked the source.
//!
//! Unlabeled sources are scored but never train the model, which keeps the
//! learning signal free of the "just new" traffic every server sees. The
//! model starts from sane hand weights, is persisted atomically and always
//! runs in `shadow` mode first: `enforce` is an explicit operator decision,
//! and even then blocks are bounded by `max_block_ttl_secs`.
//!
//! Honest scope: five sampled counters cannot separate every attacker from
//! every player. This is a cheap, explainable second opinion on top of the
//! deterministic limits - not a replacement for them, and not a reason to
//! turn the limits off.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;
use log::{info, warn};
use serde::{Deserialize, Serialize};

use crate::blocklist::{self, AutoblockStore};
use crate::config::{Config, MlMode};
use crate::metrics;
use crate::shutdown::Shutdown;
use crate::state::{HostKey, TalkerEntry, VerifiedEntry, now_ns};

/// Talker counter map (LRU, sampled).
type TalkerMap = AyaHashMap<MapData, HostKey, TalkerEntry>;
/// Verified source table used as the benign label.
type VerifiedMap = AyaHashMap<MapData, HostKey, VerifiedEntry>;

/// Bias plus one weight per feature (see [`features`]).
const FEATURES: usize = 6;
/// Hand-tuned starting weights: a high-rate source whose packets are mostly
/// dropped and which is not a verified player already scores above the
/// default threshold, so enforcement works before any training happened.
const INITIAL_WEIGHTS: [f64; FEATURES] = [-3.0, 3.0, 0.5, 2.0, 1.5, 0.5];
/// SGD learning rate and weight decay (keeps drifting weights bounded).
const LEARNING_RATE: f64 = 0.02;
const WEIGHT_DECAY: f64 = 0.999;
/// A source must have been active this recently to be scored/blocked.
const ACTIVE_WINDOW_NS: u64 = 60 * 1_000_000_000;

/// The persisted model (`model_file`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ModelFile {
    /// Bias first, then one weight per feature.
    weights: Vec<f64>,
    /// Number of labeled training samples applied so far.
    samples: u64,
}

impl Default for ModelFile {
    fn default() -> Self {
        ModelFile {
            weights: INITIAL_WEIGHTS.to_vec(),
            samples: 0,
        }
    }
}

impl ModelFile {
    /// Validates the shape and falls back to the hand weights when the file
    /// was written by a different feature layout.
    fn validated(mut self) -> ModelFile {
        if self.weights.len() != FEATURES
            || self.weights.iter().any(|weight| !weight.is_finite())
        {
            warn!(
                "ML: model file has {} weights (need {FEATURES}), starting from the default model",
                self.weights.len()
            );
            return ModelFile::default();
        }
        for weight in &mut self.weights {
            *weight = weight.clamp(-20.0, 20.0);
        }
        self
    }

    fn predict(&self, features: &[f64; FEATURES]) -> f64 {
        let mut sum = 0.0;
        for (weight, feature) in self.weights.iter().zip(features) {
            sum += weight * feature;
        }
        sigmoid(sum)
    }

    /// One SGD step. `label` is 0.0 (benign) or 1.0 (malicious).
    fn train(&mut self, features: &[f64; FEATURES], label: f64) {
        let prediction = self.predict(features);
        let error = label - prediction;
        for (weight, feature) in self.weights.iter_mut().zip(features) {
            *weight = (*weight * WEIGHT_DECAY + LEARNING_RATE * error * feature).clamp(-20.0, 20.0);
        }
        self.samples += 1;
    }
}

fn sigmoid(value: f64) -> f64 {
    // numerically stable logistic function
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}

/// The feature vector: bias, log packet rate, average packet size, drop
/// ratio, SYN ratio and an "is currently active" flag. Fixed scales keep the
/// weights interpretable and the model file comparable across restarts.
fn features(entry: &TalkerEntry, now_ns: u64) -> [f64; FEATURES] {
    let packets = entry.packets.max(1) as f64;
    let span_s = ((entry.last_seen_ns.saturating_sub(entry.first_seen_ns)) as f64 / 1e9).max(0.5);
    let pps = packets / span_s;
    let bytes_per_packet = (entry.bytes as f64 / packets / 1500.0).min(4.0);
    let drop_ratio = (entry.drops as f64 / packets).min(1.0);
    let syn_ratio = (entry.syns as f64 / packets).min(1.0);
    let active = u8::from(now_ns.saturating_sub(entry.last_seen_ns) < ACTIVE_WINDOW_NS) as f64;
    [
        1.0,
        (1.0 + pps).ln() / 8.0,
        bytes_per_packet,
        drop_ratio,
        syn_ratio * 4.0,
        active,
    ]
}

/// A scored source, for the logs and the enforcement pass.
struct Scored {
    key: HostKey,
    entry: TalkerEntry,
    score: f64,
    pps: f64,
    verified: bool,
    blocked: bool,
}

/// Starts the scoring thread when `[ml] enabled = true` (and mode != off).
/// The talker and verified-source maps are taken from `ebpf`; the auto-block
/// store must be the one `blocklist::start` returned.
pub fn start(
    ebpf: &mut Ebpf,
    config: &Config,
    autoblocks: Option<AutoblockStore>,
    shutdown: &Arc<Shutdown>,
) -> Result<Option<JoinHandle<()>>> {
    if !config.ml.enabled || config.ml.mode == MlMode::Off {
        return Ok(None);
    }
    let Some(autoblocks) = autoblocks else {
        bail!("[ml] enabled but the auto-block store is missing (internal wiring error)");
    };

    let talkers = ebpf
        .take_map("talkers_map")
        .context("can't take map 'talkers_map'")?;
    let talkers: TalkerMap = AyaHashMap::try_from(talkers)?;
    let verified = ebpf
        .take_map("verified_sources")
        .context("can't take map 'verified_sources'")?;
    let verified: VerifiedMap = AyaHashMap::try_from(verified)?;

    let mut model = match &config.ml.model_file {
        Some(file) => {
            let path = PathBuf::from(file);
            if path.exists() {
                match std::fs::read_to_string(&path)
                    .map_err(anyhow::Error::from)
                    .and_then(|contents| toml::from_str::<ModelFile>(&contents).map_err(Into::into))
                {
                    Ok(model) => {
                        info!(
                            "ML: loaded model from '{}' ({} training samples)",
                            path.display(),
                            model.samples
                        );
                        model.validated()
                    }
                    Err(error) => {
                        warn!(
                            "ML: ignoring unreadable model '{}': {error:#}",
                            path.display()
                        );
                        ModelFile::default()
                    }
                }
            } else {
                ModelFile::default()
            }
        }
        None => ModelFile::default(),
    };

    let config = config.clone();
    let shutdown = shutdown.clone();
    let handle = thread::Builder::new()
        .name("ml-score".into())
        .spawn(move || {
            run(&mut model, &talkers, &verified, &autoblocks, &config, &shutdown);
        })?;
    Ok(Some(handle))
}

fn run(
    model: &mut ModelFile,
    talkers: &TalkerMap,
    verified: &VerifiedMap,
    autoblocks: &AutoblockStore,
    config: &Config,
    shutdown: &Arc<Shutdown>,
) {
    let ml = &config.ml;
    let interval = Duration::from_secs(ml.interval_secs.max(1));
    let mut last_save: Option<ModelFile> = None;

    loop {
        if !shutdown.sleep(interval) {
            return;
        }
        let now = now_ns();
        let verified_keys = verified_set(verified);
        let mut scored: Vec<Scored> = Vec::new();

        for pair in talkers.iter() {
            let Ok((key, entry)) = pair else {
                continue;
            };
            // stale entries only inflate the map during shutdowns
            if now.saturating_sub(entry.last_seen_ns) > ACTIVE_WINDOW_NS {
                continue;
            }
            let features = features(&entry, now);
            let score = model.predict(&features);
            let pps = entry.packets.max(1) as f64
                / ((entry.last_seen_ns.saturating_sub(entry.first_seen_ns)) as f64 / 1e9).max(0.5);
            let is_verified = verified_keys.contains(&key);
            let is_blocked = blocklist::is_blocked(autoblocks, &key);
            let malicious = is_blocked;

            if ml.train {
                if malicious {
                    model.train(&features, 1.0);
                } else if is_verified {
                    model.train(&features, 0.0);
                }
            }

            scored.push(Scored {
                key,
                entry: entry.clone(),
                score,
                pps,
                verified: is_verified,
                blocked: is_blocked,
            });
        }

        let top = scored
            .iter()
            .map(|sample| sample.score)
            .fold(0.0f64, f64::max);
        metrics::ML_TOP_SCORE.set((top * 1000.0) as i64);

        scored.sort_by(|a, b| b.score.total_cmp(&a.score));
        let candidates: Vec<&Scored> = scored
            .iter()
            .filter(|sample| {
                sample.score >= ml.threshold
                    && sample.pps >= ml.min_packet_rate
                    && !sample.verified
            })
            .collect();

        if ml.mode == MlMode::Shadow {
            for sample in candidates.iter().take(3) {
                let verdict = if sample.blocked {
                    "already blocked"
                } else {
                    "would block (shadow)"
                };
                info!(
                    "ML: {} score={:.3} pps={:.0} drops={} syns={} bytes={} -> {}",
                    sample.key.to_ip(),
                    sample.score,
                    sample.pps,
                    sample.entry.drops,
                    sample.entry.syns,
                    sample.entry.bytes,
                    verdict,
                );
            }
        } else {
            for sample in candidates {
                if sample.blocked {
                    continue;
                }
                let ttl_ns = ml.max_block_ttl_secs as u64 * 1_000_000_000;
                match blocklist::block_source(autoblocks, &sample.key, ttl_ns, crate::state::REASON_AUTOBLOCK)
                {
                    Ok(entry) => {
                        metrics::ML_BLOCKS.inc();
                        info!(
                            "ML: blocked {} for {}s (score={:.3} pps={:.0} drops={} syns={} strikes={})",
                            sample.key.to_ip(),
                            ml.max_block_ttl_secs,
                            sample.score,
                            sample.pps,
                            sample.entry.drops,
                            sample.entry.syns,
                            entry.strikes,
                        );
                    }
                    Err(error) => {
                        warn!("ML: failed to block {}: {error:#}", sample.key.to_ip());
                    }
                }
            }
        }

        if let Some(file) = &ml.model_file {
            if last_save.as_ref() != Some(model) {
                let path = PathBuf::from(file);
                match save_model(&path, model) {
                    Ok(()) => last_save = Some(model.clone()),
                    Err(error) => warn!("ML: failed to save the model: {error:#}"),
                }
            }
        }
    }
}

/// Snapshot of the verified (benign-labeled) sources.
fn verified_set(verified: &VerifiedMap) -> std::collections::HashSet<HostKey> {
    verified.keys().filter_map(|key| key.ok()).collect()
}

fn save_model(path: &std::path::Path, model: &ModelFile) -> Result<()> {
    let mut weights = String::new();
    for weight in &model.weights {
        weights.push_str(&format!("{weight:.6}, "));
    }
    let contents = format!(
        "# written by the xdp-loader ml scorer; delete to start from the\n\
         # default model again\n\
         samples = {}\n\
         weights = [{}]\n",
        model.samples, weights
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

    fn entry(packets: u64, bytes: u64, drops: u32, syns: u32, span_s: u64, age_s: u64) -> TalkerEntry {
        TalkerEntry {
            packets,
            bytes,
            first_seen_ns: NOW - span_s * 1_000_000_000,
            last_seen_ns: NOW - age_s * 1_000_000_000,
            drops,
            syns,
        }
    }

    /// Shared "now" for every ML test: far enough from the epoch that the
    /// span arithmetic stays positive.
    const NOW: u64 = 1_000_000_000_000_000;

    #[test]
    fn features_are_bounded_and_finite() {
        for test in [
            entry(1, 64, 0, 0, 0, 0),
            entry(1_000_000, 1_500_000_000, 900_000, 500_000, 60, 0),
            entry(2, 3, 1, 1, 100_000, 0),
        ] {
            let features = features(&test, NOW);
            assert!(features.iter().all(|value| value.is_finite()), "{features:?}");
            assert!(features[1] >= 0.0 && features[3] <= 1.0 && features[4] <= 4.0);
        }
    }

    #[test]
    fn flood_source_scores_higher_than_a_player() {
        let model = ModelFile::default();
        let player = features(&entry(600, 300_000, 0, 0, 60, 0), NOW);
        let flood = features(&entry(60_000, 3_000_000, 55_000, 40_000, 60, 0), NOW);
        let player_score = model.predict(&player);
        let flood_score = model.predict(&flood);
        assert!(player_score < 0.5, "player scored {player_score}");
        assert!(flood_score > 0.9, "flood scored {flood_score}");
    }

    #[test]
    fn training_pushes_labels_to_their_end() {
        let mut model = ModelFile::default();
        let good = features(&entry(600, 300_000, 0, 0, 60, 0), NOW);
        let bad = features(&entry(60_000, 3_000_000, 55_000, 40_000, 60, 0), NOW);
        for _ in 0..50 {
            model.train(&bad, 1.0);
            model.train(&good, 0.0);
        }
        assert!(model.predict(&bad) > 0.9);
        assert!(model.predict(&good) < 0.2);
        assert_eq!(model.samples, 100);
    }

    #[test]
    fn model_file_shape_is_validated() {
        assert_eq!(
            ModelFile {
                weights: vec![1.0, 2.0],
                samples: 5
            }
            .validated(),
            ModelFile::default()
        );
        let mut weights = INITIAL_WEIGHTS.to_vec();
        weights[0] = -100.0;
        let model = ModelFile { weights, samples: 0 }.validated();
        assert_eq!(model.weights[0], -20.0);
    }
}
