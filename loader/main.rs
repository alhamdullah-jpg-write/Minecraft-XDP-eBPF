mod advisor;
mod allowlist;
mod autotune;
mod blocklist;
mod cidr;
mod config;
mod ebpf;
mod logging;
mod metrics;
mod ml;
mod rules;
mod shutdown;
mod state;
mod tunables;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{error, info};

use config::Config;
use shutdown::Shutdown;

const USAGE: &str = "\
Usage: xdp-loader [OPTIONS] <INTERFACE>

Arguments:
  <INTERFACE>  Network interface to attach to

Options:
  -c, --config <FILE>  Path to the TOML configuration file, created with
                       defaults if missing [default: config.toml]
      --license        Print license information
  -h, --help           Print help
  -V, --version        Print version";

#[derive(Debug)]
struct Args {
    /// Network interface to attach to, required unless --license is given.
    interface: Option<String>,
    /// Path to the TOML configuration file.
    config: String,
    /// Print license information instead of running.
    license: bool,
}

/// Hand-rolled argument parsing (a CLI library would double the binary size
/// for three options). Prints help/version/errors and exits where appropriate.
fn parse_args() -> Args {
    let mut args = Args {
        interface: None,
        config: "config.toml".into(),
        license: false,
    };

    let mut argv = std::env::args().skip(1);
    let invalid = |message: String| -> ! {
        eprintln!("error: {message}\n\n{USAGE}");
        std::process::exit(2);
    };
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("xdp-loader {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--license" => args.license = true,
            "-c" | "--config" => match argv.next() {
                Some(value) => args.config = value,
                None => invalid(format!("missing value for '{arg} <FILE>'")),
            },
            _ => match arg.strip_prefix("--config=") {
                Some(value) => args.config = value.into(),
                None if arg.starts_with('-') => invalid(format!("unexpected option '{arg}'")),
                None if args.interface.is_none() => args.interface = Some(arg),
                None => invalid(format!("unexpected argument '{arg}'")),
            },
        }
    }

    if args.interface.is_none() && !args.license {
        invalid("missing required argument <INTERFACE>".into());
    }
    args
}

fn main() {
    let args = parse_args();

    if args.license {
        println!(include_str!("../LICENSE"));
        return;
    }

    // the log level lives in the config, so it must be loaded before logging
    // is up; until then errors can only go to stderr directly
    let config = match Config::load(Path::new(&args.config)) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("failed to load config '{}': {e:#}", args.config);
            std::process::exit(1);
        }
    };

    logging::init(&config.logging).expect("Failed to setup logger");
    info!(
        "Loading minecraft xdp filter v{} by Outfluencer...",
        env!("CARGO_PKG_VERSION")
    );
    info!("Loaded configuration: {config:?}");

    let shutdown = Arc::new(Shutdown::new());
    shutdown::trigger_on_termination_signal(shutdown.clone());

    let result = run(&args, &config, &shutdown);
    if let Err(e) = &result {
        error!("{e:#}");
    }

    shutdown.trigger();
    info!("Good bye!");

    // a failed run must be visible to service managers (systemd
    // Restart=on-failure) and scripts, not only in the log
    if result.is_err() {
        std::process::exit(1);
    }
}

/// Attaches the XDP filter and its companion programs, starts every userspace
/// worker and keeps the filter alive until shutdown is triggered. Dropping
/// the `Ebpf` handle on return detaches everything again.
fn run(args: &Args, config: &Config, shutdown: &Arc<Shutdown>) -> Result<()> {
    let interface = args
        .interface
        .as_deref()
        .context("interface is required unless --license is specified")?;

    // Parse the lists before attaching anything: a misconfigured file must
    // stop the loader, not leave a half-configured filter running.
    let allowlist = match &config.xdp.allowlist_file {
        Some(path) => Some(allowlist::Allowlist::load(Path::new(path))?),
        None => None,
    };
    let blocklist = match &config.blocklist.blocklist_file {
        Some(path) => Some(blocklist::Blocklist::load(Path::new(path))?),
        None => None,
    };

    // keep the handle alive until the end of this function: dropping it
    // detaches the XDP and tc programs
    let attached = ebpf::load_and_attach(interface, config)
        .with_context(|| format!("failed to attach to interface '{interface}'"))?;
    let ebpf::Attached {
        ebpf: mut program,
        tunables,
        mode,
    } = attached;
    advisor::startup(interface, mode, config);

    log_features(config, tunables.current());
    let stats = metrics::take_stats(&mut program)?;
    let allowlist_thread = allowlist::start(&mut program, config, allowlist, shutdown)?;
    rules::start(&mut program, config)?;
    let blocklist_runtime = blocklist::start(&mut program, config, blocklist, shutdown)?;
    let autoblocks = blocklist_runtime
        .as_ref()
        .and_then(|runtime| runtime.autoblocks.clone());
    let stats_thread = metrics::start(stats.clone(), config, shutdown)?;
    let autotune_thread = match stats.clone() {
        Some(stats) => autotune::start(tunables, stats, config, shutdown)?,
        None => None,
    };
    let ml_thread = ml::start(&mut program, config, autoblocks, shutdown)?;
    let advisor_thread = advisor::start(stats, config, shutdown)?;

    shutdown.wait();

    for (thread, handle) in [
        ("allowlist", allowlist_thread),
        (
            "blocklist",
            blocklist_runtime.and_then(|runtime| runtime.handle),
        ),
        ("track-stats", stats_thread),
        ("autotune", autotune_thread),
        ("ml-score", ml_thread),
        ("advisor", advisor_thread),
    ] {
        if let Some(handle) = handle {
            handle
                .join()
                .map_err(|e| anyhow::anyhow!("{thread} thread panicked: {e:?}"))?;
        }
    }
    Ok(())
}

/// One line that says exactly which features are live; a surprising drop
/// report is much easier to read with it in the log.
fn log_features(config: &Config, tunables: tunables::Tunables) {
    use config::MlMode;
    info!(
        "Features: host/subnet/global limits={}/{}/{}, udp limit={}, window={}ms, \
         blocklist={}, autoblock={} (strikes={}), egress tracking={}, default-deny={}, \
         rules={}, bedrock={}, voice={}, icmp={}, talkers={}, ml={:?}, autotune={}, advisor={}",
        tunables.host_limit,
        tunables.subnet_limit,
        tunables.global_limit,
        tunables.udp_limit,
        tunables.window_ms,
        config.blocklist.blocklist_file.is_some(),
        config.blocklist.autoblock,
        tunables.strike_threshold,
        config.ingress.egress_tracking,
        config.ingress.default_deny,
        config.rules.len() + config.ingress.open_tcp_ports.len() + config.ingress.open_udp_ports.len(),
        config.bedrock.enabled,
        config.voice.enabled,
        config.ingress.icmp,
        config.ml.enabled || config.metrics.enabled || config.advisor.enabled,
        if config.ml.enabled { config.ml.mode } else { MlMode::Off },
        config.autotune.enabled,
        config.advisor.enabled,
    );
}
