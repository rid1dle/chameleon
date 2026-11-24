use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use cfprobe::{CFProbe, Config, Target, cloudflare, fingerprint, reporting};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cfprobe", version, about = "Measure HTTP/TLS client characteristics and Cloudflare responses on a zone you own")]
struct Cli {
    /// JSON config file (see Config); flags below override it.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Connect to ADDR for HOST:PORT, like curl --resolve. Format HOST:PORT:ADDR
    #[arg(long, global = true)]
    resolve: Vec<String>,
    /// Extra trust anchor (PEM).
    #[arg(long, global = true)]
    ca_file: Option<PathBuf>,
    /// Route every connection through this proxy: http://, https://, socks5:// or socks5h://
    /// (credentials in the URL are never printed). Without it, CFPROBE_PROXY is used if set;
    /// with neither, connections are direct and the run says so.
    #[arg(long, global = true)]
    proxy: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make one or more requests and print each exchange as JSON.
    Inspect {
        url: String,
        /// Extra request header, "name: value". Repeatable, sent in the order given.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Requests to send in sequence (reusing the connection unless the config disables it).
        #[arg(long, default_value_t = 1)]
        repeat: u32,
        /// Also print the response body (UTF-8, lossy). Off by default: bodies can carry tokens.
        /// JSON only.
        #[arg(long)]
        show_body: bool,
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
    },
    /// Request a receiver URL (lab TrackMe `/api/all` or the zone Worker `/echo`), print what the
    /// receiver measured, and compare it with each saved baseline record in --baselines.
    Fingerprint {
        url: String,
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Directory of saved receiver records, e.g. experiments/test-results/L1
        #[arg(long)]
        baselines: Option<PathBuf>,
    },
    /// Run a test matrix (see `runner`): each case by each client, results saved under --out.
    Run {
        matrix: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Run only the case with this id.
        #[arg(long)]
        only: Option<String>,
        /// Save response bodies in the raw records. Off by default: bodies can carry tokens.
        #[arg(long)]
        save_bodies: bool,
        /// Seed for order, pauses and retry jitter (overrides the matrix's). Omit for a new one.
        #[arg(long)]
        seed: Option<u64>,
    },
    /// Seeded random scenarios against a loopback mock server (no network): faults, encodings,
    /// cookies, redirects, Cloudflare pages and decoys. Exits non-zero when a scenario fails.
    Fuzz {
        /// Omit for a fresh seed (printed and recorded).
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long, default_value_t = 200)]
        count: u64,
        /// Rerun one scenario of the seed.
        #[arg(long)]
        only: Option<u64>,
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
        /// Write results.json and results.md here.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check the configured route before a campaign: open a connection to URL through the proxy
    /// (or directly when none is defined), make one GET, and report the route, timings, status and
    /// the client address the destination saw (from Cloudflare's `/cdn-cgi/trace` `ip=` line or the
    /// zone Worker's `cf-connecting-ip`). Exits non-zero on any failure, or when --expect-egress-ip
    /// is given and does not match.
    ProxyCheck {
        url: String,
        #[arg(long)]
        expect_egress_ip: Option<String>,
    },
    /// Compare two saved receiver records field by field.
    Diff {
        left: PathBuf,
        right: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Json)]
        format: Format,
    },
    /// Summarize every saved receiver record in a directory (the L1 table).
    Baselines {
        dir: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Markdown)]
        format: Format,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Json,
    #[value(name = "md")]
    Markdown,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = match &cli.config {
        Some(p) => Config::from_json(&std::fs::read_to_string(p)?)?,
        None => Config::default(),
    };
    for r in &cli.resolve {
        let (hostport, addr) = parse_resolve(r).ok_or_else(|| format!("--resolve {r:?}: want HOST:PORT:ADDR, IPv6 in brackets"))?;
        config.resolve.insert(hostport.to_string(), addr);
    }
    // A proxy from --proxy, else CFPROBE_PROXY, unless the config file already lists proxies.
    if config.proxy.proxies.is_empty() {
        let spec = match (&cli.proxy, std::env::var("CFPROBE_PROXY").ok().filter(|v| !v.trim().is_empty())) {
            (Some(url), _) => Some(("cli", url.clone())),
            (None, Some(_)) => Some(("env:CFPROBE_PROXY", "env:CFPROBE_PROXY".to_string())),
            (None, None) => None,
        };
        if let Some((id, url)) = spec {
            config.proxy.proxies.push(cfprobe::proxy::ProxySpec { id: id.into(), url, username: None, password: None, ca_file: None });
        }
    } else if cli.proxy.is_some() {
        return Err("--proxy given but the config file already lists proxies: use its `select`".into());
    }
    if needs_network(&cli.cmd) {
        // Announce the route before any connection: proxied, or direct because none is defined.
        eprintln!("cfprobe: {}", config.proxy.route()?.describe());
    }
    if let Some(ca) = cli.ca_file {
        config.tls.ca_file = Some(ca);
    }

    match cli.cmd {
        Cmd::Inspect { url, headers, repeat, show_body, format } => {
            if show_body && matches!(format, Format::Markdown) {
                return Err("--show-body works with --format json only".into());
            }
            let engine = CFProbe::new(config)?;
            let target = target(&url, &headers)?;
            for _ in 0..repeat {
                let ex = engine.inspect(target.clone()).await?;
                let analysis = cloudflare::analyze_exchange(&ex);
                match format {
                    Format::Json => {
                        let mut out = serde_json::to_value(&ex)?;
                        out["cloudflare"] = serde_json::to_value(&analysis)?;
                        if show_body {
                            out["response"]["body"] = String::from_utf8_lossy(&ex.response.body).into_owned().into();
                        }
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    }
                    Format::Markdown => println!("{}", reporting::inspect_report(&ex, &analysis)),
                }
            }
        }
        Cmd::Fingerprint { url, headers, baselines } => {
            let engine = CFProbe::new(config)?;
            let ex = engine.inspect(target(&url, &headers)?).await?;
            let seen = fingerprint::observe_exchange(&ex)?;
            let (comparisons, skipped) = match &baselines {
                Some(dir) => {
                    let (found, skipped) = fingerprint::load_baselines(dir)?;
                    let c: Vec<_> = found
                        .iter()
                        .map(|b| fingerprint::compare("this run", &seen.observation.fingerprint, &b.name, &b.observation.fingerprint))
                        .collect();
                    (c, skipped)
                }
                None => (Vec::new(), Vec::new()),
            };
            let out = serde_json::json!({
                "request": { "url": ex.request.url, "status": ex.response.status, "connection": ex.connection },
                "cloudflare": cloudflare::analyze_exchange(&ex),
                "client_tls": ex.tls,
                "receiver": seen,
                "comparisons": comparisons,
                "skipped_baseline_files": skipped,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Cmd::Run { matrix, out, only, save_bodies, seed } => {
            let m: cfprobe::runner::Matrix = serde_json::from_slice(&std::fs::read(&matrix)?)
                .map_err(|e| format!("{}: {e}", matrix.display()))?;
            let opts = cfprobe::runner::RunOptions { matrix_path: &matrix, out: &out, base_config: config, only, save_bodies, seed };
            let results = cfprobe::runner::run(&m, &opts).await?;
            let failed = results.iter().filter(|r| matches!(r.outcome, cfprobe::runner::Outcome::Fail)).count();
            println!("{} results written to {}; {failed} failed", results.len(), out.display());
            if failed > 0 {
                return Err(format!("{failed} case(s) did not meet their expectation").into());
            }
        }
        Cmd::Fuzz { seed, count, only, concurrency, out } => {
            let opts = cfprobe::random::fuzz::FuzzOptions { seed, count, only, concurrency };
            let report = cfprobe::random::fuzz::run(&opts).await?;
            let md = cfprobe::random::fuzz::markdown(&report);
            if let Some(dir) = &out {
                std::fs::create_dir_all(dir)?;
                std::fs::write(dir.join("results.json"), serde_json::to_vec_pretty(&report)?)?;
                std::fs::write(dir.join("results.md"), &md)?;
            }
            print!("{md}");
            if report.failed > 0 {
                return Err(format!("{} of {} scenarios failed (seed {})", report.failed, report.count, report.seed).into());
            }
        }
        Cmd::ProxyCheck { url, expect_egress_ip } => {
            let engine = CFProbe::new(config)?;
            let ex = engine.inspect(target(&url, &[])?).await;
            let (ok, report) = match &ex {
                Ok(ex) => {
                    let body = String::from_utf8_lossy(&ex.response.body);
                    let egress = body
                        .lines()
                        .find_map(|l| l.strip_prefix("ip="))
                        .map(str::to_string)
                        .or_else(|| serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|v| v["headers"]["cf-connecting-ip"].as_str().map(str::to_string)));
                    let matches = expect_egress_ip.as_ref().map(|want| egress.as_deref() == Some(want.as_str()));
                    let ok = (200..400).contains(&ex.response.status) && matches != Some(false);
                    (ok, serde_json::json!({
                        "route": ex.connection.route, "status": ex.response.status, "http_version": ex.response.http_version,
                        "address_source": ex.connection.address_source,
                        "timings": ex.timings, "egress_ip_seen_by_destination": egress, "egress_matches_expected": matches,
                        "direct_fallback_possible": matches!(engine.route(), cfprobe::proxy::Route::Direct),
                    }))
                }
                Err(e) => (false, serde_json::json!({ "route": engine.route().record(), "error": e.to_string(), "cloudflare": cloudflare::analyze_error(e) })),
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !ok {
                return Err("proxy check failed".into());
            }
        }
        Cmd::Diff { left, right, format } => {
            let read = |p: &PathBuf| -> Result<fingerprint::Observation, Box<dyn std::error::Error>> {
                Ok(fingerprint::parse_receiver_body(&std::fs::read(p)?)?)
            };
            let (l, r) = (read(&left)?, read(&right)?);
            let name = |p: &PathBuf| p.file_stem().unwrap_or_default().to_string_lossy().into_owned();
            let c = fingerprint::compare(&name(&left), &l.fingerprint, &name(&right), &r.fingerprint);
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&c)?),
                Format::Markdown => print!("{}", reporting::comparison_table(&c)),
            }
        }
        Cmd::Baselines { dir, format } => {
            let (found, skipped) = fingerprint::load_baselines(&dir)?;
            for s in &skipped {
                eprintln!("skipped {}: {}", s.file, s.reason);
            }
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&found)?),
                Format::Markdown => print!("{}", reporting::baseline_table(&found)),
            }
        }
    }
    Ok(())
}

fn needs_network(cmd: &Cmd) -> bool {
    matches!(cmd, Cmd::Inspect { .. } | Cmd::Fingerprint { .. } | Cmd::Run { .. } | Cmd::ProxyCheck { .. })
}

/// `HOST:PORT:ADDR` as curl takes it: `example.com:443:192.0.2.1`, `example.com:443:[2001:db8::1]`,
/// `[::1]:443:127.0.0.1`.
fn parse_resolve(r: &str) -> Option<(&str, SocketAddr)> {
    let (hostport, addr) = match r.strip_suffix(']') {
        Some(rest) => {
            let open = rest.rfind(":[")?;
            (&rest[..open], &rest[open + 2..])
        }
        None => r.rsplit_once(':')?,
    };
    let addr: std::net::IpAddr = addr.parse().ok()?;
    let port: u16 = hostport.rsplit_once(':')?.1.parse().ok()?;
    Some((hostport, SocketAddr::new(addr, port)))
}

fn target(url: &str, headers: &[String]) -> Result<Target, Box<dyn std::error::Error>> {
    let mut t = Target::get(url)?;
    for h in headers {
        let (k, v) = h.split_once(':').ok_or("header wants \"name: value\"")?;
        t = t.header(k.trim(), v.trim());
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::parse_resolve;

    #[test]
    fn resolve_takes_ipv4_and_bracketed_ipv6() {
        assert_eq!(parse_resolve("a.test:443:192.0.2.1").unwrap().1.to_string(), "192.0.2.1:443");
        assert_eq!(parse_resolve("a.test:8443:[2001:db8::1]").unwrap().1.to_string(), "[2001:db8::1]:8443");
        assert_eq!(parse_resolve("[::1]:443:127.0.0.1").unwrap().0, "[::1]:443");
        assert!(parse_resolve("a.test:443:::1").is_none());
        assert!(parse_resolve("a.test:443").is_none());
    }
}
