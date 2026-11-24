use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use cfprobe::{CFProbe, Config, Target, fingerprint, reporting};
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
        #[arg(long)]
        show_body: bool,
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
        let (hostport, addr) = r.rsplit_once(':').ok_or("--resolve wants HOST:PORT:ADDR")?;
        let addr: std::net::IpAddr = addr.parse()?;
        let port: u16 = hostport.rsplit_once(':').ok_or("--resolve wants HOST:PORT:ADDR")?.1.parse()?;
        config.resolve.insert(hostport.to_string(), SocketAddr::new(addr, port));
    }
    if let Some(ca) = cli.ca_file {
        config.tls.ca_file = Some(ca);
    }

    match cli.cmd {
        Cmd::Inspect { url, headers, repeat, show_body } => {
            let engine = CFProbe::new(config)?;
            let target = target(&url, &headers)?;
            for _ in 0..repeat {
                let ex = engine.inspect(target.clone()).await?;
                let mut out = serde_json::to_value(&ex)?;
                if show_body {
                    out["response"]["body"] = String::from_utf8_lossy(&ex.response.body).into_owned().into();
                }
                println!("{}", serde_json::to_string_pretty(&out)?);
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
                "client_tls": ex.tls,
                "receiver": seen,
                "comparisons": comparisons,
                "skipped_baseline_files": skipped,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
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

fn target(url: &str, headers: &[String]) -> Result<Target, Box<dyn std::error::Error>> {
    let mut t = Target::get(url)?;
    for h in headers {
        let (k, v) = h.split_once(':').ok_or("header wants \"name: value\"")?;
        t = t.header(k.trim(), v.trim());
    }
    Ok(t)
}
