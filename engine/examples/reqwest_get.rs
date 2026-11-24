//! The "standard Rust client" for comparisons: reqwest 0.13 with rustls, default settings, one GET,
//! body printed. Usage: cargo run --example reqwest_get -- <url> [--ca <pem>] [--resolve host:port:addr]
//! [--insecure-lab-only]
//!
//! `--insecure-lab-only` exists for one reason: the L1 lab certificate is a self-signed CA used as the
//! server certificate, which rustls refuses (`CaUsedAsEndEntity`) while BoringSSL and OpenSSL accept
//! it. Certificate checking happens after the ClientHello, so it does not change what is measured.
//! It is only for the loopback TrackMe lab; cfprobe itself never turns verification off as a fallback.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let url = args.first().expect("url");
    // Same route rule as cfprobe: --proxy, else CFPROBE_PROXY, else direct (announced). Ambient
    // proxy variables are ignored either way, so this client cannot take a route cfprobe would not.
    let mut b = reqwest::Client::builder().no_proxy();
    let proxy = args.iter().position(|a| a == "--proxy").map(|i| args[i + 1].clone()).or_else(|| std::env::var("CFPROBE_PROXY").ok().filter(|v| !v.trim().is_empty()));
    match &proxy {
        Some(p) => {
            // socks5:// would resolve locally in reqwest; socks5h:// leaves it to the proxy, like cfprobe.
            let p = p.replacen("socks5://", "socks5h://", 1);
            b = b.proxy(reqwest::Proxy::all(&p).expect("proxy url"));
            eprintln!("reqwest_get: routing through the configured proxy");
        }
        None => eprintln!("reqwest_get: no proxy defined: running in no-proxy mode (direct connections)"),
    }
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ca" => {
                let pem = std::fs::read(&args[i + 1]).unwrap();
                for c in reqwest::Certificate::from_pem_bundle(&pem).unwrap() {
                    b = b.add_root_certificate(c);
                }
            }
            "--proxy" => {}
            "--insecure-lab-only" => {
                b = b.danger_accept_invalid_certs(true);
                i += 1;
                continue;
            }
            "--resolve" => {
                let (hp, addr) = args[i + 1].rsplit_once(':').unwrap();
                let (host, port) = hp.rsplit_once(':').unwrap();
                b = b.resolve(host, std::net::SocketAddr::new(addr.parse().unwrap(), port.parse().unwrap()));
            }
            _ => panic!("unknown arg {}", args[i]),
        }
        i += 2;
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let r = b.build().unwrap().get(url).send().await.unwrap();
        eprintln!("{} {:?}", r.status(), r.version());
        print!("{}", r.text().await.unwrap());
    });
}
