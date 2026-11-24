# TLS compatibility (Phase 2, 2026-11-24)

Stack: BoringSSL via `boring` / `tokio-boring` 5.6.0 (pinned), one `SslConnector` per engine. Verification is on by default and is never turned off as a fallback.

## Verified behaviour

| Area | Result | Evidence |
|---|---|---|
| TLS 1.3 negotiation | Every real-world endpoint (19 URLs, 6 sites, 3 issuing CAs) and the zone: TLSv1.3 | Real-world run 2, zone runs |
| TLS 1.2 with a chosen cipher | `ECDHE-ECDSA-AES128-GCM-SHA256` negotiated and reported by IANA name | `tls_settings_take_effect` |
| ALPN `h2,http/1.1` / `http/1.1` only / server without h2 | h2 chosen when offered; http/1.1 when only it is offered or the server picks it | `h2_is_negotiated...`, `http1_when_server_offers_only_http1...`, zone `cfprobe-h1-titlecase` client |
| ALPN reporting | `tls.alpn` equals the receiver's view; config only accepts `h2` and `http/1.1` | `config_rejects_unknown_fields_and_bad_alpn` |
| SNI | Host name sent and reported (`tls.sni`). SNI for IP-literal URLs was not measured | `h2_is_negotiated...` (`sni: localhost`) |
| IPv6 literal over TLS | Works after D5 (bare address for SNI and verification) | `d5_ipv6_literals_work_over_http_and_tls` |
| Certificate chain parsing | Subject, issuer, validity, SHA-256 per certificate; real chains from Google Trust Services, Entrust and Amazon parsed | Real-world run 2 (`tls.peer_chain`) |
| Untrusted certificate | Refused with BoringSSL's reason and the verify result (`certificate verify ...`); classified TLS_FAILURE; never retried | `untrusted_certificate_is_rejected`, resilience test, fuzz `untrusted_certificate` (all scenarios) |
| Extra trust anchor | `--ca-file` / `tls.ca_file` adds a PEM; system roots stay | Every local TLS test |
| Handshake timeout | `Timeout { stage: tls }` at the configured budget (300 ms in test) | `tls_stage_times_out` |
| ClientHello random | Hex of the client's random; equal to the zone Worker's `tlsClientRandom` | P2 zone `fingerprint` (`same_handshake_as_client: true`) |
| GREASE and extension permutation (opt-in) | Visible on the wire | `FINGERPRINT_ACCURACY.md` |

Issuers seen on the real-world run: Google Trust Services (Cloudflare edge certificates for asurascans, discord, cloudflare.com, nowsecure.nl), Entrust (BookMyShow), Amazon (BookMyShow's CloudFront image CDN).

## Interoperability finding: rustls and the lab certificate

reqwest 0.13 with rustls refused the L1 lab server's certificate: `InvalidCertificate(Other(OtherError(CaUsedAsEndEntity)))`. The lab certificate is a self-signed CA used directly as the server certificate. BoringSSL (cfprobe) and OpenSSL (curl) accept it once it is trusted; webpki does not. This is a lab-certificate issue, not a cfprobe one. The reqwest comparison client has an explicit `--insecure-lab-only` switch for this loopback lab; cfprobe was not changed.

## Unsupported or limited

| Item | State |
|---|---|
| TLS session resumption | None: every connection is a full handshake (`session_reused: false`). Browsers resume; a resumed handshake has a different ClientHello (PSK) |
| TLS 1.3 cipher suite choice | Not configurable in BoringSSL |
| 0-RTT / early data | None |
| Client certificates | None |
| ECH | Not configured (BoringSSL's default sends no ECH GREASE here; Chromium sends `extensionEncryptedClientHello`) |
| HTTP/3 / QUIC | None |
| Certificate pinning, OCSP checking | No pinning; OCSP stapling and SCTs can be requested (`ocsp_stapling`, `signed_cert_timestamps`) but are not evaluated |
