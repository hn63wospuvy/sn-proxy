//! TLS support for the `https` proxy protocol.
//!
//! If the config file supplies `tls_cert` / `tls_key`, those PEM files are
//! used; otherwise a self-signed certificate is generated at startup. Either
//! way a single acceptor is shared by every HTTPS proxy.

use anyhow::{Context, Result, anyhow, bail};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Build a `TlsAcceptor`, loading PEM files when both paths are given.
pub fn acceptor(cert_path: Option<&str>, key_path: Option<&str>) -> Result<TlsAcceptor> {
    let (certs, key) = match (cert_path, key_path) {
        (Some(c), Some(k)) => load_pem(c, k)?,
        (None, None) => self_signed()?,
        _ => bail!("tls_cert and tls_key must both be set, or neither"),
    };

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Generate a throw-away self-signed certificate.
fn self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let signed = rcgen::generate_simple_self_signed(vec!["sn-proxy.local".to_string()])?;
    let cert = signed.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        signed.signing_key.serialize_der(),
    ));
    Ok((vec![cert], key))
}

/// Load a certificate chain and private key from PEM files.
fn load_pem(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("opening tls_cert {cert_path}"))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("reading certificates from {cert_path}"))?;
    if certs.is_empty() {
        bail!("no certificates found in {cert_path}");
    }

    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("opening tls_key {key_path}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .with_context(|| format!("reading private key from {key_path}"))?
        .ok_or_else(|| anyhow!("no private key found in {key_path}"))?;

    Ok((certs, key))
}
