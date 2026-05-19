//! TLS support for the proxy.
//!
//! Covers three roles:
//!
//! * the *global* `https` acceptor — PEM files from the config, or a
//!   self-signed certificate generated at startup;
//! * *per-proxy* `https` acceptors built from a PKCS#12 keystore, optionally
//!   enforcing client certificates (mTLS) against a PKCS#12 truststore;
//! * *client* TLS connectors that present a PKCS#12 client identity to
//!   upstream servers requiring mutual TLS.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use p12_keystore::{KeyStore, KeyStoreEntry};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Install the process-wide ring crypto provider exactly once.
pub fn install_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

/// Build the global `TlsAcceptor`, loading PEM files when both paths are given.
pub fn acceptor(cert_path: Option<&str>, key_path: Option<&str>) -> Result<TlsAcceptor> {
    let (certs, key) = match (cert_path, key_path) {
        (Some(c), Some(k)) => load_pem(c, k)?,
        (None, None) => self_signed()?,
        _ => bail!("tls_cert and tls_key must both be set, or neither"),
    };
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a per-proxy HTTPS acceptor from a base64 PKCS#12 keystore. When
/// `mtls` is set, connecting clients must present a certificate that chains to
/// the supplied PKCS#12 truststore.
pub fn acceptor_from_p12(
    keystore_b64: &str,
    keystore_password: &str,
    truststore_b64: Option<&str>,
    truststore_password: &str,
    mtls: bool,
) -> Result<TlsAcceptor> {
    let (certs, key) = p12_identity(keystore_b64, keystore_password, None)
        .context("reading the HTTPS server keystore")?;

    let builder = ServerConfig::builder();
    let config = if mtls {
        let pem = truststore_b64
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("mTLS is enabled but no truststore was provided"))?;
        let ca = p12_certificates(pem, truststore_password)
            .context("reading the client-certificate truststore")?;
        let mut roots = RootCertStore::empty();
        for cert in ca {
            roots
                .add(cert)
                .context("adding a truststore certificate to the root store")?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| anyhow!("building the client-certificate verifier: {e}"))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
    } else {
        builder.with_no_client_auth().with_single_cert(certs, key)?
    };
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a client TLS connector that presents the PKCS#12 client identity in
/// `keystore_b64`. Upstream server certificates are not verified — the proxy's
/// destinations are typically internal services behind private CAs.
pub fn client_connector(
    keystore_b64: &str,
    keystore_password: &str,
    alias: Option<&str>,
) -> Result<TlsConnector> {
    let (certs, key) = p12_identity(keystore_b64, keystore_password, alias)
        .context("reading the client mTLS keystore")?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_client_auth_cert(certs, key)
        .context("installing the client certificate")?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// A plain client connector with no client certificate, used when an `http`
/// proxy forwards to an `https://` destination that does not require mTLS.
pub fn plain_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Generate a throw-away self-signed certificate.
fn self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let signed = rcgen::generate_simple_self_signed(vec!["sn-proxy.local".to_string()])?;
    let cert = signed.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signed.signing_key.serialize_der()));
    Ok((vec![cert], key))
}

/// Load a certificate chain and private key from PEM files.
fn load_pem(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file =
        std::fs::File::open(cert_path).with_context(|| format!("opening tls_cert {cert_path}"))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("reading certificates from {cert_path}"))?;
    if certs.is_empty() {
        bail!("no certificates found in {cert_path}");
    }
    let key_file =
        std::fs::File::open(key_path).with_context(|| format!("opening tls_key {key_path}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .with_context(|| format!("reading private key from {key_path}"))?
        .ok_or_else(|| anyhow!("no private key found in {key_path}"))?;
    Ok((certs, key))
}

/// Extract a private key and its certificate chain from a base64 PKCS#12
/// keystore. When `alias` is set, that named entry is used; otherwise the
/// first private-key entry is taken.
fn p12_identity(
    keystore_b64: &str,
    password: &str,
    alias: Option<&str>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(keystore_b64.trim())
        .context("the keystore is not valid base64")?;
    let store = KeyStore::from_pkcs12(&der, password)
        .map_err(|e| anyhow!("cannot open PKCS#12 keystore (wrong password?): {e}"))?;

    let chain = match alias.filter(|a| !a.is_empty()) {
        Some(a) => match store.entry(a) {
            Some(KeyStoreEntry::PrivateKeyChain(c)) => c,
            Some(_) => bail!("keystore entry {a:?} is not a private key"),
            None => bail!("keystore has no entry named {a:?}"),
        },
        None => {
            store
                .private_key_chain()
                .ok_or_else(|| anyhow!("keystore contains no private key"))?
                .1
        }
    };

    let certs: Vec<CertificateDer<'static>> = chain
        .chain()
        .iter()
        .map(|c| CertificateDer::from(c.as_der().to_vec()))
        .collect();
    if certs.is_empty() {
        bail!("keystore private key has no certificate chain");
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.key().to_vec()));
    Ok((certs, key))
}

/// Collect every certificate from a base64 PKCS#12 truststore.
fn p12_certificates(
    truststore_b64: &str,
    password: &str,
) -> Result<Vec<CertificateDer<'static>>> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(truststore_b64.trim())
        .context("the truststore is not valid base64")?;
    let store = KeyStore::from_pkcs12(&der, password)
        .map_err(|e| anyhow!("cannot open PKCS#12 truststore (wrong password?): {e}"))?;

    let mut out = Vec::new();
    for (_alias, entry) in store.entries() {
        match entry {
            KeyStoreEntry::Certificate(c) => {
                out.push(CertificateDer::from(c.as_der().to_vec()))
            }
            KeyStoreEntry::PrivateKeyChain(chain) => {
                for c in chain.chain() {
                    out.push(CertificateDer::from(c.as_der().to_vec()));
                }
            }
        }
    }
    if out.is_empty() {
        bail!("truststore contains no certificates");
    }
    Ok(out)
}

/// A server-certificate verifier that accepts any certificate. Used for the
/// proxy's *outbound* connections, where the goal is to present a client
/// identity rather than to validate the destination.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
