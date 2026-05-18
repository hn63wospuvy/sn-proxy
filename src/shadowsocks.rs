//! Shadowsocks AEAD server (SIP004).
//!
//! Wire format: the client sends a random salt, then a stream of AEAD chunks
//! `[len][len-tag][payload][payload-tag]`. The session subkey is derived with
//! HKDF-SHA1 from a master key (EVP_BytesToKey of the password) and the salt.
//! The first decrypted bytes carry the target address in SOCKS5 form.

use crate::manager::{Manager, ProxyRuntime};
use crate::relay;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use anyhow::{Result, bail};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

const TAG: usize = 16;
const MAX_PAYLOAD: usize = 0x3FFF;

/// Supported AEAD ciphers.
#[derive(Clone, Copy)]
enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20,
}

impl Method {
    fn parse(s: &str) -> Option<Method> {
        match s {
            "aes-128-gcm" => Some(Method::Aes128Gcm),
            "aes-256-gcm" => Some(Method::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Method::Chacha20),
            _ => None,
        }
    }
    /// Key size in bytes — also the per-connection salt size.
    fn key_size(&self) -> usize {
        match self {
            Method::Aes128Gcm => 16,
            Method::Aes256Gcm | Method::Chacha20 => 32,
        }
    }
}

/// An AEAD cipher keyed with a session subkey.
enum Cipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    Cha(ChaCha20Poly1305),
}

impl Cipher {
    fn new(method: Method, key: &[u8]) -> Cipher {
        match method {
            Method::Aes128Gcm => Cipher::Aes128(Aes128Gcm::new_from_slice(key).unwrap()),
            Method::Aes256Gcm => Cipher::Aes256(Aes256Gcm::new_from_slice(key).unwrap()),
            Method::Chacha20 => Cipher::Cha(ChaCha20Poly1305::new_from_slice(key).unwrap()),
        }
    }
    /// Encrypt `pt`, returning ciphertext followed by the 16-byte tag.
    fn seal(&self, nonce: &[u8; 12], pt: &[u8]) -> Vec<u8> {
        match self {
            Cipher::Aes128(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), pt),
            Cipher::Aes256(c) => c.encrypt(aes_gcm::Nonce::from_slice(nonce), pt),
            Cipher::Cha(c) => c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), pt),
        }
        .expect("AEAD seal never fails for bounded input")
    }
    /// Decrypt `ct` (ciphertext followed by tag).
    fn open(&self, nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            Cipher::Aes128(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), ct),
            Cipher::Aes256(c) => c.decrypt(aes_gcm::Nonce::from_slice(nonce), ct),
            Cipher::Cha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), ct),
        }
        .map_err(|_| ())
    }
}

/// Increment a 12-byte little-endian nonce counter.
fn incr(nonce: &mut [u8; 12]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// OpenSSL `EVP_BytesToKey` (MD5 based) — derives the master key from a password.
fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password.as_bytes());
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

/// HKDF-SHA1 session subkey derivation.
fn subkey(master: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master);
    let mut okm = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut okm).expect("hkdf expand");
    okm
}

/// Reads and decrypts the AEAD chunk stream.
struct Decryptor {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl Decryptor {
    fn new(cipher: Cipher) -> Self {
        Self {
            cipher,
            nonce: [0u8; 12],
        }
    }
    /// Read one chunk; `Ok(None)` on a clean end of stream.
    async fn read_chunk<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> std::io::Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 2 + TAG];
        match r.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let len_pt = self
            .cipher
            .open(&self.nonce, &len_buf)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "ss length decrypt failed"))?;
        incr(&mut self.nonce);
        let len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        if len == 0 || len > MAX_PAYLOAD {
            return Err(Error::new(ErrorKind::InvalidData, "bad ss chunk length"));
        }
        let mut payload = vec![0u8; len + TAG];
        r.read_exact(&mut payload).await?;
        let pt = self
            .cipher
            .open(&self.nonce, &payload)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "ss payload decrypt failed"))?;
        incr(&mut self.nonce);
        Ok(Some(pt))
    }
}

/// Encrypts plaintext into the AEAD chunk stream.
struct Encryptor {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl Encryptor {
    fn new(cipher: Cipher) -> Self {
        Self {
            cipher,
            nonce: [0u8; 12],
        }
    }
    async fn write_chunk<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        data: &[u8],
    ) -> std::io::Result<()> {
        for piece in data.chunks(MAX_PAYLOAD) {
            let len = (piece.len() as u16).to_be_bytes();
            let len_ct = self.cipher.seal(&self.nonce, &len);
            incr(&mut self.nonce);
            let pay_ct = self.cipher.seal(&self.nonce, piece);
            incr(&mut self.nonce);
            w.write_all(&len_ct).await?;
            w.write_all(&pay_ct).await?;
        }
        Ok(())
    }
}

/// Parse a SOCKS5-form address (`ATYP | ADDR | PORT`) from `buf`.
/// Returns the `host:port` string and how many bytes it occupied.
fn parse_addr(buf: &[u8]) -> Option<(String, usize)> {
    match *buf.first()? {
        0x01 => {
            if buf.len() < 7 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Some((format!("{ip}:{port}"), 7))
        }
        0x04 => {
            if buf.len() < 19 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Some((format!("[{ip}]:{port}"), 19))
        }
        0x03 => {
            let dlen = *buf.get(1)? as usize;
            if buf.len() < 2 + dlen + 2 {
                return None;
            }
            let host = String::from_utf8_lossy(&buf[2..2 + dlen]).into_owned();
            let port = u16::from_be_bytes([buf[2 + dlen], buf[3 + dlen]]);
            Some((format!("{host}:{port}"), 2 + dlen + 2))
        }
        _ => None,
    }
}

/// Handle a single accepted Shadowsocks client connection.
pub async fn serve(
    manager: Arc<Manager>,
    runtime: Arc<ProxyRuntime>,
    mut stream: TcpStream,
    peer: SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    let (method_str, password, connect_timeout, keepalive, idle) = {
        let cfg = runtime.config.lock().unwrap();
        (
            cfg.ss_method.clone().unwrap_or_default(),
            cfg.ss_password.clone().unwrap_or_default(),
            cfg.connect_timeout_secs,
            cfg.keepalive_secs,
            cfg.idle_timeout_secs,
        )
    };
    let method = Method::parse(&method_str)
        .ok_or_else(|| anyhow::anyhow!("unknown shadowsocks cipher: {method_str}"))?;
    let key_len = method.key_size();
    let master = evp_bytes_to_key(&password, key_len);

    // The client opens with its salt, then the AEAD chunk stream.
    let mut salt = vec![0u8; key_len];
    stream.read_exact(&mut salt).await?;
    let mut dec = Decryptor::new(Cipher::new(method, &subkey(&master, &salt, key_len)));

    // Decrypt chunks until the target address is complete.
    let mut plain: Vec<u8> = Vec::new();
    let (dst, consumed) = loop {
        if let Some(found) = parse_addr(&plain) {
            break found;
        }
        match dec.read_chunk(&mut stream).await? {
            Some(chunk) => plain.extend_from_slice(&chunk),
            None => bail!("client closed before sending the shadowsocks address"),
        }
        if plain.len() > 8192 {
            bail!("shadowsocks address header too long");
        }
    };
    let initial: Vec<u8> = plain.split_off(consumed);

    let target = match relay::connect(&dst, connect_timeout, keepalive).await {
        Ok(t) => t,
        Err(e) => bail!("connect to {dst} failed: {e}"),
    };

    relay::tracked(&manager.storage, &runtime, peer.to_string(), dst, |entry| async move {
        // Reply path: send our own salt, then encrypt with a fresh subkey.
        let mut tx_salt = vec![0u8; key_len];
        getrandom::fill(&mut tx_salt).expect("getrandom");
        let mut enc = Encryptor::new(Cipher::new(method, &subkey(&master, &tx_salt, key_len)));

        let (mut client_r, mut client_w) = stream.into_split();
        let (mut target_r, mut target_w) = target.into_split();
        if client_w.write_all(&tx_salt).await.is_err() {
            return;
        }

        // client -> target: decrypt chunks, forward plaintext.
        let upstream = async {
            if !initial.is_empty() {
                target_w.write_all(&initial).await?;
                entry
                    .bytes_sent
                    .fetch_add(initial.len() as u64, Ordering::Relaxed);
            }
            while let Some(chunk) = dec.read_chunk(&mut client_r).await? {
                target_w.write_all(&chunk).await?;
                entry
                    .bytes_sent
                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
            Ok::<(), std::io::Error>(())
        };

        // target -> client: encrypt plaintext into chunks.
        let downstream = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = target_r.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                enc.write_chunk(&mut client_w, &buf[..n]).await?;
                entry
                    .bytes_received
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            Ok::<(), std::io::Error>(())
        };

        let idle_fut =
            relay::idle_watchdog(entry.clone(), idle.filter(|s| *s > 0).map(Duration::from_secs));
        tokio::select! {
            _ = upstream => {}
            _ = downstream => {}
            _ = token.cancelled() => {}
            _ = idle_fut => {}
        }
    })
    .await;
    Ok(())
}
