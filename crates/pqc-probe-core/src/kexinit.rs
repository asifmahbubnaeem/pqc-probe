//! Native SSH KEXINIT reader.
//!
//! Reads the server's key-exchange proposal straight off the wire (RFC 4253 sections 4.2 and
//! 7.1): connect, read the identification banner, send ours, read the server's first packet.
//! KEXINIT is sent before any key exchange, so it is unencrypted and needs no crypto.
//!
//! Why not scrape `ssh -vv`: OpenSSH truncates each log line (about 1 KB), so a server with a
//! long algorithm list (e.g. an OQS build offering Frodo/Kyber variants) came back cut off
//! mid-name. Reading the packet gives the complete list and does not depend on any
//! client's debug output format.

use crate::{ProbeError, Target};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// RFC 4253 section 6.1: implementations must handle packets up to 35000 bytes.
const MAX_PACKET: usize = 35_000;
/// A server may send text lines before its banner (RFC 4253 section 4.2); bound what we accept.
const MAX_BANNER_LINES: usize = 32;
const MAX_BANNER_BYTES: usize = 8 * 1024;
const SSH_MSG_KEXINIT: u8 = 20;
const CLIENT_BANNER: &[u8] = b"SSH-2.0-pqc-probe\r\n";

/// What the server announced before key exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKexInit {
    /// The identification line, e.g. "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.9".
    pub banner: String,
    /// The software version (and comments) part of the banner, if it is well formed.
    pub software_version: Option<String>,
    /// The server's complete `kex_algorithms` list, in the server's order.
    pub kex_algorithms: Vec<String>,
}

/// Connect to `target` (the pinned address if set) and read the server's KEXINIT.
/// Only IPv4 is used, like every other probe.
pub async fn read_server_kexinit(
    target: &Target,
    timeout: Duration,
) -> Result<ServerKexInit, ProbeError> {
    tokio::time::timeout(timeout, read_inner(target))
        .await
        .map_err(|_| ProbeError::Timeout)?
}

async fn read_inner(target: &Target) -> Result<ServerKexInit, ProbeError> {
    let host = target.connect_host();
    let addr = tokio::net::lookup_host((host.as_str(), target.port))
        .await?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| ProbeError::Protocol(format!("no IPv4 address for {host}")))?;
    let mut stream = TcpStream::connect(addr).await?;

    let banner = read_banner(&mut stream).await?;
    stream.write_all(CLIENT_BANNER).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let packet_len = u32::from_be_bytes(len_buf) as usize;
    if !(6..=MAX_PACKET).contains(&packet_len) {
        return Err(ProbeError::Protocol(format!(
            "implausible first packet length {packet_len}"
        )));
    }
    let mut packet = vec![0u8; packet_len];
    stream.read_exact(&mut packet).await?;

    let kex_algorithms = parse_kexinit_packet(&packet).map_err(ProbeError::Protocol)?;
    Ok(ServerKexInit {
        software_version: software_version(&banner),
        banner,
        kex_algorithms,
    })
}

/// Read lines until one starts with "SSH-". One byte at a time so nothing of the first binary
/// packet is consumed.
async fn read_banner(stream: &mut TcpStream) -> Result<String, ProbeError> {
    let mut total = 0usize;
    for _ in 0..MAX_BANNER_LINES {
        let mut line = Vec::new();
        loop {
            let b = stream.read_u8().await?;
            total += 1;
            if total > MAX_BANNER_BYTES {
                return Err(ProbeError::Protocol("banner too long".into()));
            }
            if b == b'\n' {
                break;
            }
            line.push(b);
        }
        let text = String::from_utf8_lossy(&line)
            .trim_end_matches('\r')
            .to_string();
        if text.starts_with("SSH-") {
            return Ok(text);
        }
    }
    Err(ProbeError::Protocol("no SSH identification line".into()))
}

/// "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.9" -> "OpenSSH_9.6p1 Ubuntu-3ubuntu13.9".
pub fn software_version(banner: &str) -> Option<String> {
    let rest = banner.trim().strip_prefix("SSH-")?;
    let (_proto, software) = rest.split_once('-')?;
    let software = software.trim();
    (!software.is_empty()).then(|| software.to_string())
}

/// Parse the part of a binary packet that follows `packet_length`:
/// `padding_length (1) | payload | padding`. Returns the KEX algorithm list.
pub fn parse_kexinit_packet(buf: &[u8]) -> Result<Vec<String>, String> {
    let pad = *buf.first().ok_or("empty packet")? as usize;
    if pad < 4 || 1 + pad > buf.len() {
        return Err(format!(
            "bad padding length {pad} for a {}-byte packet",
            buf.len()
        ));
    }
    parse_kexinit_payload(&buf[1..buf.len() - pad])
}

/// Parse a KEXINIT payload: `type (1) | cookie (16) | kex_algorithms name-list | ...`.
pub fn parse_kexinit_payload(p: &[u8]) -> Result<Vec<String>, String> {
    match p.first() {
        Some(&SSH_MSG_KEXINIT) => {}
        Some(t) => {
            return Err(format!(
                "first packet is message type {t}, not KEXINIT (20)"
            ))
        }
        None => return Err("empty payload".into()),
    }
    let rest = p.get(17..).ok_or("payload shorter than type + cookie")?;
    let len_bytes: [u8; 4] = rest
        .get(..4)
        .ok_or("missing kex_algorithms length")?
        .try_into()
        .map_err(|_| "bad length field")?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let end = 4usize
        .checked_add(len)
        .ok_or("kex_algorithms length overflow")?;
    let body = rest
        .get(4..end)
        .ok_or_else(|| format!("kex_algorithms claims {len} bytes but the packet ends first"))?;
    let text = std::str::from_utf8(body).map_err(|_| "kex_algorithms is not UTF-8")?;
    Ok(text
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_list(items: &[&str]) -> Vec<u8> {
        let joined = items.join(",");
        let mut v = (joined.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(joined.as_bytes());
        v
    }

    /// A full wire packet (including the 4-byte packet_length) carrying a KEXINIT.
    fn kexinit_wire(kex: &[&str]) -> Vec<u8> {
        let mut payload = vec![SSH_MSG_KEXINIT];
        payload.extend_from_slice(&[0xAB; 16]); // cookie
        payload.extend(name_list(kex));
        for _ in 0..9 {
            payload.extend(name_list(&["x"])); // the other nine name-lists
        }
        payload.push(0); // first_kex_packet_follows
        payload.extend_from_slice(&[0, 0, 0, 0]); // reserved
        let pad = 8 - ((payload.len() + 5) % 8);
        let pad = if pad < 4 { pad + 8 } else { pad };
        let mut body = vec![pad as u8];
        body.extend(payload);
        body.extend(std::iter::repeat_n(0u8, pad));
        let mut wire = (body.len() as u32).to_be_bytes().to_vec();
        wire.extend(body);
        wire
    }

    #[test]
    fn parses_a_kexinit_packet() {
        let wire = kexinit_wire(&["curve25519-sha256", "mlkem768x25519-sha256"]);
        let got = parse_kexinit_packet(&wire[4..]).unwrap();
        assert_eq!(got, vec!["curve25519-sha256", "mlkem768x25519-sha256"]);
    }

    /// Regression: `ssh -vv` cut this kind of list at ~1 KB; the wire format has no such limit.
    #[test]
    fn long_lists_are_not_truncated() {
        let names: Vec<String> = (0..60)
            .map(|i| format!("ecdh-nistp256-frodokem-{i}-aesr2-sha256@openquantumsafe.org"))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        assert!(refs.join(",").len() > 2_000);
        let wire = kexinit_wire(&refs);
        let got = parse_kexinit_packet(&wire[4..]).unwrap();
        assert_eq!(got.len(), 60);
        assert_eq!(got.last().unwrap(), names.last().unwrap());
    }

    #[test]
    fn empty_list_is_ok() {
        let wire = kexinit_wire(&[]);
        assert!(parse_kexinit_packet(&wire[4..]).unwrap().is_empty());
    }

    #[test]
    fn rejects_non_kexinit_and_malformed_packets() {
        // message type 2 (SSH_MSG_IGNORE) with valid padding
        let mut body = vec![4u8, 2, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_kexinit_packet(&body)
            .unwrap_err()
            .contains("not KEXINIT"));
        // padding larger than the packet
        body = vec![200u8, 20, 0];
        assert!(parse_kexinit_packet(&body).is_err());
        // padding below the 4-byte minimum
        body = vec![1u8, 20, 0, 0];
        assert!(parse_kexinit_packet(&body).is_err());
        assert!(parse_kexinit_packet(&[]).is_err());
        // list length runs past the end
        let mut p = vec![SSH_MSG_KEXINIT];
        p.extend_from_slice(&[0; 16]);
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(b"abc");
        assert!(parse_kexinit_payload(&p)
            .unwrap_err()
            .contains("ends first"));
        // length near u32::MAX must not overflow or panic
        let mut p = vec![SSH_MSG_KEXINIT];
        p.extend_from_slice(&[0; 16]);
        p.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_kexinit_payload(&p).is_err());
        // too short for type + cookie
        assert!(parse_kexinit_payload(&[SSH_MSG_KEXINIT, 1, 2]).is_err());
    }

    #[test]
    fn extracts_software_version() {
        assert_eq!(
            software_version("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.9").as_deref(),
            Some("OpenSSH_9.6p1 Ubuntu-3ubuntu13.9")
        );
        assert_eq!(
            software_version("SSH-2.0-OpenSSH_10.2-2025-12_").as_deref(),
            Some("OpenSSH_10.2-2025-12_")
        );
        assert_eq!(software_version("SSH-2.0-"), None);
        assert_eq!(software_version("HTTP/1.1 400"), None);
    }

    async fn serve_once(prefix: &'static [u8], wire: Vec<u8>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(prefix).await.unwrap();
            sock.write_all(&wire).await.unwrap();
            if !wire.is_empty() {
                let mut tmp = [0u8; 64];
                let _ = sock.read(&mut tmp).await; // wait for the client banner before closing
            }
        });
        port
    }

    #[tokio::test]
    async fn reads_kexinit_from_a_local_server() {
        let wire = kexinit_wire(&["curve25519-sha256", "kyber-512-sha256"]);
        let port = serve_once(b"SSH-2.0-OpenSSH_10.2-2025-12_\r\n", wire).await;
        let got = read_server_kexinit(&Target::new("127.0.0.1", port), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(got.banner, "SSH-2.0-OpenSSH_10.2-2025-12_");
        assert_eq!(
            got.software_version.as_deref(),
            Some("OpenSSH_10.2-2025-12_")
        );
        assert_eq!(
            got.kex_algorithms,
            vec!["curve25519-sha256", "kyber-512-sha256"]
        );
    }

    #[tokio::test]
    async fn skips_text_lines_before_the_banner() {
        let wire = kexinit_wire(&["curve25519-sha256"]);
        let port = serve_once(b"Welcome\r\nauthorized use only\r\nSSH-2.0-test\r\n", wire).await;
        let got = read_server_kexinit(&Target::new("127.0.0.1", port), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(got.banner, "SSH-2.0-test");
        assert_eq!(got.kex_algorithms, vec!["curve25519-sha256"]);
    }

    #[tokio::test]
    async fn non_ssh_server_is_a_protocol_error_not_a_hang() {
        let port = serve_once(b"HTTP/1.1 400 Bad Request\r\n\r\n", Vec::new()).await;
        let err = read_server_kexinit(&Target::new("127.0.0.1", port), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProbeError::Protocol(_) | ProbeError::SpawnFailed(_)
        ));
    }
}
