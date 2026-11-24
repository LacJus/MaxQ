use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;
use tokio::io::Interest;
use tokio::net::UdpSocket as TokioUdpSocket;

type Blake2b256 = Blake2b<U32>;

const SALAMANDER_PSK_MIN_LEN: usize = 4;
const SALAMANDER_SALT_LEN: usize = 8;
const SALAMANDER_KEY_LEN: usize = 32;

/// Exact implementation of Hysteria2 Salamander UDP packet obfuscation
/// (`apernet/hysteria` `extras/obfs/salamander.go`):
/// Wire packet = `[8-byte random salt][payload XOR BLAKE2b-256(PSK || salt)]`.
#[derive(Clone)]
pub struct SalamanderObfuscator {
    psk: Vec<u8>,
}

impl fmt::Debug for SalamanderObfuscator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderObfuscator")
            .field("psk", &"[REDACTED]")
            .finish()
    }
}

impl SalamanderObfuscator {
    pub fn new(psk: &[u8]) -> Result<Self, String> {
        if psk.len() < SALAMANDER_PSK_MIN_LEN {
            return Err(format!(
                "Salamander PSK must be at least {SALAMANDER_PSK_MIN_LEN} bytes"
            ));
        }
        Ok(Self { psk: psk.to_vec() })
    }

    pub fn obfuscate(&self, payload: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; SALAMANDER_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        self.obfuscate_with_salt(payload, &salt)
    }

    pub fn obfuscate_with_salt(&self, payload: &[u8], salt: &[u8; SALAMANDER_SALT_LEN]) -> Vec<u8> {
        let key = self.derive_key(salt);
        let mut out = Vec::with_capacity(SALAMANDER_SALT_LEN + payload.len());
        out.extend_from_slice(salt);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ key[i % SALAMANDER_KEY_LEN]);
        }
        out
    }

    pub fn deobfuscate(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() <= SALAMANDER_SALT_LEN {
            return None;
        }
        let salt = &packet[..SALAMANDER_SALT_LEN];
        let body = &packet[SALAMANDER_SALT_LEN..];
        let key = self.derive_key(salt);
        let mut out = Vec::with_capacity(body.len());
        for (i, &b) in body.iter().enumerate() {
            out.push(b ^ key[i % SALAMANDER_KEY_LEN]);
        }
        Some(out)
    }

    fn derive_key(&self, salt: &[u8]) -> [u8; SALAMANDER_KEY_LEN] {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.psk);
        hasher.update(salt);
        let digest = hasher.finalize();
        let mut key = [0u8; SALAMANDER_KEY_LEN];
        key.copy_from_slice(&digest);
        key
    }
}

/// Wraps a Tokio `UdpSocket` with Hysteria2 Salamander obfuscation for `quinn`.
/// Uses a heap-allocated receive scratch buffer to avoid stack overflow hazards on Windows (M-5).
#[derive(Debug)]
pub struct SalamanderUdpSocket {
    socket: Arc<TokioUdpSocket>,
    obfs: SalamanderObfuscator,
    recv_buf: Mutex<Box<[u8]>>,
}

impl SalamanderUdpSocket {
    pub fn new(std_socket: StdUdpSocket, obfs: SalamanderObfuscator) -> io::Result<Self> {
        std_socket.set_nonblocking(true)?;
        let socket = TokioUdpSocket::from_std(std_socket)?;
        Ok(Self {
            socket: Arc::new(socket),
            obfs,
            recv_buf: Mutex::new(vec![0u8; 65535].into_boxed_slice()),
        })
    }
}

#[derive(Debug)]
struct SalamanderPoller {
    socket: Arc<TokioUdpSocket>,
}

impl UdpPoller for SalamanderPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SalamanderPoller {
            socket: Arc::clone(&self.socket),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let payload = transmit.contents;
        let segment_size = transmit.segment_size.unwrap_or(payload.len()).max(1);
        for chunk in payload.chunks(segment_size) {
            let obfs_pkt = self.obfs.obfuscate(chunk);
            self.socket.try_send_to(&obfs_pkt, transmit.destination)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() || bufs[0].is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut raw_buf = self
            .recv_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        loop {
            match self.socket.poll_recv_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }

            match self.socket.try_io(Interest::READABLE, || {
                self.socket.try_recv_from(&mut raw_buf)
            }) {
                Ok((n, addr)) => {
                    let Some(plain) = self.obfs.deobfuscate(&raw_buf[..n]) else {
                        continue;
                    };
                    // Drop empty or oversized datagrams rather than truncating or emitting stride=0 (M-5)
                    if plain.is_empty() || plain.len() > bufs[0].len() {
                        continue;
                    }
                    let len = plain.len();
                    bufs[0][..len].copy_from_slice(&plain);
                    meta[0] = RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
