// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

#![allow(unused)]

use litep2p::{
    protocol::request_response::{
        Config, ConfigBuilder, DialOptions, RequestResponseEvent, RequestResponseHandle,
    },
    types::RequestId,
    PeerId, ProtocolName,
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use librsync::whole::{delta, patch, signature};
use sha2::{Digest, Sha256, Sha512};
use tokio::{
    sync::mpsc::{channel, Receiver, Sender},
    task::JoinSet,
};

use std::{
    collections::{hash_map::Entry, HashMap},
    fs::File,
    io::{Cursor, Read},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct DiffId(u64);

pub enum RsyncError {}

/// Events received from [`Rsync`].
#[derive(Debug)]
pub enum RsyncEvent {
    /// TODO:
    DiffRequestReceived {
        /// Request ID.
        request_id: RequestId,

        /// SHA256 digest of the bytes.
        digest: Vec<u8>,
    },

    DiffResponseReceived {
        /// Diff ID.
        diff_id: DiffId,

        /// Updated file.
        file: Vec<u8>,
    },
}

enum FutureEvent {
    Request {
        peer: PeerId,
        diff_id: DiffId,
        path: PathBuf,
        digest: Vec<u8>,
        signature: Vec<u8>,
    },

    ResponseOut {
        request_id: RequestId,
        delta: Vec<u8>,
    },

    ResponseIn {
        diff_id: DiffId,
        data: Vec<u8>,
    },
}

/// Handle for communicating with [`Rsync`].
pub struct Rsync {
    futures: JoinSet<Result<FutureEvent, ()>>,
    handle: RequestResponseHandle,
    next_diff_id: u64,
    pending_diffs: HashMap<RequestId, Vec<u8>>,
    pending_out_diffs: HashMap<RequestId, (DiffId, PathBuf)>,
}

impl Rsync {
    /// Create new [`Rsync`].
    pub fn new() -> (Self, Config) {
        let (config, handle) = ConfigBuilder::new(ProtocolName::from("/litep2p/rsync/0.1.0"))
            .with_max_size(10 * 1024 * 1024)
            .build();

        (
            Self {
                futures: JoinSet::new(),
                handle,
                next_diff_id: 0u64,
                pending_diffs: HashMap::new(),
                pending_out_diffs: HashMap::new(),
            },
            config,
        )
    }

    /// Allocate next [`DiffId`].
    fn next_diff_id(&mut self) -> DiffId {
        let diff_id = self.next_diff_id;
        self.next_diff_id += 1;

        DiffId(diff_id)
    }

    fn on_request_received(&self, mut bytes: Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> {
        let signature = bytes.split_off(32);

        Some((bytes, signature))
    }

    fn on_response(&mut self, request_id: RequestId, delta: Vec<u8>) {
        let (diff_id, path) = self.pending_out_diffs.remove(&request_id).unwrap();

        self.futures.spawn_blocking(move || {
            let mut contents = Vec::new();
            let mut file = File::open(&path).map_err(|_| ())?;
            file.read_to_end(&mut contents).map_err(|_| ())?;

            let mut data = Vec::new();
            patch(
                &mut Cursor::new(contents),
                &mut Cursor::new(delta),
                &mut data,
            )
            .map_err(|_| ())
            .map(|_| FutureEvent::ResponseIn { diff_id, data })
        });
    }

    pub fn send_diff_response(&mut self, request_id: RequestId, path: PathBuf) {
        let signature = self.pending_diffs.remove(&request_id).unwrap();

        self.futures.spawn_blocking(move || {
            let mut contents = Vec::new();
            let mut file = File::open(&path).map_err(|_| ())?;
            file.read_to_end(&mut contents).map_err(|_| ())?;

            println!("modified len = {}", contents.len());

            let mut dlt = Vec::new();
            delta(
                &mut Cursor::new(contents),
                &mut Cursor::new(signature),
                &mut dlt,
            )
            .map_err(|_| ())
            .map(|_| {
                println!("delta len = {}", dlt.len());

                FutureEvent::ResponseOut {
                    request_id,
                    delta: dlt,
                }
            })
        });
    }

    pub fn download_diff(&mut self, peer: PeerId, path: PathBuf) -> DiffId {
        let diff_id = self.next_diff_id();

        self.futures.spawn_blocking(move || {
            let mut contents = Vec::new();
            let mut file = File::open(&path).map_err(|_| ())?;
            file.read_to_end(&mut contents).map_err(|_| ())?;

            println!("original len = {}", contents.len());

            let digest = {
                let mut hasher = Sha256::new();
                hasher.update(&contents);
                hasher.finalize().to_vec()
            };
            let signature = {
                let mut sig = Vec::new();

                signature(&mut Cursor::new(&contents), &mut sig)
                    .map_err(|_| ())
                    .map(|_| {
                        println!("signature len = {}", sig.len());
                        sig
                    })
            }?;

            println!("ready!");

            Ok(FutureEvent::Request {
                peer,
                diff_id,
                path,
                digest,
                signature,
            })
        });

        diff_id
    }
}

impl Stream for Rsync {
    type Item = RsyncEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.futures.poll_join_next(cx) {
                Poll::Pending | Poll::Ready(None) => break,
                Poll::Ready(Some(Err(_))) => return Poll::Ready(None),
                Poll::Ready(Some(Ok(Ok(FutureEvent::Request {
                    peer,
                    diff_id,
                    path,
                    digest,
                    signature,
                })))) => {
                    let serialized = {
                        let mut out = BytesMut::with_capacity(digest.len() + signature.len());
                        out.put_slice(&digest);
                        out.put_slice(&signature);

                        out
                    };

                    match self.handle.try_send_request(
                        peer,
                        serialized.freeze().to_vec(),
                        DialOptions::Dial,
                    ) {
                        Err(_) => {}
                        Ok(request_id) => {
                            self.pending_out_diffs.insert(request_id, (diff_id, path));
                        }
                    }
                }
                Poll::Ready(Some(Ok(Ok(FutureEvent::ResponseOut { request_id, delta })))) => {
                    self.handle.send_response(request_id, delta);
                }
                Poll::Ready(Some(Ok(Ok(FutureEvent::ResponseIn { diff_id, data })))) => {
                    return Poll::Ready(Some(RsyncEvent::DiffResponseReceived {
                        diff_id,
                        file: data,
                    }))
                }
                _ => todo!(),
            }
        }

        loop {
            match futures::ready!(self.handle.poll_next_unpin(cx)) {
                None => return Poll::Ready(None),
                Some(event) => match event {
                    RequestResponseEvent::RequestReceived {
                        request_id,
                        request,
                        ..
                    } => match self.on_request_received(request) {
                        Some((digest, signature)) => {
                            self.pending_diffs.insert(request_id, signature);
                            return Poll::Ready(Some(RsyncEvent::DiffRequestReceived {
                                request_id,
                                digest,
                            }));
                        }
                        None => self.handle.reject_request(request_id),
                    },
                    RequestResponseEvent::ResponseReceived {
                        peer,
                        request_id,
                        fallback,
                        response,
                    } => self.on_response(request_id, response),
                    RequestResponseEvent::RequestFailed {
                        peer,
                        request_id,
                        error,
                    } => todo!(),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litep2p::{config::ConfigBuilder as Litep2pConfigBuilder, Litep2p};

    fn make_litep2p() -> (Litep2p, Rsync) {
        let (mut rsync, config) = Rsync::new();

        let config = Litep2pConfigBuilder::new()
            .with_tcp(Default::default())
            .with_request_response_protocol(config)
            .build();

        let litep2p = Litep2p::new(config).unwrap();

        (litep2p, rsync)
    }

    #[tokio::test]
    async fn test() {
        let (mut litep2p1, mut rsync1) = make_litep2p();
        let (mut litep2p2, mut rsync2) = make_litep2p();
        let peer1 = *litep2p1.local_peer_id();
        let peer2 = *litep2p2.local_peer_id();

        litep2p1.add_known_address(peer2, litep2p2.listen_addresses().cloned());
        litep2p2.add_known_address(peer1, litep2p1.listen_addresses().cloned());

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = litep2p1.next_event() => {}
                    _ = litep2p2.next_event() => {}
                }
            }
        });

        let mut original = PathBuf::from("resources/Cargo.lock");
        let mut modified = PathBuf::from("resources/Cargo.lock.cpy");

        let modified_digest = {
            let mut file = File::open(&modified).unwrap();
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).unwrap();

            let mut hasher = Sha256::new();
            hasher.update(&contents);
            hasher.finalize().to_vec()
        };

        tokio::spawn(async move {
            match rsync2.next().await.unwrap() {
                RsyncEvent::DiffRequestReceived { request_id, digest } => {
                    println!("send diff repsonse");
                    rsync2.send_diff_response(request_id, modified);
                }
                _ => todo!(),
            }

            loop {
                let _ = rsync2.next().await.unwrap();
            }
        });

        let diff_id = rsync1.download_diff(peer2, original);

        loop {
            while let Some(event) = rsync1.next().await {
                match event {
                    RsyncEvent::DiffResponseReceived { diff_id, file } => {
                        let mut hasher = Sha256::new();
                        hasher.update(&file);
                        let digest = hasher.finalize().to_vec();
                        assert_eq!(digest, modified_digest);

                        println!("matches");
                        return;
                    }
                    _ => todo!(),
                }
            }
        }
    }
}
