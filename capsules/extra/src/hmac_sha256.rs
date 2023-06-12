// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Software implementation of HMAC-SHA256.

use core::cell::Cell;
// use kernel::deferred_call::{DeferredCall, DeferredCallClient};

use kernel::hil;
// use kernel::hil::digest::Sha256;
// use kernel::hil::digest::{Digest, DigestData, DigestHash, DigestVerify};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};
use kernel::utilities::leasable_buffer::LeasableBuffer;
use kernel::utilities::leasable_buffer::LeasableBufferDynamic;
use kernel::utilities::leasable_buffer::LeasableMutableBuffer;
use kernel::ErrorCode;

#[derive(Clone, Copy, PartialEq)]
pub enum State {
    Idle,
    InnerHashKeyPending,
    InnerHashAddKey,
    InnerHashAddData,
    InnerHash,
    OuterHashAddKey,
    OuterHashAddHash,
    OuterHash,
}

const SHA_BLOCK_LEN_BYTES: usize = 64;
const SHA_256_OUTPUT_LEN_BYTES: usize = 32;
const NUM_ROUND_CONSTANTS: usize = 64;

pub struct HmacSha256Software<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> {
    sha256: &'a S,

    state: Cell<State>,

    client: OptionalCell<&'a dyn hil::digest::ClientDataHash<SHA_256_OUTPUT_LEN_BYTES>>,

    input_data: OptionalCell<LeasableBufferDynamic<'static, u8>>,

    data_buffer: TakeCell<'static, [u8]>,
    key_buffer: MapCell<[u8; SHA_BLOCK_LEN_BYTES]>,
    buffered_length: Cell<usize>,
    total_length: Cell<usize>,

    digest_buffer: MapCell<&'static mut [u8; 32]>,

    // Used to store the hash or the hash to compare against with verify
    output_data: Cell<Option<&'static mut [u8; SHA_256_OUTPUT_LEN_BYTES]>>,
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> HmacSha256Software<'a, S> {
    pub fn new(sha256: &'a S, data_buffer: &'static mut [u8]) -> Self {
        let s = Self {
            sha256,

            state: Cell::new(State::Idle),

            client: OptionalCell::empty(),
            input_data: OptionalCell::empty(),
            data_buffer: TakeCell::new(data_buffer),
            key_buffer: MapCell::new([0; SHA_BLOCK_LEN_BYTES]),
            buffered_length: Cell::new(0),
            total_length: Cell::new(0),

            digest_buffer: MapCell::empty(),

            output_data: Cell::new(None),
            // hash_values: Cell::new([0; 8]),
            // deferred_call: DeferredCall::new(),
        };
        // s.initialize();
        s
    }
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>>
    hil::digest::DigestData<'a, 32> for HmacSha256Software<'a, S>
{
    fn add_data(
        &self,
        data: LeasableBuffer<'static, u8>,
    ) -> Result<(), (ErrorCode, LeasableBuffer<'static, u8>)> {
        // if self.busy() {
        //     Err((ErrorCode::BUSY, data))
        // } else {
        //     self.state.set(State::Data);
        //     self.deferred_call.set();
        //     self.input_data.set(LeasableBufferDynamic::Immutable(data));
        //     self.compute_sha256();
        //     Ok(())
        // }

        self.sha256.add_data(data)
    }

    fn add_mut_data(
        &self,
        data: LeasableMutableBuffer<'static, u8>,
    ) -> Result<(), (ErrorCode, LeasableMutableBuffer<'static, u8>)> {
        // if self.busy() {
        //     Err((ErrorCode::BUSY, data))
        // } else {
        //     self.state.set(State::Data);
        //     self.deferred_call.set();
        //     self.input_data.set(LeasableBufferDynamic::Mutable(data));
        //     self.compute_sha256();
        //     Ok(())

        // self.sha256.add_mut_data(data)

        match self.state.get() {
            State::InnerHashKeyPending => {
                // We need to write the key before we write the data.

                if let Some(key_buf) = self.key_buffer.take() {
                    if let Some(data_buf) = self.data_buffer.take() {
                        for i in 0..64 {
                            data_buf[i] = key_buf[i] ^ 0x36;
                        }
                        self.key_buffer.replace(key_buf);

                        let mut lease_buf = LeasableMutableBuffer::new(data_buf);
                        lease_buf.slice(0..64);

                        kernel::debug!("set inner key");

                        self.input_data.set(LeasableBufferDynamic::Mutable(data));
                        // self.input_data.set(lease_buf);
                        self.state.set(State::InnerHashAddKey);

                        self.sha256.add_mut_data(lease_buf)
                    } else {
                        Err((ErrorCode::FAIL, data))
                    }
                } else {
                    Err((ErrorCode::FAIL, data))
                }
            }

            _ => self.sha256.add_mut_data(data),
        }

        // }
    }

    fn clear_data(&self) {
        // self.initialize();
    }
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>>
    hil::digest::DigestHash<'a, 32> for HmacSha256Software<'a, S>
{
    fn run(
        &'a self,
        digest: &'static mut [u8; 32],
    ) -> Result<(), (ErrorCode, &'static mut [u8; 32])> {
        // if self.busy() {
        //     Err((ErrorCode::BUSY, digest))
        // } else {
        //     self.state.set(State::Hash);
        //     self.complete_sha256();
        //     for i in 0..8 {
        //         let val = self.hash_values.get()[i];
        //         digest[4 * i + 3] = (val >> 0 & 0xff) as u8;
        //         digest[4 * i + 2] = (val >> 8 & 0xff) as u8;
        //         digest[4 * i + 1] = (val >> 16 & 0xff) as u8;
        //         digest[4 * i + 0] = (val >> 24 & 0xff) as u8;
        //     }
        //     self.output_data.set(Some(digest));
        //     self.deferred_call.set();
        //     Ok(())
        // }

        kernel::debug!("run called!");

        self.state.set(State::InnerHash);
        self.sha256.run(digest)
    }
}

// impl<'a> DigestVerify<'a, 32> for Sha256Software<'a> {
//     fn verify(
//         &'a self,
//         compare: &'static mut [u8; 32],
//     ) -> Result<(), (ErrorCode, &'static mut [u8; 32])> {
//         if self.busy() {
//             Err((ErrorCode::BUSY, compare))
//         } else {
//             self.state.set(State::Verify);
//             self.complete_sha256();
//             self.output_data.set(Some(compare));
//             self.deferred_call.set();
//             Ok(())
//         }
//     }
// }

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>>
    hil::digest::DigestDataHash<'a, 32> for HmacSha256Software<'a, S>
{
    fn set_client(&'a self, client: &'a dyn hil::digest::ClientDataHash<32>) {
        self.client.set(client);
    }
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> hil::digest::ClientData<32>
    for HmacSha256Software<'a, S>
{
    fn add_data_done(&self, _result: Result<(), ErrorCode>, _data: LeasableBuffer<'static, u8>) {}

    fn add_mut_data_done(
        &self,
        result: Result<(), ErrorCode>,
        data: LeasableMutableBuffer<'static, u8>,
    ) {
        match self.state.get() {
            State::InnerHashAddKey => {
                self.data_buffer.replace(data.take());

                // self.state.set(State::InnerHash);
                self.state.set(State::InnerHashAddData);

                self.input_data.take().map(|in_data| match in_data {
                    LeasableBufferDynamic::Mutable(buffer) => {
                        kernel::debug!("add buffer data {}", buffer.len());
                        self.sha256.add_mut_data(buffer);
                    }
                    LeasableBufferDynamic::Immutable(buffer) => {
                        self.sha256.add_data(buffer);
                    }
                });

                // self.state.set(State::Idle);
                // match data {
                //     LeasableBufferDynamic::Mutable(buffer) => {
                //         self.client.map(|client| {
                //             client.add_mut_data_done(Ok(()), buffer);
                //         });
                //     }
                //     LeasableBufferDynamic::Immutable(buffer) => {
                //         self.client.map(|client| {
                //             client.add_data_done(Ok(()), buffer);
                //         });
                //     }
                // }

                // self.digest_buffer.take().map(|digest_buf| {
                //     self.sha256.run(digest_buf);
                // });
            }
            State::OuterHashAddKey => {
                self.digest_buffer.map(|digest_buf| {
                    let data_buf = data.take();

                    for i in 0..32 {
                        data_buf[i] = digest_buf[i];
                    }

                    let mut lease_buf = LeasableMutableBuffer::new(data_buf);

                    lease_buf.slice(0..32);

                    kernel::debug!("add in hash result");

                    self.state.set(State::OuterHashAddHash);
                    self.sha256.add_mut_data(lease_buf);
                });
            }
            State::OuterHashAddHash => {
                self.state.set(State::OuterHash);
                self.digest_buffer.take().map(|digest_buf| {
                    self.sha256.run(digest_buf);
                });
            }
            _ => {
                // self.data_buffer.replace(data.take());

                self.client.map(|client| {
                    client.add_mut_data_done(result, data);
                });
            }
        }
    }
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> hil::digest::ClientHash<32>
    for HmacSha256Software<'a, S>
{
    fn hash_done(&self, result: Result<(), ErrorCode>, digest: &'static mut [u8; 32]) {
        match self.state.get() {
            State::InnerHash => {
                // Completed inner hash, now work on outer hash.
                self.sha256.clear_data();
                self.digest_buffer.replace(digest);

                self.key_buffer.map(|key_buf| {
                    self.data_buffer.take().map(|data_buf| {
                        for i in 0..64 {
                            data_buf[i] = key_buf[i] ^ 0x5c;
                        }

                        let mut lease_buf = LeasableMutableBuffer::new(data_buf);
                        lease_buf.slice(0..64);

                        kernel::debug!("add outer key");

                        self.state.set(State::OuterHashAddKey);
                        self.sha256.add_mut_data(lease_buf);
                    });
                });
            }

            State::OuterHash => {
                kernel::debug!("out: {:?}", digest);

                self.client.map(|c| {
                    c.hash_done(Ok(()), digest);
                });
            }
            _ => {}
        }
    }
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> hil::digest::HmacSha256
    for HmacSha256Software<'a, S>
{
    fn set_mode_hmacsha256(&self, key: &[u8]) -> Result<(), ErrorCode> {
        if key.len() > 64 {
            // Key size must be no longer than the internal block size (which is
            // 64 bytes).
            Err(ErrorCode::SIZE)
        } else {
            self.key_buffer.map_or(Err(ErrorCode::FAIL), |key_buf| {
                // self.data_buffer
                //     .take()
                //     .map_or(Err(ErrorCode::FAIL), |data_buf| {
                for i in 0..64 {
                    key_buf[i] = *key.get(i).unwrap_or(&0);

                    // data_buf[i] = key_buf[i] ^ 0x36;
                }

                kernel::debug!("set key");
                self.state.set(State::InnerHashKeyPending);

                // let mut lease_buf = LeasableMutableBuffer::new(data_buf);
                // lease_buf.slice(0..64);

                // self.sha256.add_mut_data(lease_buf);
                Ok(())
                // })
            })
            // let mut lease_buf =
            //     LeasableMutableBuffer::new(self.data_buffer.take().unwrap());
        }

        // Ok(())
    }
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> hil::digest::ClientVerify<32>
    for HmacSha256Software<'a, S>
{
    fn verification_done(&self, _result: Result<bool, ErrorCode>, _compare: &'static mut [u8; 32]) {
    }
}
