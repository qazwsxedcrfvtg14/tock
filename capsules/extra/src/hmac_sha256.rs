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
    InnerHash,
    OuterHashAddKey,
    OuterHashAddHash,
    OuterHash,
}

const SHA_BLOCK_LEN_BYTES: usize = 64;
const SHA_256_OUTPUT_LEN_BYTES: usize = 32;
const NUM_ROUND_CONSTANTS: usize = 64;

// const ROUND_CONSTANTS: [u32; NUM_ROUND_CONSTANTS] = [
//     0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
//     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
//     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
//     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
//     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
//     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
//     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
//     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
// ];

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
    // hash_values: Cell<[u32; 8]>,
    // deferred_call: DeferredCall,
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

        self.sha256.add_mut_data(data)
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
            State::OuterHashAddKey => {
                self.digest_buffer.map(|digest_buf| {
                    let data_buf = data.take();

                    for i in 0..32 {
                        data_buf[i] = digest_buf[i];
                    }

                    let mut lease_buf = LeasableMutableBuffer::new(data_buf);

                    lease_buf.slice(0..32);
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

                        self.state.set(State::OuterHashAddKey);
                        self.sha256.add_mut_data(lease_buf);
                    });
                });
            }

            State::OuterHash => {
                kernel::debug!("out: {:?}", digest);
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
                self.data_buffer
                    .take()
                    .map_or(Err(ErrorCode::FAIL), |data_buf| {
                        for i in 0..64 {
                            key_buf[i] = *key.get(i).unwrap_or(&0);

                            data_buf[i] = key_buf[i] ^ 0x36;
                        }

                        let mut lease_buf = LeasableMutableBuffer::new(data_buf);
                        lease_buf.slice(0..64);

                        self.sha256.add_mut_data(lease_buf);
                        Ok(())
                    })
            })
            // let mut lease_buf =
            //     LeasableMutableBuffer::new(self.data_buffer.take().unwrap());
        }

        // Ok(())
    }
}
