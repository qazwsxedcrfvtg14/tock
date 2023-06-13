// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Software implementation of HMAC-SHA256.

use core::cell::Cell;

use kernel::hil;
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};
use kernel::utilities::leasable_buffer::LeasableBuffer;
use kernel::utilities::leasable_buffer::LeasableBufferDynamic;
use kernel::utilities::leasable_buffer::LeasableMutableBuffer;
use kernel::ErrorCode;

#[derive(Clone, Copy, PartialEq)]
pub enum State {
    Idle,
    InnerHashAddKeyPending,
    InnerHashAddKey,
    InnerHashAddData,
    InnerHash,
    OuterHashAddKey,
    OuterHashAddHash,
    OuterHash,
}

const SHA_BLOCK_LEN_BYTES: usize = 64;
const SHA_256_OUTPUT_LEN_BYTES: usize = 32;

pub struct HmacSha256Software<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> {
    sha256: &'a S,

    state: Cell<State>,

    client: OptionalCell<&'a dyn hil::digest::ClientDataHash<SHA_256_OUTPUT_LEN_BYTES>>,

    input_data: OptionalCell<LeasableBufferDynamic<'static, u8>>,

    data_buffer: TakeCell<'static, [u8]>,
    key_buffer: MapCell<[u8; SHA_BLOCK_LEN_BYTES]>,

    digest_buffer: MapCell<&'static mut [u8; 32]>,
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> HmacSha256Software<'a, S> {
    pub fn new(sha256: &'a S, data_buffer: &'static mut [u8]) -> Self {
        Self {
            sha256,

            state: Cell::new(State::Idle),

            client: OptionalCell::empty(),
            input_data: OptionalCell::empty(),
            data_buffer: TakeCell::new(data_buffer),
            key_buffer: MapCell::new([0; SHA_BLOCK_LEN_BYTES]),

            digest_buffer: MapCell::empty(),
        }
    }
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>>
    hil::digest::DigestData<'a, 32> for HmacSha256Software<'a, S>
{
    fn add_data(
        &self,
        data: LeasableBuffer<'static, u8>,
    ) -> Result<(), (ErrorCode, LeasableBuffer<'static, u8>)> {
        match self.state.get() {
            State::InnerHashAddKeyPending => {
                // We need to write the key before we write the data.

                if let Some(key_buf) = self.key_buffer.take() {
                    if let Some(data_buf) = self.data_buffer.take() {
                        // Copy the key XOR with inner pad (0x36).
                        for i in 0..64 {
                            data_buf[i] = key_buf[i] ^ 0x36;
                        }
                        self.key_buffer.replace(key_buf);

                        let mut lease_buf = LeasableMutableBuffer::new(data_buf);
                        lease_buf.slice(0..64);

                        match self.sha256.add_mut_data(lease_buf) {
                            Ok(()) => {
                                self.state.set(State::InnerHashAddKey);
                                // Save the incoming data to add to the hasher
                                // on the next iteration.
                                self.input_data.set(LeasableBufferDynamic::Immutable(data));
                                Ok(())
                            }
                            Err((e, leased_data_buf)) => {
                                self.data_buffer.replace(leased_data_buf.take());
                                Err((e, data))
                            }
                        }
                    } else {
                        Err((ErrorCode::FAIL, data))
                    }
                } else {
                    Err((ErrorCode::FAIL, data))
                }
            }

            State::InnerHashAddData => {
                // In this state the hasher is ready to take more input data so
                // we can provide more input data. This is the only state after
                // setting the key we can accept new data in.
                self.sha256.add_data(data)
            }

            State::Idle => {
                // We need a key before we can accept data, so we must return
                // error here. `OFF` is the closest error to this issue so we
                // return that.
                Err((ErrorCode::OFF, data))
            }

            _ => {
                // Any other state we cannot accept new data.
                Err((ErrorCode::BUSY, data))
            }
        }
    }

    fn add_mut_data(
        &self,
        data: LeasableMutableBuffer<'static, u8>,
    ) -> Result<(), (ErrorCode, LeasableMutableBuffer<'static, u8>)> {
        match self.state.get() {
            State::InnerHashAddKeyPending => {
                // We need to write the key before we write the data.

                if let Some(key_buf) = self.key_buffer.take() {
                    if let Some(data_buf) = self.data_buffer.take() {
                        // Copy the key XOR with inner pad (0x36).
                        for i in 0..64 {
                            data_buf[i] = key_buf[i] ^ 0x36;
                        }
                        self.key_buffer.replace(key_buf);

                        let mut lease_buf = LeasableMutableBuffer::new(data_buf);
                        lease_buf.slice(0..64);

                        match self.sha256.add_mut_data(lease_buf) {
                            Ok(()) => {
                                self.state.set(State::InnerHashAddKey);
                                // Save the incoming data to add to the hasher
                                // on the next iteration.
                                self.input_data.set(LeasableBufferDynamic::Mutable(data));
                                Ok(())
                            }
                            Err((e, leased_data_buf)) => {
                                self.data_buffer.replace(leased_data_buf.take());
                                Err((e, data))
                            }
                        }
                    } else {
                        Err((ErrorCode::FAIL, data))
                    }
                } else {
                    Err((ErrorCode::FAIL, data))
                }
            }

            State::InnerHashAddData => {
                // In this state the hasher is ready to take more input data so
                // we can provide more input data. This is the only state after
                // setting the key we can accept new data in.
                self.sha256.add_mut_data(data)
            }

            State::Idle => {
                // We need a key before we can accept data, so we must return
                // error here. `OFF` is the closest error to this issue so we
                // return that.
                Err((ErrorCode::OFF, data))
            }

            _ => {
                // Any other state we cannot accept new data.
                Err((ErrorCode::BUSY, data))
            }
        }
    }

    fn clear_data(&self) {
        self.state.set(State::Idle);
        self.sha256.clear_data();
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

                // We just added the key, so we can now add the stored data.
                self.state.set(State::InnerHashAddData);
                self.input_data.take().map(|in_data| match in_data {
                    LeasableBufferDynamic::Mutable(buffer) => {
                        self.sha256.add_mut_data(buffer);
                    }
                    LeasableBufferDynamic::Immutable(buffer) => {
                        self.sha256.add_data(buffer);
                    }
                });
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
                // Save the key in our key buffer.
                for i in 0..64 {
                    key_buf[i] = *key.get(i).unwrap_or(&0);
                }

                // Mark that we have the key pending which we can add once we
                // get additional data to add. We can't add the key in the
                // underlying hash now because we don't have a callback to use,
                // so we have to just store the key. We need to use the key
                // again anyway, so this is ok.
                self.state.set(State::InnerHashAddKeyPending);
                Ok(())
            })
        }
    }
}

impl<'a, S: hil::digest::Sha256 + hil::digest::DigestDataHash<'a, 32>> hil::digest::ClientVerify<32>
    for HmacSha256Software<'a, S>
{
    fn verification_done(&self, _result: Result<bool, ErrorCode>, _compare: &'static mut [u8; 32]) {
    }
}
