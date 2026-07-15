// Copyright 2018 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Verification-only implementation of Cuckatoo Cycle.

use byteorder::{BigEndian, WriteBytesExt};

use crate::pow::common::{CuckooParams, EdgeType};
use crate::pow::error::Error;
use crate::pow::{PoWContext, Proof};
use crate::util;

pub fn new_cuckatoo_ctx<T>(
    edge_bits: u8,
    proof_size: usize,
    _max_solutions: u32,
) -> Result<Box<dyn PoWContext<T>>, Error>
where
    T: EdgeType + 'static,
{
    Ok(Box::new(CuckatooContext::<T>::new_impl(
        edge_bits,
        proof_size,
    )?))
}

pub struct CuckatooContext<T>
where
    T: EdgeType,
{
    params: CuckooParams<T>,
}

impl<T> PoWContext<T> for CuckatooContext<T>
where
    T: EdgeType,
{
    fn set_header_nonce(
        &mut self,
        header: Vec<u8>,
        nonce: Option<u64>,
        _height: Option<u64>,
        _solve: bool,
    ) -> Result<(), Error> {
        self.set_header_nonce_impl(header, nonce)
    }

    fn verify(&mut self, proof: &Proof) -> Result<(), Error> {
        self.verify_impl(proof)
    }
}

impl<T> CuckatooContext<T>
where
    T: EdgeType,
{
    pub fn new_impl(edge_bits: u8, proof_size: usize) -> Result<CuckatooContext<T>, Error> {
        Ok(CuckatooContext {
            params: CuckooParams::new(edge_bits, proof_size)?,
        })
    }

    pub fn sipkey_hex(&self, index: usize) -> Result<String, Error> {
        let mut output = vec![];
        output.write_u64::<BigEndian>(self.params.siphash_keys[index])?;
        Ok(util::to_hex(output))
    }

    pub fn set_header_nonce_impl(
        &mut self,
        header: Vec<u8>,
        nonce: Option<u64>,
    ) -> Result<(), Error> {
        self.params.reset_header_nonce(header, nonce)
    }

    pub fn sipnode(&self, edge: T, uorv: u64) -> Result<T, Error> {
        self.params.sipnode(edge, uorv, false)
    }

    pub fn verify_impl(&self, proof: &Proof) -> Result<(), Error> {
        if let Proof::CuckooProof { nonces, .. } = proof {
            let mut endpoints = vec![0u64; 2 * proof.proof_size()];
            let mut xor0: u64 = (self.params.proof_size as u64 / 2) & 1;
            let mut xor1 = xor0;

            for index in 0..proof.proof_size() {
                if nonces[index] > to_u64!(self.params.edge_mask) {
                    return Err(Error::Verification("edge too big".to_owned()));
                }
                if index > 0 && nonces[index] <= nonces[index - 1] {
                    return Err(Error::Verification("edges not ascending".to_owned()));
                }
                endpoints[2 * index] = to_u64!(self.sipnode(to_edge!(nonces[index]), 0)?);
                endpoints[2 * index + 1] = to_u64!(self.sipnode(to_edge!(nonces[index]), 1)?);
                xor0 ^= endpoints[2 * index];
                xor1 ^= endpoints[2 * index + 1];
            }
            if xor0 | xor1 != 0 {
                return Err(Error::Verification("endpoints do not match".to_owned()));
            }

            let mut cycle_length = 0;
            let mut endpoint_index = 0;
            loop {
                let mut match_index = endpoint_index;
                let mut candidate = match_index;
                loop {
                    candidate = (candidate + 2) % (2 * self.params.proof_size);
                    if candidate == endpoint_index {
                        break;
                    }
                    if endpoints[candidate] >> 1 == endpoints[endpoint_index] >> 1 {
                        if match_index != endpoint_index {
                            return Err(Error::Verification("branch in cycle".to_owned()));
                        }
                        match_index = candidate;
                    }
                }
                if match_index == endpoint_index || endpoints[match_index] == endpoints[endpoint_index]
                {
                    return Err(Error::Verification("cycle dead ends".to_owned()));
                }
                endpoint_index = match_index ^ 1;
                cycle_length += 1;
                if endpoint_index == 0 {
                    break;
                }
            }

            if cycle_length == self.params.proof_size {
                Ok(())
            } else {
                Err(Error::Verification("cycle too short".to_owned()))
            }
        } else {
            Err(Error::Verification("wrong algorithm".to_owned()))
        }
    }
}
