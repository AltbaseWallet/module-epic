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

//! Proof-of-work data types and verification used by the wallet.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

#[macro_use]
mod common;
pub mod cuckaroo;
pub mod cuckatoo;
mod error;
pub mod md5;
pub mod progpow;
pub mod randomx;
mod siphash;
mod types;

use crate::core::BlockHeader;
use crate::global;

pub use self::common::EdgeType;
pub use self::types::*;
pub use crate::pow::cuckaroo::{new_cuckaroo_ctx, CuckarooContext};
pub use crate::pow::cuckatoo::{new_cuckatoo_ctx, CuckatooContext};
pub use crate::pow::error::Error;
pub use crate::pow::md5::{new_md5_ctx, MD5Context};
pub use crate::pow::progpow::{new_progpow_ctx, ProgPowContext};
pub use crate::pow::randomx::{new_randomx_ctx, RXContext};

const VERIFICATION_CONTEXTS: u32 = 1;

pub fn verify_size(header: &BlockHeader) -> Result<(), Error> {
    let mut context = match header.pow.proof {
        Proof::ProgPowProof { .. } => new_progpow_ctx(),
        Proof::RandomXProof { .. } => new_randomx_ctx(header.pow.seed),
        Proof::MD5Proof { .. } => new_md5_ctx(
            header.pow.edge_bits(),
            global::proofsize(),
            VERIFICATION_CONTEXTS,
        ),
        Proof::CuckooProof { ref nonces, .. } => Ok(global::create_pow_context::<u64>(
            header.height,
            header.pow.edge_bits(),
            nonces.len(),
            VERIFICATION_CONTEXTS,
        )?),
    }?;

    if let Proof::CuckooProof { .. } = header.pow.proof {
        context.set_header_nonce(header.pre_pow(), None, Some(header.height), false)?;
    } else {
        context.set_header_nonce(
            header.pre_pow(),
            Some(header.pow.nonce),
            Some(header.height),
            false,
        )?;
    }

    context.verify(&header.pow.proof)
}
