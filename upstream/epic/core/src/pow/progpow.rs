use std::marker::PhantomData;

use crate::pow::common::EdgeType;
use crate::pow::error::Error;
use crate::pow::{PoWContext, Proof};

pub fn new_progpow_ctx<T>() -> Result<Box<dyn PoWContext<T>>, Error>
where
    T: EdgeType + 'static,
{
    Ok(Box::new(ProgPowContext {
        nonce: 0,
        height: 0,
        header: vec![],
        phantom: PhantomData,
    }))
}

pub fn get_progpow_value(header: &[u8], height: u64, nonce: u64) -> [u8; 32] {
    let _ = (header, height, nonce);
    [0u8; 32]
}

pub struct ProgPowContext<T>
where
    T: EdgeType,
{
    pub header: Vec<u8>,
    pub nonce: u64,
    pub height: u64,
    phantom: PhantomData<T>,
}

impl<T> PoWContext<T> for ProgPowContext<T>
where
    T: EdgeType,
{
    fn set_header_nonce(
        &mut self,
        header: Vec<u8>,
        nonce: Option<u64>,
        height: Option<u64>,
        _solve: bool,
    ) -> Result<(), Error> {
        self.header = header;
        self.nonce = nonce.unwrap_or(0);
        self.height = height.unwrap_or(0);
        Ok(())
    }

    fn verify(&mut self, proof: &Proof) -> Result<(), Error> {
        let _ = proof;
        Err(Error::Verification(
            "native wallet build has no PoW verifier".to_string(),
        ))
    }
}
