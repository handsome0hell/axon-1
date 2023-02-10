mod blake2_f;
mod call_ckb_vm;
mod ec_add;
mod ec_mul;
mod ec_pairing;
mod ecrecover;
mod eth_verifier;
mod get_cell;
mod identity;
mod modexp;
mod ripemd160;
mod rsa;
mod secp256r1;
mod sha256;
#[cfg(test)]
mod tests;
mod verify_by_ckb_vm;

use std::collections::BTreeMap;

use bn::{AffineG1, Fq, Fr, Group, G1};
use evm::executor::stack::{
    PrecompileFailure, PrecompileFn, PrecompileHandle, PrecompileOutput, PrecompileSet,
};
use evm::{Context, ExitError};

use ethers::types::U256;
use protocol::types::H160;

use crate::precompiles::{
    blake2_f::Blake2F, ec_add::EcAdd, ec_mul::EcMul, ec_pairing::EcPairing, ecrecover::EcRecover,
    eth_verifier::ETHVerifier, identity::Identity, modexp::ModExp, ripemd160::Ripemd160,
    sha256::Sha256,
};

#[macro_export]
macro_rules! err {
    () => {
        Err(PrecompileFailure::Error {
            exit_status: ExitError::OutOfGas,
        })
    };

    ($msg: expr) => {
        Err(PrecompileFailure::Error {
            exit_status: ExitError::Other($msg.into()),
        })
    };

    (_, $msg: expr) => {
        PrecompileFailure::Error {
            exit_status: ExitError::Other($msg.into()),
        }
    };
}

macro_rules! precompiles {
    () => { BTreeMap::new() };

    ($($contract: ident),+) => {{
        let mut set = BTreeMap::new();
        $(
            set.insert($contract::ADDRESS, $contract::exec_fn as PrecompileFn);
        )*
        set
    }};
}

trait PrecompileContract {
    const ADDRESS: H160;
    const MIN_GAS: u64;

    fn exec_fn(
        input: &[u8],
        gas_limit: Option<u64>,
        context: &Context,
        is_static: bool,
    ) -> Result<(PrecompileOutput, u64), PrecompileFailure>;

    fn gas_cost(input: &[u8]) -> u64;
}

const fn precompile_address(addr: u8) -> H160 {
    H160([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, addr,
    ])
}

pub struct StatefulPrecompileSet {
    pure_contracts: BTreeMap<H160, PrecompileFn>,
    timestamp:      U256,
}

impl PrecompileSet for StatefulPrecompileSet {
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<PrecompileOutput, PrecompileFailure>> {
        let address = handle.code_address();

        let precompile = self.pure_contracts.get(&address);
        if precompile.is_none() && address != ETHVerifier::ADDRESS {
            return None;
        };

        let input = handle.input();
        let gas_limit = handle.gas_limit();
        let context = handle.context();
        let is_static = handle.is_static();

        Some(
            match match precompile {
                Some(precompile) => (*precompile)(input, gas_limit, context, is_static),
                None => {
                    if address == ETHVerifier::ADDRESS {
                        ETHVerifier::exec_fn(self.timestamp, input, gas_limit, context, is_static)
                    } else {
                        return None;
                    }
                }
            } {
                Ok((output, cost)) => handle
                    .record_cost(cost)
                    .map(|_| output)
                    .map_err(|err| err.into()),
                Err(err) => Err(err),
            },
        )
    }

    /// Check if the given address is a precompile. Should only be called to
    /// perform the check while not executing the precompile afterward, since
    /// `execute` already performs a check internally.
    fn is_precompile(&self, address: H160) -> bool {
        self.pure_contracts.contains_key(&address) || address == ETHVerifier::ADDRESS
    }
}

pub fn build_precompile_set(timestamp: U256) -> StatefulPrecompileSet {
    StatefulPrecompileSet {
        pure_contracts: precompiles!(
            EcRecover, Sha256, Ripemd160, Identity, ModExp, EcAdd, EcMul, EcPairing, Blake2F
        ),
        timestamp,
    }
}

pub(crate) fn read_point(input: &[u8], start: usize) -> Result<G1, PrecompileFailure> {
    if input.len() < start + 64 {
        return err!("Invalid input length");
    }

    let px =
        Fq::from_slice(&input[start..(start + 32)]).map_err(|_| err!(_, "Invalid X coordinate"))?;

    let py = Fq::from_slice(&input[(start + 32)..(start + 64)])
        .map_err(|_| err!(_, "Invalid Y coordinate"))?;

    let ret = if px == Fq::zero() && py == Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(px, py)
            .map_err(|_| err!(_, "Invalid curve point"))?
            .into()
    };

    Ok(ret)
}

pub(crate) fn read_fr(input: &[u8], start: usize) -> Result<Fr, PrecompileFailure> {
    if input.len() < start + 32 {
        return err!("Invalid input length");
    }

    Fr::from_slice(&input[start..(start + 32)]).map_err(|_| err!(_, "Invalid field element"))
}
