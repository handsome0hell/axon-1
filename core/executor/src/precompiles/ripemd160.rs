use evm::executor::stack::{PrecompileFailure, PrecompileOutput};
use evm::{Context, ExitError, ExitSucceed};
use ripemd::Digest;

use protocol::types::H160;

use crate::err;
use crate::precompiles::{precompile_address, PrecompileContract};

#[derive(Default, Clone)]
pub struct Ripemd160;

impl PrecompileContract for Ripemd160 {
    const ADDRESS: H160 = precompile_address(0x03);
    const MIN_GAS: u64 = 600;

    fn exec_fn(
        input: &[u8],
        gas_limit: Option<u64>,
        _context: &Context,
        _is_static: bool,
    ) -> Result<(PrecompileOutput, u64), PrecompileFailure> {
        let gas = Self::gas_cost(input);
        if let Some(limit) = gas_limit {
            if gas > limit {
                return err!();
            }
        }

        let mut ret = [0u8; 32];
        let mut hasher = ripemd::Ripemd160::default();
        hasher.update(input);
        ret[12..].copy_from_slice(&hasher.finalize());

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output:      ret.to_vec(),
            },
            gas,
        ))
    }

    fn gas_cost(input: &[u8]) -> u64 {
        let data_word_size = (input.len() + 31) / 32;
        (data_word_size * 120) as u64 + Self::MIN_GAS
    }
}
