use ethers::{
    abi::{decode_whole, ParamType, Token},
    providers::{Http, Middleware, Provider},
    types::{BlockId, H256, U256},
};
use evm::executor::stack::{PrecompileFailure, PrecompileOutput};
use evm::{Context, ExitError, ExitSucceed};

use tokio::{runtime::Handle, task::block_in_place};

use protocol::types::H160;

use crate::err;
use crate::precompiles::{precompile_address, PrecompileContract};

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default, Clone)]
pub struct ETHVerifier;

impl PrecompileContract for ETHVerifier {
    const ADDRESS: H160 = precompile_address(0x87);
    const MIN_GAS: u64 = 15;

    fn exec_fn(
        input: &[u8],
        gas_limit: Option<u64>,
        _context: &Context,
        _is_static: bool,
    ) -> Result<(PrecompileOutput, u64), PrecompileFailure> {
        let now_secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(val) => U256::from(val.as_secs()),
            Err(_) => return err!(),
        };

        let gas = Self::gas_cost(input);

        if let Some(limit) = gas_limit {
            if gas > limit {
                return err!();
            }
        }

        let decoded = match decode_whole(&[ParamType::Uint(256), ParamType::FixedBytes(32)], input)
        {
            Ok(res) => res,
            Err(_) => return err!(),
        };

        let (timestamp, block_hash) = match &decoded[..] {
            [Token::Uint(timestamp), Token::FixedBytes(block_hash)] => (timestamp, block_hash),
            _ => return err!(),
        };

        let provider = Provider::<Http>::try_from("https://rpc.ankr.com/eth")
            .expect("could not instantiate HTTP Provider");

        let block = block_in_place(|| {
            Handle::current().block_on(async {
                let block = provider
                    .get_block(BlockId::Hash(H256::from_slice(block_hash)))
                    .await
                    .unwrap();
                block
            })
        });

        let valid = (|| {
            let block = match block {
                Some(block) => block,
                None => return false,
            };

            timestamp == &block.timestamp
                && &now_secs >= timestamp
                && now_secs - timestamp > U256::from(60)
        })();

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output:      vec![if valid { 0 } else { 1 }],
            },
            gas,
        ))
    }

    fn gas_cost(_input: &[u8]) -> u64 {
        15
    }
}
