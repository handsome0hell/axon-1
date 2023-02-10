use ethers::{
    abi::{encode, parse_abi, FunctionExt, Token},
    providers::{Http, Middleware, Provider},
    types::{BlockId, H256, U256},
};
use evm::{
    executor::stack::{PrecompileFailure, PrecompileOutput},
    ExitRevert,
};
use evm::{Context, ExitError, ExitSucceed};

use tokio::{runtime::Handle, task::block_in_place};

use protocol::types::H160;

use crate::precompiles::precompile_address;

#[derive(Default, Clone)]
pub struct ETHVerifier;
const RPC_URI: &str = "https://rpc.ankr.com/eth";
const CONFIRMATION_DELAY: u64 = 30;

fn str_to_revert_err(val: &str) -> PrecompileFailure {
    PrecompileFailure::Revert {
        exit_status: ExitRevert::Reverted,
        output:      val.as_bytes().to_vec(),
    }
}

fn error_to_revert_err<E: std::error::Error>(err: E) -> PrecompileFailure {
    str_to_revert_err(&err.to_string())
}

impl ETHVerifier {
    pub const ADDRESS: H160 = precompile_address(0x87);
    pub const MIN_GAS: u64 = 500;

    pub fn exec_fn(
        latest_timestamp: U256,
        input: &[u8],
        gas_limit: Option<u64>,
        _context: &Context,
        _is_static: bool,
    ) -> Result<(PrecompileOutput, u64), PrecompileFailure> {
        if input.len() < 4 {
            return Err(str_to_revert_err("Invalid input"));
        }

        let contract = parse_abi(&[
            "function getBlock(uint64 timestamp, bytes32 blockHash) external returns (tuple(uint64 number, uint64 timestamp, bytes32 blockHash, bytes32 parentHash, bytes32 stateRoot, bytes32 transactionsRoot, bytes32 receiptsRoot) memory)",
        ])
            .map_err(error_to_revert_err)?;

        let function = contract
            .functions()
            .find(|fun| fun.selector() == input[0..4])
            .ok_or(str_to_revert_err("Unknown selector"))?;

        let gas = Self::gas_cost(input);

        if let Some(limit) = gas_limit {
            if gas > limit {
                return Err(PrecompileFailure::from(ExitError::OutOfGas));
            }
        }

        let decoded = function
            .decode_input(&input[4..])
            .map_err(error_to_revert_err)?;

        let (timestamp, block_hash) = match &decoded[..] {
            [Token::Uint(timestamp), Token::FixedBytes(block_hash)] => (timestamp, block_hash),
            _ => return Err(str_to_revert_err("Invalid input")),
        };

        if &latest_timestamp < timestamp
            || latest_timestamp - timestamp < U256::from(CONFIRMATION_DELAY)
        {
            return Err(str_to_revert_err("Time traveller"));
        }

        let provider = Provider::<Http>::try_from(RPC_URI).map_err(error_to_revert_err)?;

        let block = block_in_place(|| -> Result<_, PrecompileFailure> {
            Handle::current().block_on(async {
                let block = provider
                    .get_block(BlockId::Hash(H256::from_slice(block_hash)))
                    .await
                    .map_err(error_to_revert_err)?
                    .ok_or(str_to_revert_err("Block not found"))?;
                Ok(block)
            })
        })?;

        if timestamp != &block.timestamp {
            return Err(str_to_revert_err("Timestamp mismatch"));
        }

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output:      encode(&[Token::Tuple(vec![
                    Token::Uint(U256::from(block.number.map(|v| v.as_u64()).unwrap_or(0))),
                    Token::Uint(block.timestamp),
                    Token::FixedBytes(
                        block
                            .hash
                            .map(|v| v.as_bytes().to_vec())
                            .unwrap_or_else(|| block_hash.to_vec()),
                    ),
                    Token::FixedBytes(block.parent_hash.as_bytes().to_vec()),
                    Token::FixedBytes(block.state_root.as_bytes().to_vec()),
                    Token::FixedBytes(block.transactions_root.as_bytes().to_vec()),
                    Token::FixedBytes(block.receipts_root.as_bytes().to_vec()),
                ])]),
            },
            gas,
        ))
    }

    fn gas_cost(_input: &[u8]) -> u64 {
        Self::MIN_GAS
    }
}
