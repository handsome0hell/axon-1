use evm::executor::stack::{MemoryStackState, PrecompileSet, StackExecutor, StackSubstateMetadata};

use protocol::traits::{ApplyBackend, Backend};
use protocol::types::{Config, SignedTransaction, TransactionAction, TxResp, U256};

// deprecated
#[allow(dead_code)]
#[derive(Default)]
pub struct EvmExecutor;

#[allow(dead_code)]
impl EvmExecutor {
    pub fn inner_exec<B: Backend + ApplyBackend>(
        &self,
        backend: &mut B,
        config: &Config,
        gas_limit: u64,
        precompiles: &impl PrecompileSet,
        tx: SignedTransaction,
    ) -> TxResp {
        let old_nonce = backend.basic(tx.sender).nonce;
        let metadata = StackSubstateMetadata::new(gas_limit, config);
        let mut executor = StackExecutor::new_with_precompiles(
            MemoryStackState::new(metadata, backend),
            config,
            precompiles,
        );
        let (exit_reason, ret) = match tx.transaction.unsigned.action() {
            TransactionAction::Call(addr) => executor.transact_call(
                tx.sender,
                *addr,
                *tx.transaction.unsigned.value(),
                tx.transaction.unsigned.data().to_vec(),
                gas_limit,
                tx.transaction
                    .unsigned
                    .access_list()
                    .into_iter()
                    .map(|x| (x.address, x.storage_keys))
                    .collect(),
            ),
            TransactionAction::Create => executor.transact_create(
                tx.sender,
                *tx.transaction.unsigned.value(),
                tx.transaction.unsigned.data().to_vec(),
                gas_limit,
                tx.transaction
                    .unsigned
                    .access_list()
                    .into_iter()
                    .map(|x| (x.address, x.storage_keys))
                    .collect(),
            ),
        };

        let remain_gas = executor.gas();
        let gas_used = executor.used_gas();
        let code_address = if tx.transaction.unsigned.action() == &TransactionAction::Create
            && exit_reason.is_succeed()
        {
            Some(crate::code_address(&tx.sender, &old_nonce))
        } else {
            None
        };

        let resp = TxResp {
            exit_reason,
            ret,
            remain_gas,
            gas_used,
            fee_cost: U256::default(),
            logs: vec![],
            code_address,
            removed: false,
        };

        if resp.exit_reason.is_succeed() {
            let (values, logs) = executor.into_state().deconstruct();
            backend.apply(values, logs, true);
        }

        resp
    }
}
