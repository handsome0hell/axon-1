use ckb_types::{bytes::Bytes, core::cell::CellMeta, packed, prelude::*};
use rlp::{RlpDecodable, RlpEncodable};

use protocol::types::{MerkleRoot, H256};

use crate::system_contract::error::{SystemScriptError, SystemScriptResult};
use crate::system_contract::image_cell::trie_db::RocksTrieDB;
use crate::system_contract::image_cell::MPTTrie;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellKey {
    pub tx_hash: H256,
    pub index:   u32,
}

impl From<&packed::OutPoint> for CellKey {
    fn from(out_point: &packed::OutPoint) -> Self {
        CellKey {
            tx_hash: H256(out_point.tx_hash().unpack().0),
            index:   out_point.index().unpack(),
        }
    }
}

impl CellKey {
    const ENCODED_LEN: usize = 32 + 4;

    pub fn new(tx_hash: [u8; 32], index: u32) -> Self {
        let tx_hash = H256(tx_hash);
        CellKey { tx_hash, index }
    }

    pub fn decode(input: &[u8]) -> SystemScriptResult<Self> {
        if input.len() != Self::ENCODED_LEN {
            return Err(SystemScriptError::DataLengthMismatch {
                expect: Self::ENCODED_LEN,
                actual: input.len(),
            });
        }

        let tx_hash = H256::from_slice(&input[0..32]);
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&input[32..36]);
        let index = u32::from_le_bytes(buf);

        Ok(CellKey { tx_hash, index })
    }

    pub fn encode(&self) -> Bytes {
        let mut ret = Vec::with_capacity(Self::ENCODED_LEN);
        ret.extend_from_slice(&self.tx_hash.0);
        ret.extend_from_slice(&self.index.to_le_bytes());
        ret.into()
    }
}

#[derive(RlpEncodable, RlpDecodable)]
pub struct CellInfo {
    pub cell_output:     Bytes, // packed::CellOutput
    pub cell_data:       Bytes,
    pub created_number:  u64,
    pub consumed_number: Option<u64>,
}

impl CellInfo {
    pub fn into_meta(self, out_point: &packed::OutPoint) -> CellMeta {
        CellMeta {
            cell_output:        packed::CellOutput::new_unchecked(self.cell_output),
            out_point:          out_point.clone(),
            transaction_info:   None,
            data_bytes:         self.cell_data.len() as u64,
            mem_cell_data_hash: Some(cell_data_hash(&self.cell_data)),
            mem_cell_data:      Some(self.cell_data),
        }
    }
}

pub fn commit(mpt: &mut MPTTrie<RocksTrieDB>) -> SystemScriptResult<MerkleRoot> {
    mpt.commit()
        .map_err(|e| SystemScriptError::CommitError(e.to_string()))
}

pub fn insert_header(
    mpt: &mut MPTTrie<RocksTrieDB>,
    key: &H256,
    header: &packed::Header,
) -> SystemScriptResult<()> {
    mpt.insert(&key.0, &header.as_bytes())
        .map_err(|e| SystemScriptError::InsertHeader(e.to_string()))
}

pub fn remove_header(mpt: &mut MPTTrie<RocksTrieDB>, key: &H256) -> SystemScriptResult<()> {
    mpt.remove(&key.0)
        .map_err(|e| SystemScriptError::RemoveHeader(e.to_string()))
}

pub fn get_header(
    mpt: &MPTTrie<RocksTrieDB>,
    key: &H256,
) -> SystemScriptResult<Option<packed::Header>> {
    let header = match mpt.get(&key.0) {
        Ok(n) => match n {
            Some(n) => n,
            None => return Ok(None),
        },
        Err(e) => return Err(SystemScriptError::GetHeader(e.to_string())),
    };

    Ok(Some(
        packed::Header::from_slice(&header).map_err(SystemScriptError::MoleculeVerification)?,
    ))
}

pub fn insert_cell(
    mpt: &mut MPTTrie<RocksTrieDB>,
    key: &CellKey,
    cell: &CellInfo,
) -> SystemScriptResult<()> {
    mpt.insert(&key.encode(), &rlp::encode(cell))
        .map_err(|e| SystemScriptError::InsertCell(e.to_string()))
}

pub fn remove_cell(mpt: &mut MPTTrie<RocksTrieDB>, key: &CellKey) -> SystemScriptResult<()> {
    mpt.remove(&key.encode())
        .map_err(|e| SystemScriptError::RemoveCell(e.to_string()))
}

pub fn get_cell(mpt: &MPTTrie<RocksTrieDB>, key: &CellKey) -> SystemScriptResult<Option<CellInfo>> {
    let cell = match mpt.get(&key.encode()) {
        Ok(n) => match n {
            Some(n) => n,
            None => return Ok(None),
        },
        Err(e) => return Err(SystemScriptError::GetCell(e.to_string())),
    };

    Ok(Some(
        rlp::decode(&cell).map_err(SystemScriptError::DecodeCell)?,
    ))
}

fn cell_data_hash(data: &Bytes) -> packed::Byte32 {
    if !data.is_empty() {
        return ckb_hash::blake2b_256(data).pack();
    }

    packed::Byte32::zero()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_key_codec() {
        for _ in 0..10 {
            let cell_key = CellKey {
                tx_hash: H256::random(),
                index:   random(),
            };

            assert_eq!(CellKey::decode(&cell_key.encode()).unwrap(), cell_key);
        }
    }
}
