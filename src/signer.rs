use std::fmt;

use alloy_consensus::SignableTransaction;
use alloy_primitives::{Address, ChainId, B256};
use alloy_signer::{sign_transaction_with_chain_id, Result, Signature, Signer};
use async_trait::async_trait;

pub struct StrongholdSigner {
    pub(crate) address: Address,
    pub(crate) chain_id: Option<ChainId>,
}

impl fmt::Debug for StrongholdSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrongholdSigner")
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Signer for StrongholdSigner {
    #[inline]
    async fn sign_hash(&self, _hash: &B256) -> Result<Signature> {
        Err(alloy_signer::Error::UnsupportedOperation(
            alloy_signer::UnsupportedSignerOperation::SignHash,
        ))
    }

    #[inline]
    async fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        self.sign_message_using_stronghold(message)
            .await
            .map_err(alloy_signer::Error::other)
    }

    #[inline]
    fn address(&self) -> Address {
        self.address
    }

    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    #[inline]
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl alloy_network::TxSigner<Signature> for StrongholdSigner {
    fn address(&self) -> Address {
        self.address
    }

    #[inline]
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> Result<Signature> {
        sign_transaction_with_chain_id!(self, tx, self.sign_tx_using_stronghold(tx).await)
    }
}

impl StrongholdSigner {
    async fn sign_message_using_stronghold(&self, _message: &[u8]) -> Result<Signature> {
        unimplemented!()
    }

    async fn sign_tx_using_stronghold(
        &self,
        _tx: &dyn SignableTransaction<Signature>,
    ) -> Result<Signature> {
        unimplemented!()
    }
}
