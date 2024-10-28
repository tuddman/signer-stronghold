use std::fmt;

use alloy_consensus::SignableTransaction;
use alloy_primitives::{hex, Address, ChainId, B256};
use alloy_signer::{sign_transaction_with_chain_id, Result, Signature, Signer};
use async_trait::async_trait;
use iota_stronghold::{procedures::KeyType, KeyProvider, Location, SnapshotPath, Stronghold};

const STRONGHOLD_PATH: &str = "signer.stronghold";
const CLIENT_PATH: &[u8] = b"client-path-0";
const VAULT_PATH: &[u8] = b"vault-path";
const RECORD_PATH: &[u8] = b"record-path-0";

pub struct StrongholdSigner {
    pub(crate) address: Address,
    pub(crate) chain_id: Option<ChainId>,
    stronghold: iota_stronghold::Stronghold,
}

impl fmt::Debug for StrongholdSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrongholdSigner")
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StrongholdSignerError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Client(#[from] iota_stronghold::types::ClientError),
    #[error(transparent)]
    Signature(#[from] alloy_primitives::SignatureError),
    #[error(transparent)]
    Procedure(#[from] iota_stronghold::procedures::ProcedureError),
    #[error(transparent)]
    Var(#[from] std::env::VarError),
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
        sign_transaction_with_chain_id!(self, tx, self.sign_hash(&tx.signature_hash()).await)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Signer for StrongholdSigner {
    #[inline]
    async fn sign_hash(&self, hash: &B256) -> Result<Signature> {
        let msg = hash.as_slice();
        self.sign_message_using_stronghold(msg)
            .await
            .map_err(alloy_signer::Error::other)
    }

    //#[inline]
    //async fn sign_message(&self, message: &[u8]) -> Result<Signature> {
    //    self.sign_message_using_stronghold(message)
    //        .await
    //        .map_err(alloy_signer::Error::other)
    //}

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

impl StrongholdSigner {
    pub fn new(chain_id: Option<ChainId>) -> Result<Self, StrongholdSignerError> {
        let master_passphrase = std::env::var("PASSPHRASE")?.as_bytes().to_vec();

        let snapshot_path = SnapshotPath::from_path(STRONGHOLD_PATH);
        let key_provider = KeyProvider::with_passphrase_hashed_blake2b(master_passphrase)?;
        let stronghold = Stronghold::default();

        let init_result =
            stronghold.load_client_from_snapshot(CLIENT_PATH, &key_provider, &snapshot_path);

        let address = match init_result {
            Err(iota_stronghold::ClientError::SnapshotFileMissing(_)) => {
                stronghold.create_client(CLIENT_PATH)?;
                Self::maybe_generate_key(&stronghold, &key_provider, "secp256k1")?;

                stronghold.commit_with_keyprovider(&snapshot_path, &key_provider)?;
                Self::get_evm_address(&stronghold)?
            }
            Err(iota_stronghold::ClientError::ClientAlreadyLoaded(_)) => {
                stronghold.get_client(CLIENT_PATH)?;
                Self::get_evm_address(&stronghold)?
            }
            _ => Self::get_evm_address(&stronghold)?,
        };

        Ok(Self {
            address,
            chain_id,
            stronghold,
        })
    }

    fn maybe_generate_key(
        stronghold: &Stronghold,
        key_provider: &KeyProvider,
        key_type: &str,
    ) -> Result<(), StrongholdSignerError> {
        let ty = match key_type {
            "ed25519" => KeyType::Ed25519,
            "secp256k1" => KeyType::Secp256k1Ecdsa,
            _ => KeyType::Secp256k1Ecdsa,
        };

        let output = Location::const_generic(VAULT_PATH.to_vec(), RECORD_PATH.to_vec());

        let client = stronghold.get_client(CLIENT_PATH)?;
        match client.record_exists(&output) {
            Ok(exists) if exists => {}
            Ok(exists) if !exists => {
                let generate_key_procedure =
                    iota_stronghold::procedures::GenerateKey { ty, output };
                client.execute_procedure(generate_key_procedure)?;
                let snapshot_path = SnapshotPath::from_path(STRONGHOLD_PATH);
                stronghold.commit_with_keyprovider(&snapshot_path, key_provider)?;
            }
            Ok(_) => unreachable!(),
            Err(_e) => {}
        }

        Ok(())
    }

    fn get_evm_address(stronghold: &Stronghold) -> Result<Address, StrongholdSignerError> {
        let client = stronghold.get_client(CLIENT_PATH)?;
        let location = Location::const_generic(VAULT_PATH.to_vec(), RECORD_PATH.to_vec());
        let result = client.execute_procedure(iota_stronghold::procedures::GetEvmAddress {
            private_key: location,
        })?;

        Ok(result.into())
    }

    async fn sign_message_using_stronghold(
        &self,
        message: &[u8],
    ) -> Result<Signature, StrongholdSignerError> {
        let client = self.stronghold.get_client(CLIENT_PATH)?;
        let location = Location::const_generic(VAULT_PATH.to_vec(), RECORD_PATH.to_vec());
        let result = client.execute_procedure(iota_stronghold::procedures::Secp256k1EcdsaSign {
            flavor: iota_stronghold::procedures::Secp256k1EcdsaFlavor::Keccak256,
            msg: message.to_vec(),
            private_key: location,
        })?;

        let signature = Signature::try_from(result.as_slice())?;

        Ok(signature)
    }

    #[allow(dead_code)]
    async fn sign_tx_using_stronghold(
        &self,
        _tx: &mut dyn SignableTransaction<Signature>,
    ) -> Result<Signature> {
        unimplemented!()
    }
}
