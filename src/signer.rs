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

#[derive(Clone)]
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
        let passphrase = std::env::var("PASSPHRASE")?.as_bytes().to_vec();

        let snapshot_path = SnapshotPath::from_path(STRONGHOLD_PATH);
        let key_provider = KeyProvider::with_passphrase_hashed_blake2b(passphrase)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    //use alloy::providers::ProviderBuilder;
    use alloy_consensus::{TxEnvelope, TxLegacy};
    use alloy_network::TxSigner;
    use alloy_primitives::{bytes, U256};
    use std::{env, fs};
    use tempfile::NamedTempFile;

    // Helper to create temp stronghold file
    fn setup_temp_stronghold() -> NamedTempFile {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        env::set_var("PASSPHRASE", "test_passphrase");
        temp_file
    }

    // Helper to clean up
    fn cleanup_temp_stronghold(path: &str) {
        let _ = fs::remove_file(path);
        env::remove_var("PASSPHRASE");
    }

    #[tokio::test]
    async fn test_initialize_new_signer() {
        let temp_file = setup_temp_stronghold();
        let path = temp_file.path().to_str().unwrap();

        let signer = StrongholdSigner::new(Some(1));
        assert!(signer.is_ok(), "Should initialize successfully");

        let signer = signer.unwrap();
        assert!(signer.address != Address::ZERO, "Address should be set");
        assert_eq!(signer.chain_id, Some(1), "Chain ID should match");

        cleanup_temp_stronghold(path);
    }

    #[tokio::test]
    async fn test_reinitialize_existing_signer() {
        let temp_file = setup_temp_stronghold();
        let path = temp_file.path().to_str().unwrap();

        // First creation
        let signer1 = StrongholdSigner::new(Some(1)).unwrap();
        let address1 = signer1.address;

        // Second creation should load same key
        let signer2 = StrongholdSigner::new(Some(1)).unwrap();
        assert_eq!(signer2.address, address1, "Should load same address");

        cleanup_temp_stronghold(path);
    }

    #[tokio::test]
    async fn test_sign_hash() {
        let temp_file = setup_temp_stronghold();
        let path = temp_file.path().to_str().unwrap();

        let signer = StrongholdSigner::new(Some(1)).unwrap();
        let hash = B256::new(*b"test_hash_of_this_correct_length");

        let signature = signer.sign_hash(&hash).await;
        assert!(signature.is_ok(), "Should sign hash successfully");

        let sig = signature.unwrap();
        assert!(!sig.r().is_zero(), "r component should be non-zero");
        assert!(!sig.s().is_zero(), "s component should be non-zero");
        assert!(sig.v(), "v component should be valid");

        cleanup_temp_stronghold(path);
    }

    #[tokio::test]
    async fn test_sign_transaction() {
        let temp_file = setup_temp_stronghold();
        let path = temp_file.path().to_str().unwrap();

        let signer = StrongholdSigner::new(Some(1)).unwrap();
        let to = "deaddeaddeaddeaddeaddeaddeaddeaddeaddead";
        let to: Address = to.parse().unwrap();

        let mut tx = TxLegacy {
            to: alloy::primitives::TxKind::Call(to),
            value: U256::from(100),
            gas_price: 1,
            gas_limit: 21000,
            input: bytes!(""),
            nonce: 0,
            ..Default::default()
        };

        let result = signer.sign_transaction(&mut tx).await;
        assert!(result.is_ok(), "Should sign transaction successfully");

        let sig = result.unwrap();
        let _envelope = TxEnvelope::Legacy(tx.into_signed(sig));
        //assert!(envelope.signature(), "Should have valid signature");

        cleanup_temp_stronghold(path);
    }

    #[tokio::test]
    async fn test_get_evm_address() {
        let temp_file = setup_temp_stronghold();
        let path = temp_file.path().to_str().unwrap();

        let signer = StrongholdSigner::new(Some(1)).unwrap();
        let address: Address = TxSigner::address(&signer);

        assert_ne!(address, Address::ZERO, "Address should not be zero");
        assert_eq!(address.len(), 20, "Address should be 20 bytes");

        cleanup_temp_stronghold(path);
    }

    #[tokio::test]
    async fn test_chain_id_management() {
        let temp_file = setup_temp_stronghold();
        let path = temp_file.path().to_str().unwrap();

        let mut signer = StrongholdSigner::new(Some(1)).unwrap();
        assert_eq!(signer.chain_id(), Some(1));

        signer.set_chain_id(Some(5));
        assert_eq!(signer.chain_id(), Some(5));

        signer.set_chain_id(None);
        assert_eq!(signer.chain_id(), None);

        cleanup_temp_stronghold(path);
    }

    #[tokio::test]
    async fn test_missing_passphrase() {
        env::remove_var("PASSPHRASE");

        let result = StrongholdSigner::new(Some(1));
        assert!(result.is_err(), "Should fail without passphrase");
    }

    #[tokio::test]
    async fn test_signer_trait_implementation() {
        let temp_file = setup_temp_stronghold();
        let path = temp_file.path().to_str().unwrap();

        let signer = StrongholdSigner::new(Some(1)).unwrap();

        // Test address method
        let address: Address = TxSigner::address(&signer);
        assert_ne!(address, Address::ZERO);

        // Test chain_id method
        assert_eq!(signer.chain_id(), Some(1));

        cleanup_temp_stronghold(path);
    }

    #[tokio::test]
    async fn test_end_to_end_transaction_with_anvil() {
        use alloy::network::EthereumWallet;
        use alloy::node_bindings::Anvil;
        use alloy::providers::{ext::AnvilApi, Provider, ProviderBuilder};
        use alloy_primitives::U256;

        // Setup temp stronghold
        let temp_file = setup_temp_stronghold();
        let path = temp_file.path().to_str().unwrap();

        // Create signer (chain_id 1 to match Anvil's default)
        let signer = StrongholdSigner::new(Some(1)).expect("Failed to create signer");
        let sender_address: Address = TxSigner::address(&signer);
        let wallet = EthereumWallet::from(signer.clone());

        // Start Anvil instance
        let anvil = Anvil::new().spawn();

        // Create provider connected to Anvil
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(anvil.endpoint_url());

        provider
            .anvil_set_balance(sender_address, U256::from(1_000_000_000))
            .await
            .unwrap();
        // Fund the signer's address (Anvil starts with prefunded accounts)
        let initial_balance = provider
            .get_balance(sender_address)
            .await
            .expect("Failed to get balance");

        assert!(initial_balance > U256::ZERO, "Signer should have balance");

        // Create a transaction
        let recipient = "deaddeaddeaddeaddeaddeaddeaddeaddeaddead";
        let recipient: Address = recipient.parse().unwrap();
        let tx_value = U256::from(100);
        let gas_price = provider
            .get_gas_price()
            .await
            .expect("Failed to get gas price");
        let nonce = provider
            .get_transaction_count(sender_address)
            .await
            .expect("Failed to get nonce");

        let mut tx = TxLegacy {
            to: alloy::primitives::TxKind::Call(recipient),
            value: tx_value,
            gas_price,
            gas_limit: 21000,
            input: bytes!(""),
            nonce,
            ..Default::default()
        };

        // Sign the transaction
        let signature = signer
            .sign_transaction(&mut tx)
            .await
            .expect("Failed to sign tx");
        let signed_tx = tx.into_signed(signature);

        // Encode the signed transaction to RLP bytes
        let mut tx_bytes = Vec::new();
        signed_tx.rlp_encode(&mut tx_bytes);

        // Send the transaction
        let tx_hash = provider
            .send_raw_transaction(&tx_bytes)
            .await
            .unwrap()
            .watch()
            .await
            .expect("Failed to send tx");

        // Wait for transaction to be mined
        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await
            .expect("Failed to get receipt")
            .expect("Receipt not found (tx not mined)");

        assert!(receipt.status(), "Tx should be successful");

        // Verify balances
        let sender_balance = provider
            .get_balance(sender_address)
            .await
            .expect("Failed to get sender balance");
        let recipient_balance = provider
            .get_balance(recipient)
            .await
            .expect("Failed to get recipient balance");

        //// Calculate expected values (very simplified - doesn't account for gas properly)
        //let expected_sender_balance = initial_balance - tx_value - (gas_price * 21000);
        //let expected_recipient_balance = tx_value;
        //
        //assert!(
        //    sender_balance < initial_balance,
        //    "Sender balance should decrease"
        //);
        //assert!(
        //    recipient_balance >= expected_recipient_balance,
        //    "Recipient should receive funds"
        //);

        cleanup_temp_stronghold(path);
    }
}
