use std::fmt;

use alloy_consensus::SignableTransaction;
use alloy_primitives::{hex, Address, ChainId, B256, Signature};
use alloy_signer::{sign_transaction_with_chain_id, Result, Signer};
use async_trait::async_trait;
use crypto::signatures::secp256k1_ecdsa::RecoverableSignature;
use iota_stronghold::{
    procedures::{KeyType, PublicKey as PublickKeyProcedure},
    KeyProvider, Location, SnapshotPath, Stronghold,
};

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
    #[error("invalid recovery value: {0}")]
    InvalidRecoveryValue(u8),
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

alloy_network::impl_into_wallet!(StrongholdSigner);

impl StrongholdSigner {
    /// Create a new StrongholdSigner with an optional chain ID.
    ///
    /// This will read the passphrase from the `PASSPHRASE` environment variable.
    /// If the stronghold snapshot file doesn't exist, it will create a new key.
    pub fn new(chain_id: Option<ChainId>) -> Result<Self, StrongholdSignerError> {
        let passphrase = std::env::var("PASSPHRASE")?.as_bytes().to_vec();

        let snapshot_path = SnapshotPath::from_path(STRONGHOLD_PATH);
        let key_provider = KeyProvider::with_passphrase_hashed_blake2b(passphrase)?;
        let stronghold = Stronghold::default();

        let init_result =
            stronghold.load_client_from_snapshot(CLIENT_PATH, &key_provider, &snapshot_path);

        let address = match init_result {
            Err(iota_stronghold::ClientError::SnapshotFileMissing(_)) => {
                // No snapshot file exists, create a new client and key
                stronghold.create_client(CLIENT_PATH)?;
                Self::maybe_generate_key(&stronghold, &key_provider, KeyType::Secp256k1Ecdsa)?;

                stronghold.commit_with_keyprovider(&snapshot_path, &key_provider)?;
                Self::get_evm_address(&stronghold)?
            }
            Err(iota_stronghold::ClientError::ClientAlreadyLoaded(_)) => {
                // Client already loaded, get the address
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

    /// Creates a new StrongholdSigner from an existing Stronghold instance with the key already in place.
    pub fn from_stronghold(
        stronghold: Stronghold,
        chain_id: Option<ChainId>,
    ) -> Result<Self, StrongholdSignerError> {
        let address = Self::get_evm_address(&stronghold)?;
        
        Ok(Self {
            address,
            chain_id,
            stronghold,
        })
    }

    /// Creates a key if it doesn't already exist in the stronghold vault
    fn maybe_generate_key(
        stronghold: &Stronghold,
        key_provider: &KeyProvider,
        ty: KeyType,
    ) -> Result<(), StrongholdSignerError> {
        let output = Location::const_generic(VAULT_PATH.to_vec(), RECORD_PATH.to_vec());

        let client = stronghold.get_client(CLIENT_PATH)?;
        match client.record_exists(&output) {
            Ok(exists) if exists => {
                // Key already exists, do nothing
            }
            Ok(exists) if !exists => {
                // No key exists, generate one
                let generate_key_procedure =
                    iota_stronghold::procedures::GenerateKey { ty, output };
                client.execute_procedure(generate_key_procedure)?;
                let snapshot_path = SnapshotPath::from_path(STRONGHOLD_PATH);
                stronghold.commit_with_keyprovider(&snapshot_path, key_provider)?;
            }
            Ok(_) => unreachable!(),
            Err(_) => {
                // Handle error by attempting to generate the key
                let generate_key_procedure =
                    iota_stronghold::procedures::GenerateKey { ty, output };
                client.execute_procedure(generate_key_procedure)?;
                let snapshot_path = SnapshotPath::from_path(STRONGHOLD_PATH);
                stronghold.commit_with_keyprovider(&snapshot_path, key_provider)?;
            }
        }

        Ok(())
    }

    /// Gets the Ethereum address associated with the key in stronghold
    fn get_evm_address(stronghold: &Stronghold) -> Result<Address, StrongholdSignerError> {
        let client = stronghold.get_client(CLIENT_PATH)?;
        let private_key = Location::const_generic(VAULT_PATH.to_vec(), RECORD_PATH.to_vec());
        let result = client.execute_procedure(iota_stronghold::procedures::GetEvmAddress {
            private_key
        })?;

        Ok(result.into())
    }

    /// Sign a message using the Stronghold client.
    /// The private key is never exposed outside of Stronghold's secure enclave.
    ///
    /// This returns an alloy_primitives::Signature with the correct format.
    async fn sign_message_using_stronghold(
        &self,
        message: &[u8],
    ) -> Result<Signature, StrongholdSignerError> {
        let client = self.stronghold.get_client(CLIENT_PATH)?;
        let location = Location::const_generic(VAULT_PATH.to_vec(), RECORD_PATH.to_vec());
        
        // Sign the message using the Stronghold secp256k1 ECDSA procedure
        let result: [u8; RecoverableSignature::LENGTH] =
            client.execute_procedure(iota_stronghold::procedures::Secp256k1EcdsaSign {
                flavor: iota_stronghold::procedures::Secp256k1EcdsaFlavor::Keccak256,
                msg: message.to_vec(),
                private_key: location.clone(),
            })?;

        // Convert the IOTA signature format to Alloy Signature format
        let signature = convert_iota_bytes_to_alloy_sig(&result)?;
        Ok(signature)
    }
}

/// Converts an IOTA Stronghold signature to an alloy_primitives::Signature
///
/// IOTA's RecoverableSignature has the form [r (32 bytes) | s (32 bytes) | v (1 byte)]
/// where v is either 0 or 1 (the parity of the y coordinate).
///
/// For Ethereum, the recovery ID (v) needs to be either 27 or 28 for non-EIP155 signatures.
fn convert_iota_bytes_to_alloy_sig(
    iota_bytes: &[u8; RecoverableSignature::LENGTH],
) -> Result<Signature, StrongholdSignerError> {
    // Extract r, s, and v values
    let r = &iota_bytes[0..32];
    let s = &iota_bytes[32..64];
    let v = iota_bytes[64];
    
    // Convert IOTA's v (0 or 1) to Ethereum's v (27 or 28)
    let v_eth = match v {
        0 => 27,
        1 => 28,
        27 | 28 => v, // Already in Ethereum format
        _ => return Err(StrongholdSignerError::InvalidRecoveryValue(v)),
    };
    
    // Create a standard 65-byte Ethereum signature
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..64].copy_from_slice(s);
    sig_bytes[64] = v_eth;
    
    // Use alloy_primitives to create a Signature
    let signature = Signature::try_from(sig_bytes.as_ref())
        .map_err(|e| StrongholdSignerError::Signature(e))?;
    
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address as AlloyAddress, Signature};
    use alloy_consensus::{TxEnvelope, TxLegacy};
    use alloy_network::TxSigner;
    use alloy_primitives::{bytes, U256};
    use alloy_signer::Signer;
    use crypto::signatures::secp256k1_ecdsa::EvmAddress;
    use k256::ecdsa::{signature::Signer as K256Signer, SigningKey};
    use std::str::FromStr;
    use std::{env, fs};

    // Helper to setup test environment
    fn setup_test_env() {
        env::set_var("PASSPHRASE", "test_passphrase_of_sufficient_length");
    }

    // Helper to clean up test environment
    fn cleanup_test_env() {
        env::remove_var("PASSPHRASE");
    }

    #[tokio::test]
    async fn test_initialize_new_signer() {
        setup_test_env();

        let signer = StrongholdSigner::new(Some(1));
        assert!(signer.is_ok(), "Should initialize successfully");

        let signer = signer.unwrap();
        assert!(signer.address != Address::ZERO, "Address should be set");
        assert_eq!(signer.chain_id, Some(1), "Chain ID should match");

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_reinitialize_existing_signer() {
        setup_test_env();

        // First creation
        let signer1 = StrongholdSigner::new(Some(1)).unwrap();
        let address1 = signer1.address;

        // Second creation should load same key
        let signer2 = StrongholdSigner::new(Some(1)).unwrap();
        assert_eq!(signer2.address, address1, "Should load same address");

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_sign_message() {
        setup_test_env();

        let signer = StrongholdSigner::new(Some(1)).unwrap();
        let signer_address = alloy_network::TxSigner::address(&signer);

        let message = b"hello world";
        let signature = signer
            .sign_message(message)
            .await
            .expect("Failed to sign message");

        // Recover address from the signature
        let recovered = signature
            .recover_address_from_msg(message)
            .expect("Failed to recover address");
        assert_eq!(signer_address, recovered);

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_sign_hash() {
        setup_test_env();

        let signer = StrongholdSigner::new(Some(1)).unwrap();
        let message = alloy::primitives::keccak256(b"hello world");
        let hash = B256::from(message);

        let signature = signer.sign_hash(&hash).await;
        assert!(signature.is_ok(), "Should sign hash successfully");

        let sig = signature.unwrap();
        assert!(!sig.r().is_zero(), "r component should be non-zero");
        assert!(!sig.s().is_zero(), "s component should be non-zero");
        
        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_sign_transaction() {
        setup_test_env();

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

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_get_evm_address() {
        setup_test_env();

        let signer = StrongholdSigner::new(Some(1)).unwrap();
        let tx_signer_addr: Address = TxSigner::address(&signer);

        assert_ne!(tx_signer_addr, Address::ZERO, "Address should not be zero");
        assert_eq!(tx_signer_addr.len(), 20, "Address should be 20 bytes");

        let signer_address: Address = alloy_signer::Signer::address(&signer);
        assert_ne!(signer_address, Address::ZERO, "Address should not be zero");
        assert_eq!(signer_address.len(), 20, "Address should be 20 bytes");

        assert_eq!(tx_signer_addr, signer_address, "Addresses should match");

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_chain_id_management() {
        setup_test_env();

        let mut signer = StrongholdSigner::new(Some(1)).unwrap();
        assert_eq!(signer.chain_id(), Some(1));

        signer.set_chain_id(Some(5));
        assert_eq!(signer.chain_id(), Some(5));

        signer.set_chain_id(None);
        assert_eq!(signer.chain_id(), None);

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_missing_passphrase() {
        env::remove_var("PASSPHRASE");

        let result = StrongholdSigner::new(Some(1));
        assert!(result.is_err(), "Should fail without passphrase");
    }

    #[tokio::test]
    async fn test_signer_trait_implementation() {
        setup_test_env();

        let signer = StrongholdSigner::new(Some(1)).unwrap();

        // Test address method
        let address: Address = TxSigner::address(&signer);
        assert_ne!(address, Address::ZERO);

        // Test chain_id method
        assert_eq!(signer.chain_id(), Some(1));

        cleanup_test_env();
    }

    #[tokio::test]
    async fn test_end_to_end_transaction_with_anvil() {
        use alloy::network::EthereumWallet;
        use alloy::node_bindings::Anvil;
        use alloy::providers::{ext::AnvilApi, Provider, ProviderBuilder};
        use alloy_primitives::U256;

        setup_test_env();

        // Create signer (chain_id 1 to match Anvil's default)
        let signer = StrongholdSigner::new(Some(1)).expect("Failed to create signer");
        let sender_address: Address = TxSigner::address(&signer);
        let wallet = EthereumWallet::from(signer.clone());
        println!("Signer        : {:?}", signer);
        println!("Sender address: {:?}", sender_address);
        println!("Wallet        : {:?}", wallet);

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

        // Calculate expected values (very simplified - doesn't account for gas properly)
        let expected_sender_balance = initial_balance - tx_value - U256::from(gas_price * 21000);
        let expected_recipient_balance = tx_value;

        assert!(
            expected_sender_balance > U256::ZERO,
            "Sender balance should be positive"
        );
        assert!(
            sender_balance < initial_balance,
            "Sender balance should decrease"
        );
        assert!(
            recipient_balance >= expected_recipient_balance,
            "Recipient should receive funds"
        );

        cleanup_test_env();
    }
}