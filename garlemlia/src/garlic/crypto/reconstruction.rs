use crate::core::constants::{AES_BLOCK_SIZE, DATA_SHARDS};
use crate::garlic::{Clove, CloveMessage};
use aes::Aes256;
use bincode;
use cipher;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, KeyInit};
use reed_solomon_erasure::galois_8::ReedSolomon;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use std::error::Error;

pub struct Reconstruction;
impl Reconstruction {
    /// Converts two clove fragments into a complete CloveMessage by:
    /// 1. Reconstructing the original message using Reed-Solomon encoding
    /// 2. Decrypting the message key using RSA if a private key is provided
    /// 3. Decrypting the message content using AES
    pub fn clove_to_message(
        clove_1: Clove,
        clove_2: Clove,
        self_priv_key: Option<RsaPrivateKey>,
    ) -> Result<CloveMessage, Box<dyn Error>> {
        let parity_shards = clove_1.ida_count as usize - DATA_SHARDS;
        let reed_solomon = ReedSolomon::new(DATA_SHARDS, parity_shards)?;

        // Reconstruct message and key fragments
        let mut message_shards = Reconstruction::initialize_shards(parity_shards + DATA_SHARDS);
        let mut key_shards = Reconstruction::initialize_shards(parity_shards + DATA_SHARDS);

        message_shards[clove_1.index as usize] = Some(clove_1.msg_fragment);
        message_shards[clove_2.index as usize] = Some(clove_2.msg_fragment);
        key_shards[clove_1.index as usize] = Some(clove_1.key_fragment);
        key_shards[clove_2.index as usize] = Some(clove_2.key_fragment);

        reed_solomon.reconstruct(&mut message_shards)?;
        reed_solomon.reconstruct(&mut key_shards)?;

        let encrypted_data = Reconstruction::collect_shard_data(&message_shards);
        let mut decryption_key = Reconstruction::collect_shard_data(&key_shards);

        // Decrypt the message key if a private key is provided
        if let Some(private_key) = self_priv_key {
            decryption_key = private_key.decrypt(Pkcs1v15Encrypt, &decryption_key)?;
        }

        // Decrypt the message content
        let decrypted_data = Reconstruction::decrypt_aes(&encrypted_data, &decryption_key)?;

        Ok(bincode::deserialize(&decrypted_data)?)
    }

    /// Creates a vector of None values with a given capacity
    pub fn initialize_shards(capacity: usize) -> Vec<Option<Vec<u8>>> {
        vec![None; capacity]
    }

    /// Collects and flattens shard data from first DATA_SHARDS shards
    pub fn collect_shard_data(shards: &[Option<Vec<u8>>]) -> Vec<u8> {
        shards
            .iter()
            .take(DATA_SHARDS)
            .filter_map(|s| s.as_ref())
            .flatten()
            .copied()
            .collect()
    }

    /// Decrypts data using AES-256 in ECB mode and removes padding
    pub fn decrypt_aes(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut decrypted = encrypted_data.to_vec();

        // Decrypt blocks
        for chunk in decrypted.chunks_exact_mut(AES_BLOCK_SIZE) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
        }

        // Remove PKCS7 padding
        let padding_len = *decrypted.last().ok_or("Empty decrypted data")? as usize;
        Ok(decrypted[..decrypted.len() - padding_len].to_vec())
    }
}
