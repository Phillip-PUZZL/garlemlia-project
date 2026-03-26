use aes::Aes256;
use bincode;
use chrono::Utc;
use cipher;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use primitive_types::U256;
use rand;
use rand::{rng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::error::Error;
use crate::structs::constants::{EncryptedData, EncryptionKey, AES_BLOCK_SIZE, DATA_SHARDS, PROXY_SEND_ERROR_BOTH, PROXY_SEND_ERROR_NEIGHBOR1, PROXY_SEND_ERROR_NEIGHBOR2};
use crate::structs::garlic_message::{Clove, CloveMessage, CloveRequestID};

/// Converts two clove fragments into a complete CloveMessage by:
/// 1. Reconstructing the original message using Reed-Solomon encoding
/// 2. Decrypting the message key using RSA if a private key is provided
/// 3. Decrypting the message content using AES
pub fn clove_to_message(clove_1: Clove, clove_2: Clove, self_priv_key: Option<RsaPrivateKey>) -> Result<CloveMessage, Box<dyn Error>> {
    let parity_shards = clove_1.ida_count as usize - DATA_SHARDS;
    let reed_solomon = ReedSolomon::new(DATA_SHARDS, parity_shards)?;

    // Reconstruct message and key fragments
    let mut message_shards = initialize_shards(parity_shards + DATA_SHARDS);
    let mut key_shards = initialize_shards(parity_shards + DATA_SHARDS);

    message_shards[clove_1.index as usize] = Some(clove_1.msg_fragment);
    message_shards[clove_2.index as usize] = Some(clove_2.msg_fragment);
    key_shards[clove_1.index as usize] = Some(clove_1.key_fragment);
    key_shards[clove_2.index as usize] = Some(clove_2.key_fragment);

    reed_solomon.reconstruct(&mut message_shards)?;
    reed_solomon.reconstruct(&mut key_shards)?;

    let encrypted_data = collect_shard_data(&message_shards);
    let mut decryption_key = collect_shard_data(&key_shards);

    // Decrypt the message key if a private key is provided
    if let Some(private_key) = self_priv_key {
        decryption_key = private_key.decrypt(Pkcs1v15Encrypt, &decryption_key)?;
    }

    // Decrypt the message content
    let decrypted_data = decrypt_aes(&encrypted_data, &decryption_key)?;

    Ok(bincode::deserialize(&decrypted_data)?)
}

/// Creates a vector of None values with a given capacity
pub fn initialize_shards(capacity: usize) -> Vec<Option<Vec<u8>>> {
    vec![None; capacity]
}

/// Collects and flattens shard data from first DATA_SHARDS shards
pub fn collect_shard_data(shards: &[Option<Vec<u8>>]) -> Vec<u8> {
    shards.iter()
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
pub fn generate_encryption_key() -> Result<EncryptionKey, Box<dyn Error>> {
    let mut key = [0u8; 32];
    rng().fill_bytes(&mut key);
    Ok(key)
}

pub fn pad_message(message: &[u8]) -> Vec<u8> {
    let mut padded_message = message.to_vec();
    let pad_len = AES_BLOCK_SIZE - (padded_message.len() % AES_BLOCK_SIZE);
    padded_message.extend(vec![pad_len as u8; pad_len]);
    padded_message
}

pub fn encrypt_message(padded_message: &[u8], key: &EncryptionKey) -> Result<EncryptedData, Box<dyn Error>> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut ciphertext = padded_message.to_vec();

    for chunk in ciphertext.chunks_exact_mut(AES_BLOCK_SIZE) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }

    Ok(ciphertext)
}

pub fn encrypt_key(key_data: Vec<u8>, recipient_pub_key: Option<RsaPublicKey>) -> Result<Vec<u8>, rsa::Error> {
    Ok(match recipient_pub_key {
        Some(pub_key) => pub_key.encrypt(&mut rand_core::OsRng, Pkcs1v15Encrypt, &key_data)?,
        None => key_data,
    })
}

pub fn generate_reed_solomon_shards(
    data: Vec<u8>,
    key_data: Vec<u8>,
    count: u8,
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), reed_solomon_erasure::Error> {
    let parity_shards = count as usize - DATA_SHARDS;
    let total_shards = DATA_SHARDS + parity_shards;
    let reed_solomon = ReedSolomon::new(DATA_SHARDS, parity_shards)?;

    let data_shard_size = (data.len() + DATA_SHARDS - 1) / DATA_SHARDS;
    let key_shard_size = (key_data.len() + DATA_SHARDS - 1) / DATA_SHARDS;

    let mut data_shards = vec![vec![0; data_shard_size]; total_shards];
    let mut key_shards = vec![vec![0; key_shard_size]; total_shards];

    // Fill data shards
    for (i, chunk) in data.chunks(data_shard_size).enumerate().take(DATA_SHARDS) {
        data_shards[i][..chunk.len()].copy_from_slice(chunk);
    }

    // Fill key shards
    for (i, chunk) in key_data.chunks(key_shard_size).enumerate().take(DATA_SHARDS) {
        key_shards[i][..chunk.len()].copy_from_slice(chunk);
    }

    reed_solomon.encode(&mut data_shards)?;
    reed_solomon.encode(&mut key_shards)?;

    Ok((data_shards, key_shards))
}

pub fn generate_cloves(
    sequence_number: U256,
    request_id: CloveRequestID,
    data_shards: Vec<Vec<u8>>,
    key_shards: Vec<Vec<u8>>,
    send_count: u8,
    ida_count: u8,
) -> Result<Vec<Clove>, Box<dyn Error>> {
    Ok((0..send_count as usize)
        .map(|i| Clove {
            sequence_number,
            request_id: request_id.clone(),
            msg_fragment: data_shards[i].clone(),
            key_fragment: key_shards[i].clone(),
            sent: Utc::now(),
            index: i as u8,
            ida_count,
        })
        .collect())
}

pub fn send_error_neighbor1(forward_type: u8) -> bool {
    forward_type == PROXY_SEND_ERROR_NEIGHBOR1 || forward_type == PROXY_SEND_ERROR_BOTH
}

pub fn send_error_neighbor2(forward_type: u8) -> bool {
    forward_type == PROXY_SEND_ERROR_NEIGHBOR2 || forward_type == PROXY_SEND_ERROR_BOTH
}