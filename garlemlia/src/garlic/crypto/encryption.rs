use crate::core::constants::{EncryptedData, EncryptionKey, AES_BLOCK_SIZE};
use aes::Aes256;
use cipher;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};
use rand;
use rand::{rng, RngCore};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use std::error::Error;

pub struct Encryption;
impl Encryption {
    pub fn generate_key() -> Result<EncryptionKey, Box<dyn Error>> {
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

    pub fn encrypt_message(
        padded_message: &[u8],
        key: &EncryptionKey,
    ) -> Result<EncryptedData, Box<dyn Error>> {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut ciphertext = padded_message.to_vec();

        for chunk in ciphertext.chunks_exact_mut(AES_BLOCK_SIZE) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
        }

        Ok(ciphertext)
    }

    pub fn encrypt_key(
        key_data: Vec<u8>,
        recipient_pub_key: Option<RsaPublicKey>,
    ) -> Result<Vec<u8>, rsa::Error> {
        Ok(match recipient_pub_key {
            Some(pub_key) => pub_key.encrypt(&mut rand_core::OsRng, Pkcs1v15Encrypt, &key_data)?,
            None => key_data,
        })
    }
}
