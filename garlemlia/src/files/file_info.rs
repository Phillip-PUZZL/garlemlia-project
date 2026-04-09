use crate::core::ids::u256_random;
use crate::data::garlemlia_protocol::InitialChunkInfo;
use crate::time::time_based_hash::HashLocation;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use primitive_types::U256;
use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileInfo {
    request_id: U256,
    pub name: String,
    pub file_type: String,
    pub size: usize,
    downloaded: usize,
    pub categories: Vec<String>,
    pub metadata_location: Vec<HashLocation>,
    pub key_location: Vec<HashLocation>,
    pub(crate) file_id: Option<U256>,
    enc_file_id: Option<U256>,
    decryption_key: Option<String>,
    downloaded_chunks: Vec<InitialChunkInfo>,
    pub(crate) needed_chunks: Vec<InitialChunkInfo>,
    all_chunks: Vec<InitialChunkInfo>,
}

impl FileInfo {
    pub fn new(name: String, file_type: String, size: usize, categories: Vec<String>) -> FileInfo {
        FileInfo {
            request_id: u256_random(),
            name,
            file_type,
            size,
            downloaded: 0,
            categories,
            metadata_location: vec![],
            key_location: vec![],
            file_id: None,
            enc_file_id: None,
            decryption_key: None,
            downloaded_chunks: vec![],
            needed_chunks: vec![],
            all_chunks: vec![],
        }
    }

    pub fn from(
        name: String,
        file_type: String,
        size: usize,
        categories: Vec<String>,
        metadata_location: Vec<HashLocation>,
        key_location: Vec<HashLocation>,
    ) -> FileInfo {
        FileInfo {
            request_id: u256_random(),
            name,
            file_type,
            size,
            downloaded: 0,
            categories,
            metadata_location,
            key_location,
            file_id: None,
            enc_file_id: None,
            decryption_key: None,
            downloaded_chunks: vec![],
            needed_chunks: vec![],
            all_chunks: vec![],
        }
    }

    pub fn set_request_id(&mut self, request_id: U256) {
        self.request_id = request_id;
    }

    pub fn get_request_id(&self) -> U256 {
        self.request_id
    }

    pub fn set_chunk_info(&mut self, chunks: Vec<InitialChunkInfo>) {
        self.needed_chunks = chunks.clone();
        self.all_chunks = chunks;
    }

    pub fn set_file_id(&mut self, file_id: U256) {
        self.file_id = Some(file_id);
    }

    pub fn set_enc_file_id(&mut self, enc_file_id: U256) {
        self.enc_file_id = Some(enc_file_id);
    }

    pub fn set_decryption_key(&mut self, decryption_key: String) {
        self.decryption_key = Some(decryption_key);
    }

    pub fn add_downloaded(&mut self, chunk_id: U256) {
        for i in 0..self.needed_chunks.len() {
            if self.needed_chunks[i].chunk_id == chunk_id {
                self.downloaded_chunks.push(self.needed_chunks[i].clone());
                self.downloaded += self.needed_chunks[i].size;
                self.needed_chunks.remove(i);
                break;
            }
        }
    }

    pub async fn assemble(&self, chunk_files_path: Box<Path>) -> Result<String, (u8, String)> {
        if !self.needed_chunks.is_empty() {
            return Err((0, "Do not have all file chunks".to_string()));
        }

        if self.downloaded_chunks.len() != self.all_chunks.len() {
            return Err((
                1,
                "Downloaded chunks count is not equivalent to all chunks listed".to_string(),
            ));
        }

        let mut chunks_ordered = self.all_chunks.clone();
        chunks_ordered.sort_by_key(|c| c.index);

        let encrypted_file_location = if self.file_type.is_empty() {
            format!("{}/{}.enc", chunk_files_path.to_str().unwrap(), self.name)
        } else {
            format!(
                "{}/{}.{}.enc",
                chunk_files_path.to_str().unwrap(),
                self.name,
                self.file_type
            )
        };

        let encrypted_file_path = Path::new(&encrypted_file_location);
        if encrypted_file_path.exists() {
            return Err((
                2,
                format!("File at {} already exists", encrypted_file_location),
            ));
        }

        let mut encrypted_file = File::create(encrypted_file_path).await.map_err(|_| {
            (
                5,
                format!("Could not create file {}", encrypted_file_location),
            )
        })?;

        for chunk in &chunks_ordered {
            let chunk_file_name = hex::encode(chunk.chunk_id.to_big_endian());
            let chunk_file_location =
                format!("{}/{}", chunk_files_path.to_str().unwrap(), chunk_file_name);

            let mut chunk_file = File::open(&chunk_file_location).await.map_err(|_| {
                (
                    3,
                    format!("Could not find chunk with ID {}", chunk_file_name),
                )
            })?;

            let mut chunk_data = Vec::new();
            chunk_file.read_to_end(&mut chunk_data).await.map_err(|_| {
                (
                    4,
                    format!(
                        "Could not read chunk data from file {}",
                        chunk_file_location
                    ),
                )
            })?;

            encrypted_file.write_all(&chunk_data).await.map_err(|_| {
                (
                    5,
                    format!("Could not write to file {}", encrypted_file_location),
                )
            })?;
        }

        for chunk in &chunks_ordered {
            let chunk_file_name = hex::encode(chunk.chunk_id.to_big_endian());
            let chunk_file_location =
                format!("{}/{}", chunk_files_path.to_str().unwrap(), chunk_file_name);

            fs::remove_file(&chunk_file_location).await.map_err(|_| {
                (
                    6,
                    format!("Could not delete chunk file {}", chunk_file_location),
                )
            })?;
        }

        Ok(encrypted_file_location)
    }

    pub async fn decrypt(
        &self,
        encrypted_file_path: Box<Path>,
        output_folder: Box<Path>,
    ) -> Result<String, (u8, String)> {
        let file_id = self.file_id.ok_or((0, "No file id found".to_string()))?;
        let enc_file_id = self
            .enc_file_id
            .ok_or((1, "No encrypted file id found".to_string()))?;
        let decryption_key = self
            .decryption_key
            .clone()
            .ok_or((2, "No decryption key found".to_string()))?;

        let file_location = if self.file_type.is_empty() {
            format!("{}/{}", output_folder.to_str().unwrap(), self.name)
        } else {
            format!(
                "{}/{}.{}",
                output_folder.to_str().unwrap(),
                self.name,
                self.file_type
            )
        };

        let mut encrypted_file = File::open(encrypted_file_path.clone())
            .await
            .map_err(|_| (3, "Failed to open encrypted file".to_string()))?;

        let mut encrypted_data = Vec::new();
        encrypted_file
            .read_to_end(&mut encrypted_data)
            .await
            .map_err(|_| (4, "Failed to read encrypted file".to_string()))?;

        {
            let mut hasher = Sha256::new();
            hasher.update(&encrypted_data);
            let hash = hasher.finalize();

            if U256::from_big_endian(&hash) != enc_file_id {
                return Err((5, "Encrypted file hash mismatch".to_string()));
            }
        }

        if encrypted_data.len() < 12 {
            return Err((
                6,
                "Encrypted file is too small to contain a nonce".to_string(),
            ));
        }

        let nonce_bytes = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];

        let key_bytes = hex::decode(&decryption_key)
            .map_err(|_| (7, "Invalid decryption key (hex decode failed)".to_string()))?;

        if key_bytes.len() != 32 {
            return Err((8, "Decryption key is not 32 bytes".to_string()));
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| (9, "Failed to decrypt file".to_string()))?;

        {
            let mut hasher = Sha256::new();
            hasher.update(&plaintext);
            let hash = hasher.finalize();

            if U256::from_big_endian(&hash) != file_id {
                return Err((10, "Decrypted file hash mismatch".to_string()));
            }
        }

        let mut out = File::create(&file_location)
            .await
            .map_err(|_| (11, "Failed to create output file".to_string()))?;

        out.write_all(&plaintext)
            .await
            .map_err(|_| (12, "Failed to write decrypted file".to_string()))?;

        fs::remove_file(encrypted_file_path.clone())
            .await
            .map_err(|_| {
                (
                    13,
                    format!(
                        "Could not delete encrypted file {}",
                        encrypted_file_path.to_str().unwrap()
                    ),
                )
            })?;

        Ok(file_location)
    }

    pub fn to_string(&self) -> String {
        let mut output = format!(
            "{{\n\tName: {}\n\tType: {}\n\tSize: {}\n\tDownloaded: {}\n\tCategories: [\n",
            self.name, self.file_type, self.size, self.downloaded
        );
        for item in self.categories.clone() {
            output.push_str(format!("\t\t{}", item).as_str());
        }
        output.push_str(
            format!(
                "\t]\n\tChunks Downloaded: {}\n\tChunks Needed: {}\n}}",
                self.downloaded_chunks.len(),
                self.needed_chunks.len()
            )
            .as_str(),
        );

        output
    }
}

pub struct FileInformation {
    pub(crate) id: U256,
    pub name: String,
    pub file_type: String,
    pub(crate) size: usize,
    pub(crate) categories: Vec<String>,
    pub(crate) file_id: U256,
    pub(crate) enc_file_id: U256,
    pub(crate) decryption_key: String,
}
