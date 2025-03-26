use crate::garlemlia_structs::garlemlia_structs::{u256_random, ChunkInfo};
use crate::time_hash::time_based_hash::RotatingHash;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use primitive_types::U256;
use rand::RngCore;
use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    id: U256,
    name: String,
    file_type: String,
    size: usize,
    downloaded: usize,
    categories: Vec<String>,
    file_id: Option<U256>,
    enc_file_id: Option<U256>,
    decryption_key: Option<String>,
    downloaded_chunks: Vec<ChunkInfo>,
    needed_chunks: Vec<ChunkInfo>,
    all_chunks: Vec<ChunkInfo>
}

impl FileInfo {
    pub fn new(id: U256, name: String, file_type: String, size: usize, categories: Vec<String>) -> FileInfo {
        FileInfo {
            id,
            name,
            file_type,
            size,
            downloaded: 0,
            categories,
            file_id: None,
            enc_file_id: None,
            decryption_key: None,
            downloaded_chunks: vec![],
            needed_chunks: vec![],
            all_chunks: vec![],
        }
    }

    pub fn set_chunk_info(&mut self, chunks: Vec<ChunkInfo>) {
        self.needed_chunks = chunks.clone();
        self.all_chunks = chunks;
    }

    pub fn set_file_id(&mut self, file_id: U256) {
        self.file_id = Some(file_id);
    }

    pub fn set_downloaded(&mut self, downloaded: usize) {
        self.downloaded = downloaded;
    }

    pub fn set_enc_file_id(&mut self, enc_file_id: U256) {
        self.enc_file_id = Some(enc_file_id);
    }

    pub fn set_decryption_key(&mut self, decryption_key: String) {
        self.decryption_key = Some(decryption_key);
    }

    pub fn add_downloaded(&mut self, chunk: ChunkInfo) {
        self.downloaded_chunks.push(chunk.clone());
        for i in 0..self.needed_chunks.len() {
            if self.needed_chunks[i].chunk_id == chunk.chunk_id {
                self.needed_chunks.remove(i);
                break;
            }
        }
    }

    pub async fn assemble(&self, chunk_files_path: Box<Path>) -> Result<String, (u8, String)> {
        let file_id;
        let enc_file_id;
        match self.file_id {
            Some(self_file_id) => {
                file_id = self_file_id;
            }
            _ => {
                return Err((0, "No file id found".to_string()));
            }
        }
        match self.enc_file_id {
            Some(self_enc_file_id) => {
                enc_file_id = self_enc_file_id;
            }
            _ => {
                return Err((1, "No encrypted file id found".to_string()));
            }
        }
        if self.needed_chunks.len() > 0 {
            return Err((2, "Do not have all file chunks".to_string()));
        }
        if self.downloaded_chunks.len() != self.all_chunks.len() {
            return Err((3, "Downloaded chunks count is not equivalent to all chunks listed".to_string()));
        }

        let mut chunks_ordered = self.all_chunks.clone();
        chunks_ordered.sort_by_key(|c| c.index);

        let encrypted_file_location;
        if self.file_type != "" {
            encrypted_file_location = format!("{}/{}.{}.enc", chunk_files_path.to_str().unwrap(), self.name, self.file_type);
        } else {
            encrypted_file_location = format!("{}/{}.enc", chunk_files_path.to_str().unwrap(), self.name);
        }

        let encrypted_file_path = Path::new(&encrypted_file_location);
        if encrypted_file_path.exists() {
            return Err((4, format!("File at {} already exists", encrypted_file_location)));
        }

        let mut encrypted_file = File::create(encrypted_file_path).await.unwrap();
        for chunk in chunks_ordered {
            let chunk_file_name = hex::encode(chunk.chunk_id.to_big_endian());

            let chunk_file_location = format!("{}/{}", chunk_files_path.to_str().unwrap(), chunk_file_name);
            let chunk_file_res = File::open(chunk_file_location.clone()).await;
            if chunk_file_res.is_err() {
                return Err((5, format!("Could not find chunk with ID {}", chunk_file_name)));
            }
            let mut chunk_file = chunk_file_res.unwrap();

            let mut chunk_data = Vec::new();
            let chunk_file_read = chunk_file.read_to_end(&mut chunk_data).await;

            if chunk_file_read.is_err() {
                return Err((6, format!("Could not read chunk data from file {}", chunk_file_location)));
            }

            let enc_file_write = encrypted_file.write_all(&chunk_data).await;

            if enc_file_write.is_err() {
                return Err((7, format!("Could not write to file {}", encrypted_file_location)));
            }

            let chunk_delete = fs::remove_file(chunk_file_location.clone()).await;

            if chunk_delete.is_err() {
                return Err((8, format!("Could not delete chunk file {}", chunk_file_location)));
            }
        }

        Ok(encrypted_file_location)
    }

    pub async fn decrypt(&self, encrypted_file_path: Box<Path>, output_folder: Box<Path>) -> Result<String, (u8, String)> {
        let file_id;
        let enc_file_id;
        let decryption_key;
        match self.file_id {
            Some(self_file_id) => {
                file_id = self_file_id;
            }
            _ => {
                return Err((0, "No file id found".to_string()));
            }
        }
        match self.enc_file_id {
            Some(self_enc_file_id) => {
                enc_file_id = self_enc_file_id;
            }
            _ => {
                return Err((1, "No encrypted file id found".to_string()));
            }
        }
        match self.decryption_key.clone() {
            Some(self_decryption_key) => {
                decryption_key = self_decryption_key;
            }
            _ => {
                return Err((2, "No decryption key found".to_string()));
            }
        }

        let file_location;
        if self.file_type != "" {
            file_location = format!("{}/{}.{}", output_folder.to_str().unwrap(), self.name, self.file_type);
        } else {
            file_location = format!("{}/{}", output_folder.to_str().unwrap(), self.name);
        }

        let encrypted_file_res = File::open(encrypted_file_path.clone()).await;

        let mut encrypted_file;
        match encrypted_file_res {
            Ok(enc_file) => {
                encrypted_file = enc_file;
            }
            Err(_) => {
                return Err((3, "Failed to open encrypted file".to_string()))
            }
        }

        let mut encrypted_data = Vec::new();
        let read_res = encrypted_file.read_to_end(&mut encrypted_data).await;

        match read_res {
            Ok(_) => {}
            Err(_) => {
                return Err((4, "Failed to read encrypted file".to_string()));
            }
        }

        {
            let mut hasher = Sha256::new();
            hasher.update(&encrypted_data);
            let hash = hasher.finalize();
            let actual_enc_file_id = U256::from_big_endian(&hash);

            if actual_enc_file_id != enc_file_id {
                return Err((5, "Encrypted file hash mismatch".to_string()));
            }
        }

        if encrypted_data.len() < 12 {
            return Err((6, "Encrypted file is too small to contain a nonce".to_string()));
        }

        let nonce_bytes = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];

        let key_bytes_res = hex::decode(&decryption_key);

        let key_bytes;
        match key_bytes_res {
            Ok(bytes) => {
                key_bytes = bytes;
            }
            _ => {
                return Err((7, "Invalid decryption key (hex decode failed)".to_string()));
            }
        }

        if key_bytes.len() != 32 {
            return Err((8, "Decryption key is not 32 bytes".to_string()));
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext_res = cipher.decrypt(nonce, ciphertext);

        let plaintext;
        match plaintext_res {
            Ok(plaintext_data) => {
                plaintext = plaintext_data;
            }
            Err(_) => {
                return Err((9, "Failed to decrypt file".to_string()));
            }
        }

        {
            let mut hasher = Sha256::new();
            hasher.update(&plaintext);
            let hash = hasher.finalize();
            let actual_file_id = U256::from_big_endian(&hash);

            if actual_file_id != file_id {
                return Err((10, "Decrypted file hash mismatch".to_string()));
            }
        }

        {
            let out_res = File::create(&file_location).await;

            let mut out;
            match out_res {
                Ok(file_thingy) => {
                    out = file_thingy;
                }
                Err(_) => {
                    return Err((11, "Failed to create output file".to_string()));
                }
            }
            let write_res = out.write_all(&plaintext).await;

            if write_res.is_err() {
                return Err((12, "Failed to write decrypted file".to_string()));
            }
        }

        let enc_file_delete = fs::remove_file(encrypted_file_path.clone()).await;

        if enc_file_delete.is_err() {
            return Err((13, format!("Could not delete encrypted file {}", encrypted_file_path.to_str().unwrap())));
        }

        Ok(file_location)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStorage {
    pub file_storage_settings_path: String,
    downloads_path: String,
    chunk_data_path: String,
    temp_chunk_data_path: String,
    downloads: Vec<FileInfo>,
    chunk_names: Vec<String>
}

impl FileStorage {
    pub fn new(file_storage_settings_path: String, downloads_path: String, chunk_data_path: String, temp_chunk_data_path: String) -> FileStorage {
        FileStorage {
            file_storage_settings_path,
            downloads_path,
            chunk_data_path,
            temp_chunk_data_path,
            downloads: Vec::new(),
            chunk_names: Vec::new()
        }
    }

    pub async fn load(file_storage_file: String) -> Result<FileStorage, Box<dyn std::error::Error>> {
        let mut file = File::open(file_storage_file).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;
        let file_keys: FileStorage = serde_json::from_str(&contents)?;
        Ok(file_keys)
    }

    pub async fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(self)?;
        let mut file = File::create(self.file_storage_settings_path.clone()).await?;
        file.write_all(json_string.as_bytes()).await?;
        Ok(())
    }
}

pub struct FileInformation {
    id: U256,
    name: String,
    file_type: String,
    size: usize,
    categories: Vec<String>,
    file_id: U256,
    enc_file_id: U256,
    decryption_key: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileUpload {
    pub id: U256,
    pub name: String,
    pub file_type: String,
    pub size: usize,
    pub categories: Vec<String>,
    pub file_id: U256,
    pub enc_file_id: U256,
    pub decryption_key: String,
    pub metadata_location: RotatingHash,
    pub key_location: RotatingHash,
    pub chunks: Vec<ChunkInfo>
}

impl FileUpload {
    pub fn new(information: FileInformation, chunks: Vec<ChunkInfo>, rotation_time_hours: f64) -> FileUpload {
        FileUpload {
            id: information.id,
            name: information.name,
            file_type: information.file_type,
            size: information.size,
            categories: information.categories,
            file_id: information.file_id,
            enc_file_id: information.enc_file_id,
            decryption_key: information.decryption_key,
            metadata_location: RotatingHash::new(rotation_time_hours),
            key_location: RotatingHash::new(rotation_time_hours),
            chunks,
        }
    }
    pub async fn encrypt_file(input_file: Box<Path>, output_path: Box<Path>) -> std::io::Result<FileInformation> {
        let mut key_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut key_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut file_data = Vec::new();
        {
            let mut f = File::open(input_file.clone()).await?;
            f.read_to_end(&mut file_data).await?;
        }

        let mut hasher = Sha256::new();
        hasher.update(&file_data);
        let hash = hasher.finalize();

        let mut name = input_file.file_name().unwrap().to_str().unwrap().to_string();
        if name.contains(".") {
            name = name.split('.').collect::<Vec<&str>>()[0].to_string();
        }

        let file_type = input_file.extension().unwrap_or(OsStr::new("")).to_str().unwrap().to_string();
        let size = file_data.len();
        let file_id = U256::from_big_endian(&hash);

        let encrypted_data = cipher
            .encrypt(nonce, file_data.as_ref())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let mut output_file: PathBuf = output_path.into();
        output_file.push(format!("{}.enc", input_file.file_name().unwrap().to_str().unwrap()));

        {
            let mut out = File::create(output_file).await?;
            out.write_all(&nonce_bytes).await?;
            out.write_all(&encrypted_data).await?;
        }

        let mut encrypted_file_data: Vec<u8> = vec![];
        encrypted_file_data.extend(nonce_bytes);
        encrypted_file_data.extend(encrypted_data);

        let mut hasher2 = Sha256::new();
        hasher2.update(&encrypted_file_data);
        let hash2 = hasher2.finalize();

        let enc_file_id = U256::from_big_endian(&hash2);

        let decryption_key = hex::encode(key_bytes);

        Ok(FileInformation {
            id: u256_random(),
            name,
            file_type,
            size,
            categories: vec![],
            file_id,
            enc_file_id,
            decryption_key,
        })
    }

    pub async fn split_into_chunks(encrypted_file: Box<Path>, num_chunks: usize) -> std::io::Result<Vec<ChunkInfo>> {
        let mut file = OpenOptions::new().read(true).open(&encrypted_file).await?;
        let file_size = file.metadata().await?.len() as usize;

        if num_chunks == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "num_chunks must be > 0",
            ));
        }
        if file_size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "File is empty; cannot split.",
            ));
        }

        let base_size = file_size / num_chunks;
        let remainder = file_size % num_chunks;

        let mut chunk_infos = Vec::with_capacity(num_chunks);
        let parent_dir = encrypted_file.as_ref().parent().unwrap_or_else(|| ".".as_ref());

        let mut chunks: Vec<String> = vec![];

        let mut offset: usize = 0;
        for i in 0..num_chunks {
            let this_chunk_size;
            if i < remainder {
                this_chunk_size = base_size + 1;
            } else {
                this_chunk_size = base_size;
            };

            let mut chunk_data = vec![0u8; this_chunk_size];
            file.seek(SeekFrom::Start(offset as u64)).await?;
            file.read_exact(&mut chunk_data).await?;

            let mut hasher = Sha256::new();
            hasher.update(&chunk_data);
            let hash = hasher.finalize();

            let chunk_u256 = U256::from_big_endian(&hash);

            let filename_hex = hex::encode(hash);

            let chunk_path = parent_dir.join(filename_hex);

            {
                let mut chunk_file = File::create(&chunk_path).await?;
                chunk_file.write_all(&chunk_data).await?;
            }

            let chunk_info = ChunkInfo {
                index: i,
                chunk_id: chunk_u256,
                size: this_chunk_size,
            };
            chunk_infos.push(chunk_info);

            offset += this_chunk_size;
            chunks.push(chunk_path.to_string_lossy().to_string());
        }

        fs::remove_file(encrypted_file).await?;

        Ok(chunk_infos)
    }
}