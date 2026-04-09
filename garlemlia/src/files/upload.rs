use crate::data::garlemlia_protocol::InitialChunkInfo;
use crate::files::file_info::FileInformation;
use crate::time::time_based_hash::RotatingHash;
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
    pub chunks: Vec<InitialChunkInfo>,
}

impl FileUpload {
    pub fn new(
        information: FileInformation,
        chunks: Vec<InitialChunkInfo>,
        rotation_time_hours: f64,
    ) -> FileUpload {
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
    pub async fn encrypt_file(
        input_file: Box<Path>,
        output_path: Box<Path>,
    ) -> std::io::Result<FileInformation> {
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

        let mut name = input_file
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        if name.contains(".") {
            name = name.split('.').collect::<Vec<&str>>()[0].to_string();
        }

        let file_type = input_file
            .extension()
            .unwrap_or(OsStr::new(""))
            .to_str()
            .unwrap()
            .to_string();
        let size = file_data.len();
        let file_id = U256::from_big_endian(&hash);

        let encrypted_data = cipher
            .encrypt(nonce, file_data.as_ref())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let mut output_file: PathBuf = output_path.into();
        output_file.push(format!(
            "{}.enc",
            input_file.file_name().unwrap().to_str().unwrap()
        ));

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

        let name_vec = name.as_bytes().to_vec();
        let mut hasher3 = Sha256::new();
        hasher3.update(&name_vec);
        let hash3 = hasher3.finalize();

        Ok(FileInformation {
            id: U256::from_big_endian(&hash3),
            name,
            file_type,
            size,
            categories: vec![],
            file_id,
            enc_file_id,
            decryption_key,
        })
    }

    pub async fn split_into_chunks(
        encrypted_file: Box<Path>,
        num_chunks: usize,
    ) -> std::io::Result<Vec<InitialChunkInfo>> {
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
        let parent_dir = encrypted_file
            .as_ref()
            .parent()
            .unwrap_or_else(|| ".".as_ref());

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

            let chunk_info = InitialChunkInfo {
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
