use primitive_types::U256;
use crate::garlemlia_structs::garlemlia_structs::ChunkInfo;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    needed_chunks: Vec<ChunkInfo>
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

    pub fn get_chunk(chunk_name: String) -> Vec<u8> {
        let mut chunk_info = vec![];


        chunk_info
    }

    pub fn append_download(file_name: String) {

    }


}

pub struct FileUpload {
    id: U256,
    name: String,
    file_type: String,
    size: usize,
    categories: Vec<String>,
    file_id: U256,
    enc_file_id: U256,
    decryption_key: String,
    metadata_location_seed: U256,
    metadata_seed_rotation: f64,
    key_location_seed: U256,
    key_seed_rotation: f64,
    chunks: Vec<String>
}

impl FileUpload {

}