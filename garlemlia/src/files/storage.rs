use super::file_info::FileInfo;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileStorage {
    pub file_storage_root_path: String,
    pub file_storage_settings_path: String,
    pub downloads_path: String,
    pub chunk_data_path: String,
    pub temp_chunk_data_path: String,
    files: Vec<FileInfo>,
}

impl FileStorage {
    pub fn new(
        file_storage_root_path: String,
        file_storage_settings_path: String,
        downloads_path: String,
        chunk_data_path: String,
        temp_chunk_data_path: String,
    ) -> FileStorage {
        FileStorage {
            file_storage_root_path,
            file_storage_settings_path,
            downloads_path,
            chunk_data_path,
            temp_chunk_data_path,
            files: Vec::new(),
        }
    }

    pub async fn store_chunk_part(
        &self,
        id: U256,
        index: usize,
        data: Vec<u8>,
    ) -> std::io::Result<bool> {
        let chunk_path = Path::new(&self.chunk_data_path)
            .join(format!("{}_{index}", hex::encode(id.to_big_endian())));

        if !chunk_path.exists() {
            let mut chunk_file = File::create(&chunk_path).await?;
            chunk_file.write_all(&data).await?;
        }

        Ok(true)
    }

    pub async fn assemble_chunk(&self, id: U256, parts_count: usize) -> std::io::Result<bool> {
        let chunk_path =
            Path::new(&self.chunk_data_path).join(format!("{}", hex::encode(id.to_big_endian())));

        if !chunk_path.exists() {
            let mut chunk_file = File::create(&chunk_path).await?;
            for index in 0..parts_count {
                let part_path = Path::new(&self.chunk_data_path)
                    .join(format!("{}_{index}", hex::encode(id.to_big_endian())));

                if part_path.exists() {
                    let mut part_file = File::open(&part_path).await?;

                    let mut part_data = Vec::new();
                    part_file.read_to_end(&mut part_data).await?;

                    chunk_file.write_all(&part_data).await?;
                }
            }
        }

        for index in 0..parts_count {
            let part_path = Path::new(&self.chunk_data_path)
                .join(format!("{}_{index}", hex::encode(id.to_big_endian())));

            if part_path.exists() {
                fs::remove_file(&part_path).await?;
            }
        }

        Ok(true)
    }

    pub async fn get_chunk(&self, id: U256) -> std::io::Result<Vec<u8>> {
        let chunk_path = Path::new(&self.chunk_data_path).join(hex::encode(id.to_big_endian()));

        let mut chunk_file = File::open(&chunk_path).await?;

        let mut chunk_data = Vec::new();
        chunk_file.read_to_end(&mut chunk_data).await?;

        Ok(chunk_data)
    }

    pub async fn store_temp_chunk_part(
        &self,
        id: U256,
        index: usize,
        data: Vec<u8>,
    ) -> std::io::Result<bool> {
        let chunk_path = Path::new(&self.temp_chunk_data_path)
            .join(format!("{}_{index}", hex::encode(id.to_big_endian())));

        if !chunk_path.exists() {
            let mut chunk_file = File::create(&chunk_path).await?;
            chunk_file.write_all(&data).await?;
        }

        Ok(true)
    }

    pub async fn assemble_temp_chunk(&self, id: U256, parts_count: usize) -> std::io::Result<bool> {
        let chunk_path = Path::new(&self.temp_chunk_data_path)
            .join(format!("{}", hex::encode(id.to_big_endian())));

        if !chunk_path.exists() {
            let mut chunk_file = File::create(&chunk_path).await?;
            for index in 0..parts_count {
                let part_path = Path::new(&self.temp_chunk_data_path)
                    .join(format!("{}_{index}", hex::encode(id.to_big_endian())));

                if part_path.exists() {
                    let mut part_file = File::open(&part_path).await?;

                    let mut part_data = Vec::new();
                    part_file.read_to_end(&mut part_data).await?;

                    chunk_file.write_all(&part_data).await?;
                }
            }
        }

        for index in 0..parts_count {
            let part_path = Path::new(&self.temp_chunk_data_path)
                .join(format!("{}_{index}", hex::encode(id.to_big_endian())));

            if part_path.exists() {
                fs::remove_file(&part_path).await?;
            }
        }

        Ok(true)
    }

    pub async fn get_temp_chunk(&self, id: U256) -> std::io::Result<Vec<u8>> {
        let chunk_path =
            Path::new(&self.temp_chunk_data_path).join(hex::encode(id.to_big_endian()));

        let mut chunk_file = File::open(&chunk_path).await?;

        let mut chunk_data = Vec::new();
        chunk_file.read_to_end(&mut chunk_data).await?;

        Ok(chunk_data)
    }

    pub async fn load(
        file_storage_file: String,
    ) -> Result<FileStorage, Box<dyn std::error::Error>> {
        let mut file = File::open(file_storage_file).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;
        let file_keys: FileStorage = serde_json::from_str(&contents)?;
        Ok(file_keys)
    }

    // TODO: Remove this function and migrate over to the version in structs/garlemlia_data.rs
    pub async fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(self)?;
        let mut file = File::create(self.file_storage_settings_path.clone()).await?;
        file.write_all(json_string.as_bytes()).await?;
        Ok(())
    }

    pub fn add_download(&mut self, download: FileInfo) {
        let _ = &self.files.push(download);
    }

    pub fn get_download(&self, id: U256) -> Option<FileInfo> {
        for item in &self.files {
            if item.file_id.unwrap() == id {
                return Some(item.clone());
            }
        }

        None
    }

    pub fn get_download_mut(&mut self, id: U256) -> Option<&mut FileInfo> {
        for item in &mut self.files {
            if item.file_id.unwrap() == id {
                return Some(item);
            }
        }

        None
    }

    pub fn remove_download(&mut self, id: U256) {
        for i in 0..self.files.len() {
            if self.files[i].file_id.unwrap() == id {
                self.files.remove(i);
                return;
            }
        }
    }
}
