use std::collections::HashMap;
use std::net::SocketAddr;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::file_utils::garlemlia_files::{FileStorage};
use crate::structs::constants::SOCKET_FILE_DATA_MAX;
use crate::structs::garlemlia_message::{GarlemliaFindRequest, GarlemliaResponse, InitialChunkInfo};
use crate::structs::node::Node;
use crate::time_hash::time_based_hash::RotatingHash;

pub async fn new_tracker(file_storage_path: String) -> Result<GarlemliaFilesTracker, Box<dyn std::error::Error>> {
    let file_storage = FileStorage::new(file_storage_path.clone(), format!("{}/file_storage.json", file_storage_path), format!("{}/downloads", file_storage_path), format!("{}/uploads", file_storage_path), format!("{}/temporary", file_storage_path));


    let tracker = GarlemliaFilesTracker::new(None, file_storage);

    Ok(tracker)
}

pub async fn load_tracker_file(tracker_file_path: String) -> Result<GarlemliaFilesTracker, Box<dyn std::error::Error>> {
    let mut file = File::open(tracker_file_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    let tracker: GarlemliaFilesTracker = serde_json::from_str(&contents)?;

    Ok(tracker)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GarlemliaFilesTracker {
    uploads: Vec<GarlemliaData>,
    downloads: FileStorage
}

impl GarlemliaFilesTracker {
    pub fn new(uploads: Option<Vec<GarlemliaData>>, downloads: FileStorage) -> Self {
        Self {
            uploads: uploads.unwrap_or(vec![]),
            downloads
        }
    }

    pub fn get_uploads(&self) -> &Vec<GarlemliaData> {
        &self.uploads
    }

    pub fn get_downloads(&self) -> &FileStorage {
        &self.downloads
    }

    pub fn get_uploads_mut(&mut self) -> &mut Vec<GarlemliaData> {
        &mut self.uploads
    }

    pub fn get_downloads_mut(&mut self) -> &mut FileStorage {
        &mut self.downloads
    }

    pub fn set_uploads(&mut self, uploads: Vec<GarlemliaData>) {
        self.uploads = uploads;
    }

    pub fn set_downloads(&mut self, downloads: FileStorage) {
        self.downloads = downloads;
    }

    pub fn add_upload(&mut self, data: GarlemliaData) {
        self.uploads.push(data);
    }

    pub async fn save_tracker(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(&self)?;
        let mut file = File::create(format!("{}/tracker.data", &self.downloads.file_storage_root_path)).await?;
        file.write_all(json_string.as_bytes()).await?;

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaData {
    Value { id: U256, value: String },
    Validator { id: U256, proxy_ids: Vec<U256>, proxies: HashMap<U256, SocketAddr> },
    FileName { id: U256, name: String, file_type: String, size: usize, categories: Vec<String>, metadata_location: RotatingHash, key_location: RotatingHash },
    MetaData { id: U256, file_id: U256, chunk_info: Vec<InitialChunkInfo>, downloads: usize, availability: f64, metadata_location: RotatingHash },
    FileKey { id: U256, enc_file_id: U256, decryption_key: String, key_location: RotatingHash },
    FileChunk { id: U256, size: usize }
}

impl GarlemliaData {
    /// Get ID from response
    pub fn get_id(&self) -> U256 {
        match self {
            GarlemliaData::Value { id, .. } => *id,
            GarlemliaData::Validator { id, .. } => *id,
            GarlemliaData::FileName { id, .. } => *id,
            GarlemliaData::MetaData { id, .. } => *id,
            GarlemliaData::FileKey { id, .. } => *id,
            GarlemliaData::FileChunk { id, .. } => *id,
        }
    }

    /// Function to transpose the information given to a form in which it is more easily stored
    pub fn store(&mut self) {
        match self {
            GarlemliaData::FileName { id, name, file_type, size, categories, metadata_location, key_location } => {
                let mut m_loc = metadata_location.clone();
                m_loc.store();

                let mut k_loc = key_location.clone();
                k_loc.store();

                *self = GarlemliaData::FileName {
                    id: id.clone(),
                    name: name.clone(),
                    file_type: file_type.clone(),
                    size: size.clone(),
                    categories: categories.clone(),
                    metadata_location: m_loc,
                    key_location: k_loc
                };
            }
            GarlemliaData::MetaData { id, file_id, chunk_info, downloads, availability, metadata_location } => {
                let mut m_loc = metadata_location.clone();
                m_loc.store();

                *self = GarlemliaData::MetaData {
                    id: id.clone(),
                    file_id: file_id.clone(),
                    chunk_info: chunk_info.clone(),
                    downloads: downloads.clone(),
                    availability: availability.clone(),
                    metadata_location: m_loc
                };
            }
            GarlemliaData::FileKey { id, enc_file_id, decryption_key, key_location } => {
                let mut k_loc = key_location.clone();
                k_loc.store();

                *self = GarlemliaData::FileKey {
                    id: id.clone(),
                    enc_file_id: enc_file_id.clone(),
                    decryption_key: decryption_key.clone(),
                    key_location: k_loc
                };
            }
            _ => {}
        }
    }

    /// Function for converting a FindRequest into a Response type w/ properly mapped values
    pub fn get_response(&self, request: Option<GarlemliaFindRequest>) -> Option<GarlemliaResponse> {
        match self {
            GarlemliaData::Value { value, .. } => {
                Some(GarlemliaResponse::Value {
                    value: value.to_string()
                })
            }
            GarlemliaData::Validator { proxy_ids, proxies, .. } => {
                let mut res = GarlemliaResponse::Validator {
                    proxy: None
                };

                if request.is_none() {
                    return None;
                }

                match request.unwrap() {
                    GarlemliaFindRequest::Validator { proxy_id, .. } => {
                        let mut ids = proxy_ids.clone();
                        while ids.len() > 0 {
                            let check_id = ids.remove(rand::random_range(0..ids.len()));

                            if check_id != proxy_id {
                                res = GarlemliaResponse::Validator {
                                    proxy: proxies.get(&check_id).cloned()
                                };
                                break;
                            }
                        }
                    }
                    _ => {}
                }

                Some(res)
            }
            GarlemliaData::FileName { name, file_type, size, categories, metadata_location, key_location, .. } => {
                Some(GarlemliaResponse::FileName {
                    name: name.clone(),
                    file_type: file_type.clone(),
                    size: size.clone(),
                    categories: categories.clone(),
                    metadata_location: metadata_location.get_next(24, 1.0).unwrap(),
                    key_location: key_location.get_next(24, 1.0).unwrap()
                })
            }
            GarlemliaData::MetaData { file_id, chunk_info, downloads, availability, .. } => {
                Some(GarlemliaResponse::MetaData {
                    file_id: file_id.clone(),
                    chunk_info: chunk_info.clone(),
                    downloads: downloads.clone(),
                    availability: availability.clone()
                })
            }
            GarlemliaData::FileKey { enc_file_id, decryption_key, .. } => {
                Some(GarlemliaResponse::FileKey {
                    enc_file_id: enc_file_id.clone(),
                    decryption_key: decryption_key.clone()
                })
            }
            _ => {
                None
            }
        }
    }

    /// Function for turning a chunk request into a response
    pub fn get_chunk_info(&self, data: Vec<u8>, request_id: U256, sender: Node) -> Option<GarlemliaResponse> {
        match self {
            GarlemliaData::FileChunk { id, size } => {
                let total_parts = (data.len() + SOCKET_FILE_DATA_MAX - 1) / SOCKET_FILE_DATA_MAX;

                Some(GarlemliaResponse::FileChunkInfo {
                    request_id,
                    chunk_id: id.clone(),
                    chunk_size: size.clone(),
                    parts_count: total_parts,
                    sender
                })
            },
            _ => None
        }
    }

    /// Function for converting a chunk request into its proper chunk part responses
    pub fn get_chunk_responses(&self, mut data: Vec<u8>, request_id: U256) -> Option<Vec<GarlemliaResponse>> {
        match self {
            GarlemliaData::FileChunk { id, .. } => {
                let mut responses = vec![];

                let part_size = SOCKET_FILE_DATA_MAX;

                let mut total_parts = 0;
                while data.len() > 0 {
                    let part_data: Vec<u8>;
                    if part_size > data.len() {
                        part_data = data.drain(..).collect();
                    } else {
                        part_data = data.drain(0..part_size).collect();
                    }

                    responses.push(GarlemliaResponse::ChunkPart {
                        request_id,
                        chunk_id: id.clone(),
                        index: total_parts,
                        part_size: part_data.len(),
                        data: part_data
                    });

                    total_parts += 1;
                }

                Some(responses)
            },
            _ => None
        }
    }

    /// Function for checking whether this data is a file chunk
    pub fn is_chunk(&self) -> bool {
        match self {
            GarlemliaData::FileChunk { .. } => true,
            _ => false
        }
    }
}