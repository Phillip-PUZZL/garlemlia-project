use std::collections::HashMap;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ProcessingCheck {
    is_processing: bool
}

impl ProcessingCheck {
    pub fn new(is_processing: bool) -> ProcessingCheck {
        ProcessingCheck {
            is_processing
        }
    }

    pub fn check(&self) -> bool {
        self.is_processing
    }

    pub fn set(&mut self, state: bool) {
        self.is_processing = state;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChunkPartInfo {
    pub index: usize,
    pub size: usize
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyChunkPartInfo {
    pub index: usize,
    pub size: usize,
    pub data: Vec<u8>
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileChunkInfo {
    pub request_id: U256,
    pub chunk_id: U256,
    pub chunk_size: usize,
    pub parts_count: usize,
    pub parts_info: Vec<ChunkPartInfo>
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyFileChunkInfo {
    pub request_id: U256,
    pub chunk_id: U256,
    pub chunk_size: usize,
    pub parts_count: usize,
    pub parts_info: Vec<ProxyChunkPartInfo>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPartAssociations {
    store_chunks: Vec<FileChunkInfo>,
    temp_chunks: Vec<FileChunkInfo>,
    proxy_chunks: Vec<ProxyFileChunkInfo>,
    pub already_has: HashMap<U256, U256>
}

impl ChunkPartAssociations {
    pub fn new() -> ChunkPartAssociations {
        ChunkPartAssociations {
            store_chunks: vec![],
            temp_chunks: vec![],
            proxy_chunks: vec![],
            already_has: HashMap::new()
        }
    }

    pub fn add_store_chunk(&mut self, store_chunk: FileChunkInfo) {
        self.store_chunks.push(store_chunk);
    }

    pub fn add_temp_chunk(&mut self, temp_chunk: FileChunkInfo) {
        self.temp_chunks.push(temp_chunk);
    }

    pub fn add_proxy_chunk(&mut self, proxy_chunk: ProxyFileChunkInfo) {
        self.proxy_chunks.push(proxy_chunk);
    }

    pub fn remove_store_chunk(&mut self, chunk_id: U256) {
        for i in 0..self.store_chunks.len() {
            if self.store_chunks[i].chunk_id == chunk_id {
                self.store_chunks.remove(i);
                break;
            }
        }
    }

    pub fn remove_temp_chunk(&mut self, temp_chunk_id: U256) {
        for i in 0..self.temp_chunks.len() {
            if self.temp_chunks[i].chunk_id == temp_chunk_id {
                self.temp_chunks.remove(i);
                break;
            }
        }
    }

    pub fn remove_proxy_chunk(&mut self, proxy_chunk_id: U256) {
        for i in 0..self.proxy_chunks.len() {
            if self.proxy_chunks[i].chunk_id == proxy_chunk_id {
                self.proxy_chunks.remove(i);
                break;
            }
        }
    }

    pub fn is_store_chunk(&self, chunk_id: U256) -> bool {
        for i in 0..self.store_chunks.len() {
            if self.store_chunks[i].chunk_id == chunk_id {
                return true;
            }
        }
        false
    }

    pub fn is_temp_chunk(&self, chunk_id: U256) -> bool {
        for i in 0..self.temp_chunks.len() {
            if self.temp_chunks[i].chunk_id == chunk_id {
                return true;
            }
        }
        false
    }

    pub fn is_proxy_chunk(&self, chunk_id: U256) -> bool {
        for i in 0..self.proxy_chunks.len() {
            if self.proxy_chunks[i].chunk_id == chunk_id {
                return true;
            }
        }
        false
    }

    pub fn get_store_chunk_mut(&mut self, chunk_id: U256) -> Option<&mut FileChunkInfo> {
        for i in 0..self.store_chunks.len() {
            if self.store_chunks[i].chunk_id == chunk_id {
                return Some(&mut self.store_chunks[i]);
            }
        }
        None
    }

    pub fn get_temp_chunk_mut(&mut self, chunk_id: U256) -> Option<&mut FileChunkInfo> {
        for i in 0..self.temp_chunks.len() {
            if self.temp_chunks[i].chunk_id == chunk_id {
                return Some(&mut self.temp_chunks[i]);
            }
        }
        None
    }

    pub fn get_proxy_chunk_mut(&mut self, chunk_id: U256) -> Option<&mut ProxyFileChunkInfo> {
        for i in 0..self.proxy_chunks.len() {
            if self.proxy_chunks[i].chunk_id == chunk_id {
                return Some(&mut self.proxy_chunks[i]);
            }
        }
        None
    }

    pub fn get_store_chunk_request_id(&self, chunk_id: U256) -> Option<U256> {
        for i in 0..self.store_chunks.len() {
            if self.store_chunks[i].chunk_id == chunk_id {
                return Some(self.store_chunks[i].request_id);
            }
        }
        None
    }

    pub fn get_temp_chunk_request_id(&self, chunk_id: U256) -> Option<U256> {
        for i in 0..self.temp_chunks.len() {
            if self.temp_chunks[i].chunk_id == chunk_id {
                return Some(self.temp_chunks[i].request_id);
            }
        }
        None
    }

    pub fn get_proxy_chunk_request_id(&self, chunk_id: U256) -> Option<U256> {
        for i in 0..self.proxy_chunks.len() {
            if self.proxy_chunks[i].chunk_id == chunk_id {
                return Some(self.proxy_chunks[i].request_id);
            }
        }
        None
    }
}