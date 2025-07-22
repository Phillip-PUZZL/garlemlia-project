use std::collections::HashMap;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// State information for shared memory processing
#[derive(Debug, Clone)]
pub struct ProcessingCheck {
    // true = shared memory in use by another thread
    // false = shared memory not in use by another thread
    is_processing: bool
}

impl ProcessingCheck {
    pub fn new(is_processing: bool) -> ProcessingCheck {
        ProcessingCheck {
            is_processing
        }
    }

    // Check current state of shared memory
    pub fn check(&self) -> bool {
        self.is_processing
    }

    // Set current state of shared memory
    pub fn set(&mut self, state: bool) {
        self.is_processing = state;
    }
}

/// Struct to hold information on chunk parts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChunkPartInfo {
    pub index: usize,
    pub size: usize
}

/// Struct to hold information and the data for chunk parts - used by proxies when awaiting all
/// chunk part data to come in
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyChunkPartInfo {
    pub index: usize,
    pub size: usize,
    pub data: Vec<u8>
}

/// Struct to hold information for a file chunk, including chunk parts information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileChunkInfo {
    pub request_id: U256,
    pub chunk_id: U256,
    pub chunk_size: usize,
    pub parts_count: usize,
    pub parts_info: Vec<ChunkPartInfo>
}

/// Struct to hold information for a file chunk, including chunk parts information
/// This one is specifically used for proxies awaiting all chunk parts before forwarding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyFileChunkInfo {
    pub request_id: U256,
    pub chunk_id: U256,
    pub chunk_size: usize,
    pub parts_count: usize,
    pub parts_info: Vec<ProxyChunkPartInfo>
}

/// Struct for the garlemlia instance to hold which maintains state data for file chunks this node
/// currently provides for others to download, file chunks which this node is actively downloading,
/// and file chunks which this node is actively attempting to forward
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPartAssociations {
    chunks_storing: Vec<FileChunkInfo>,
    chunks_downloading: Vec<FileChunkInfo>,
    chunks_proxy_for: Vec<ProxyFileChunkInfo>,
    pub already_has: HashMap<U256, U256>
}

impl ChunkPartAssociations {
    pub fn new() -> ChunkPartAssociations {
        ChunkPartAssociations {
            chunks_storing: vec![],
            chunks_downloading: vec![],
            chunks_proxy_for: vec![],
            already_has: HashMap::new()
        }
    }

    pub fn add_to_chunk_storage(&mut self, store_chunk: FileChunkInfo) {
        self.chunks_storing.push(store_chunk);
    }

    pub fn add_to_chunk_downloads(&mut self, temp_chunk: FileChunkInfo) {
        self.chunks_downloading.push(temp_chunk);
    }

    pub fn add_to_chunk_proxy(&mut self, proxy_chunk: ProxyFileChunkInfo) {
        self.chunks_proxy_for.push(proxy_chunk);
    }

    pub fn remove_from_chunk_storage(&mut self, chunk_id: U256) {
        for i in 0..self.chunks_storing.len() {
            if self.chunks_storing[i].chunk_id == chunk_id {
                self.chunks_storing.remove(i);
                break;
            }
        }
    }

    pub fn remove_from_chunk_downloads(&mut self, temp_chunk_id: U256) {
        for i in 0..self.chunks_downloading.len() {
            if self.chunks_downloading[i].chunk_id == temp_chunk_id {
                self.chunks_downloading.remove(i);
                break;
            }
        }
    }

    pub fn remove_from_chunk_proxy(&mut self, proxy_chunk_id: U256) {
        for i in 0..self.chunks_proxy_for.len() {
            if self.chunks_proxy_for[i].chunk_id == proxy_chunk_id {
                self.chunks_proxy_for.remove(i);
                break;
            }
        }
    }

    pub fn am_storing_chunk(&self, chunk_id: U256) -> bool {
        for i in 0..self.chunks_storing.len() {
            if self.chunks_storing[i].chunk_id == chunk_id {
                return true;
            }
        }
        false
    }

    pub fn am_downloading_chunk(&self, chunk_id: U256) -> bool {
        for i in 0..self.chunks_downloading.len() {
            if self.chunks_downloading[i].chunk_id == chunk_id {
                return true;
            }
        }
        false
    }

    pub fn am_proxy_for_chunk(&self, chunk_id: U256) -> bool {
        for i in 0..self.chunks_proxy_for.len() {
            if self.chunks_proxy_for[i].chunk_id == chunk_id {
                return true;
            }
        }
        false
    }

    pub fn get_mut_chunk_stored(&mut self, chunk_id: U256) -> Option<&mut FileChunkInfo> {
        for i in 0..self.chunks_storing.len() {
            if self.chunks_storing[i].chunk_id == chunk_id {
                return Some(&mut self.chunks_storing[i]);
            }
        }
        None
    }

    pub fn get_mut_chunk_downloading(&mut self, chunk_id: U256) -> Option<&mut FileChunkInfo> {
        for i in 0..self.chunks_downloading.len() {
            if self.chunks_downloading[i].chunk_id == chunk_id {
                return Some(&mut self.chunks_downloading[i]);
            }
        }
        None
    }

    pub fn get_mut_chunk_proxy(&mut self, chunk_id: U256) -> Option<&mut ProxyFileChunkInfo> {
        for i in 0..self.chunks_proxy_for.len() {
            if self.chunks_proxy_for[i].chunk_id == chunk_id {
                return Some(&mut self.chunks_proxy_for[i]);
            }
        }
        None
    }

    pub fn get_stored_chunk_from_request_id(&self, chunk_id: U256) -> Option<U256> {
        for i in 0..self.chunks_storing.len() {
            if self.chunks_storing[i].chunk_id == chunk_id {
                return Some(self.chunks_storing[i].request_id);
            }
        }
        None
    }

    pub fn get_downloading_chunk_from_request_id(&self, chunk_id: U256) -> Option<U256> {
        for i in 0..self.chunks_downloading.len() {
            if self.chunks_downloading[i].chunk_id == chunk_id {
                return Some(self.chunks_downloading[i].request_id);
            }
        }
        None
    }

    pub fn get_proxy_chunk_from_request_id(&self, chunk_id: U256) -> Option<U256> {
        for i in 0..self.chunks_proxy_for.len() {
            if self.chunks_proxy_for[i].chunk_id == chunk_id {
                return Some(self.chunks_proxy_for[i].request_id);
            }
        }
        None
    }
}