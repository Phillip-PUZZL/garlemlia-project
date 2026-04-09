use crate::core::constants::{
    DATA_SHARDS, PROXY_SEND_ERROR_BOTH, PROXY_SEND_ERROR_NEIGHBOR1, PROXY_SEND_ERROR_NEIGHBOR2,
};
use crate::garlic::{Clove, CloveRequestID};
use chrono::Utc;
use primitive_types::U256;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::error::Error;

pub struct Sharding;
impl Sharding {
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
        for (i, chunk) in key_data
            .chunks(key_shard_size)
            .enumerate()
            .take(DATA_SHARDS)
        {
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
}
