use kademlia::{Kademlia, KademliaMessage, Node};
use rand::Rng;
use tokio::net::UdpSocket;
use std::time::Duration;
use num_traits::pow;

fn bucket_index(src_id: u8, target_id: u8) -> u8 {
    let xor_distance = src_id ^ target_id;

    (8 - xor_distance.leading_zeros()) as u8
}

#[tokio::main]
async fn main() {
    let id_1 = 22;//rand::rng().random::<u128>();
    for i in 1..pow(2, 6) {
        if i == id_1 {
            continue;
        }
        println!("src_id: {}, target_id: {}, bucket: {}", id_1, i, bucket_index(id_1, i));
    }
}