use kademlia::Kademlia;
use rand::Rng;
use std::net::{SocketAddr, UdpSocket};

#[tokio::main]
async fn main() {
    let id = rand::rng().random::<u64>();
    let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let socket = UdpSocket::bind(address).unwrap();

    let kad = Kademlia::new(id, address);
    kad.start(socket);
}