use kademlia::{Kademlia, KademliaMessage, Node};
use kademlia_simulator;
use rand::Rng;
use std::net::UdpSocket;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let mut port = 2740;

    // Node 1
    let id_1 = rand::rng().random::<u64>();
    let mut kad_1 = Kademlia::new(id_1, "127.0.0.1", port);
    let socket_1 = UdpSocket::bind(kad_1.node.address).unwrap();
    kad_1.start(socket_1.try_clone().unwrap());

    port += 1;

    // Node 2
    let id_2 = rand::rng().random::<u64>();
    let mut kad_2 = Kademlia::new(id_2, "127.0.0.1", port);
    let socket_2 = UdpSocket::bind(kad_2.node.address).unwrap();
    kad_2.start(socket_2.try_clone().unwrap());

    // Node 1 discovers Node 2
    let node_2 = Node { id: id_2, address: kad_2.node.address };
    kad_1.add_node(node_2.clone(), &socket_1);

    println!("Node 1 with ID {id_1} sending FIND_NODE request to Node 2 with ID {id_2}...");

    let message = KademliaMessage::FindNode { id: id_1, sender_id: id_1 };
    kad_1.send_message(&socket_1, &kad_2.node.address, message);

    // Give time for communication
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    kad_1.stop();
    kad_2.stop();
}