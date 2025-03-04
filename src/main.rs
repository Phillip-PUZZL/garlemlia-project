use kademlia_simulator;

#[tokio::main]
async fn main() {
    kademlia_simulator::init_socket_once().await;
    kademlia_simulator::run_create_network("test_nodes.json", 10000).await;
}