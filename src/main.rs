#[tokio::main]
async fn main() {
    let test_file_path = "./test_nodes_loong_1.json";
    let nodes_to_create: usize = 10000;
    garlemlia_simulator::init_socket_once().await;
    garlemlia_simulator::run_create_network(test_file_path, nodes_to_create as u16).await;
}

// Chapter 1: Introduction
// 1.1 Motivation
// 1.2 - ? Rest of intro
// Chapter 2: Statement of problem
// ^^^ Describe interest, problem to solve with new algorithm, what am I basing research on
// Chapter 3: Literature Review
// ^^^ Explain Kademlia and Garlic Cast, good attributes, bad attributes
// 