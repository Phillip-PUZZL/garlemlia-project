use std::net::SocketAddr;
use kademlia_simulator::{create_network, load_simulated_nodes, save_simulated_nodes, Simulator};

#[tokio::main]
async fn main() {
    let file_path = "kademlia_nodes_empty.json";

    // Load nodes from JSON
    match load_simulated_nodes(file_path).await {
        Ok(nodes) => {
            //println!("Loaded nodes: {:?}", nodes);

            create_network(nodes.clone()).await;

            let updated_nodes = kademlia_simulator::get_all_nodes().await;

            // Save the modified nodes back to a new file
            let new_file_path = "updated_nodes.json";
            if let Err(e) = save_simulated_nodes(new_file_path, &updated_nodes).await {
                eprintln!("Error saving nodes: {}", e);
            } else {
                println!("Saved updated nodes to {}", new_file_path);
            }

        }
        Err(e) => {
            eprintln!("Error loading nodes: {}", e);
        },
    }
}