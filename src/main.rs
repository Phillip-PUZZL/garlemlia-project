use kademlia_simulator::{Kademlia, KademliaMessage, Node, load_simulated_nodes, save_simulated_nodes};

#[tokio::main]
async fn main() {
    let file_path = "nodes.json";

    // Load nodes from JSON
    match load_simulated_nodes(file_path) {
        Ok(mut nodes) => {
            println!("Loaded nodes: {:?}", nodes);

            // Modify the nodes as needed
            if let Some(first_node) = nodes.get_mut(0) {
                first_node.locked = true;
            }

            // Save the modified nodes back to a new file
            let new_file_path = "updated_nodes.json";
            if let Err(e) = save_simulated_nodes(new_file_path, &nodes) {
                eprintln!("Error saving nodes: {}", e);
            } else {
                println!("Saved updated nodes to {}", new_file_path);
            }
        }
        Err(e) => eprintln!("Error loading nodes: {}", e),
    }
}