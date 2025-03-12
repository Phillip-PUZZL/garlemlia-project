use garlemlia::simulator::simulator;

#[tokio::test]
async fn generate_test_nodes() {
    let test_file_path = "./test_nodes.json";
    let keys_file_path = "./keys.json";
    let nodes_to_create: usize = 10000;
    simulator::init_socket_once().await;
    simulator::run_create_network(test_file_path, nodes_to_create as u16, keys_file_path).await;

    // Load nodes from JSON
    match simulator::load_simulated_nodes(test_file_path).await {
        Ok(nodes) => {
            assert_eq!(nodes.len(), nodes_to_create, "Could not load nodes");
        }
        Err(e) => {
            eprintln!("Error loading nodes: {}", e);
            assert!(false, "Could not load nodes");
        },
    }
}