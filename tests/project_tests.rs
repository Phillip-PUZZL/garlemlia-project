#[tokio::test]
async fn generate_test_nodes() {
    let test_file_path = "./garlemlia-simulator/tests/test_nodes.json";
    let nodes_to_create: usize = 1000;
    garlemlia_simulator::init_socket_once().await;
    garlemlia_simulator::run_create_network(test_file_path, nodes_to_create as u16).await;

    // Load nodes from JSON
    match garlemlia_simulator::load_simulated_nodes(test_file_path).await {
        Ok(nodes) => {
            assert_eq!(nodes.len(), nodes_to_create, "Could not load nodes");
        }
        Err(e) => {
            eprintln!("Error loading nodes: {}", e);
            assert!(false, "Could not load nodes");
        },
    }
}