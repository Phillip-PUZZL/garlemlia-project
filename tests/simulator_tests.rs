use std::net::SocketAddr;
use std::sync::Arc;
use rand::seq::IndexedRandom;
use rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use garlemlia::garlemlia::garlemlia::Garlemlia;
use garlemlia::simulator::simulator::{get_global_socket, load_simulated_nodes, save_simulated_nodes, SimulatedMessageHandler, SIM, add_running, remove_running, init_socket_once};
use garlemlia::garlemlia_structs::garlemlia_structs::{GMessage, RoutingTable, Node};

async fn create_test_node(id: u128, port: u16) -> Garlemlia {
    let node_actual = Node { id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port) };

    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let mut node = Garlemlia::new_with_details(id, "127.0.0.1", port, RoutingTable::new(node_actual.clone()), SimulatedMessageHandler::create(0), get_global_socket().unwrap().clone(), public_key, private_key);

    add_running(node_actual.clone(), Arc::clone(&node.routing_table)).await;

    node
}

#[tokio::test]
async fn simulated_node_find_test() {
    init_socket_once().await;
    let file_path = "./test_nodes.json";

    // Load nodes from JSON
    match load_simulated_nodes(file_path).await {
        Ok(nodes) => {

            {
                SIM.lock().await.set_nodes(nodes.clone());
            }

            let mut node1 = create_test_node(rand::random::<u128>(), 6000).await;

            {
                println!("NODE:\nID: {}", node1.node.lock().await.id);
            }

            let test_node_sock = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % nodes.len() as u16));

            let selected_port = 9000 + (nodes.len() / 2) as u16;

            let node_random = nodes.choose(&mut rand::rng()).unwrap().clone();
            let mut temp_node_selected = None;
            {
                let temp_node = SIM.lock().await.get_node(SocketAddr::new("127.0.0.1".parse().unwrap(), selected_port)).await;
                match temp_node {
                    Some(node_unlocked) => {
                        temp_node_selected = Some(node_unlocked.lock().await.clone());
                    }
                    None => {}
                }
            }

            assert!(temp_node_selected.is_some(), "Could not retrieve Node with selected port");

            let node_selected = temp_node_selected.unwrap();

            println!("SEARCHING FOR:");
            println!("ID: {}, Address: {}", node_selected.node.id, node_selected.node.address);
            println!("ID: {}, Address: {}", node_random.node.id, node_random.node.address);

            println!("BOOTSTRAP IP: 127.0.0.1:{}", test_node_sock.clone().port());

            node1.join_network(get_global_socket().unwrap().clone(), &test_node_sock).await;

            println!("Joined Network");

            // Perform lookup
            let found_nodes_selected = node1.iterative_find_node(Arc::clone(&node1.socket), node_selected.node.id).await;
            let found_nodes_random = node1.iterative_find_node(Arc::clone(&node1.socket), node_random.node.id).await;

            println!("Send Find Node");

            println!("SEARCH FOR SELECTED NODE WITH PORT {} :: found_nodes: {:?}", selected_port, found_nodes_selected);
            println!("SEARCH FOR RANDOM NODE WITH PORT {} :: found_nodes: {:?}", node_random.node.address.port(), found_nodes_random);
            {
                println!("ROUTING TABLE:\n{}", node1.routing_table.lock().await.to_string().await);
            }

            remove_running(node1.node.lock().await.clone()).await;

            assert_eq!(found_nodes_selected[0], node_selected.node, "Should find selected, and it should be first in the list");
            assert_eq!(found_nodes_random[0], node_random.node, "Should find random node, and it should be first in the list");

        }
        Err(e) => {
            eprintln!("Error loading nodes: {}", e);
            assert!(false, "Could not load nodes");
        },
    }
}

#[tokio::test]
async fn simulated_node_store_test() {
    init_socket_once().await;
    let file_path = "./test_nodes.json";

    // Load nodes from JSON
    match load_simulated_nodes(file_path).await {
        Ok(nodes) => {

            {
                SIM.lock().await.set_nodes(nodes.clone());
            }

            let mut node1 = create_test_node(rand::random::<u128>(), 6000).await;
            let mut node2 = create_test_node(rand::random::<u128>(), 6001).await;

            {
                println!("NODE1:\nID: {}", node1.node.lock().await.id);
                println!("NODE2:\nID: {}", node2.node.lock().await.id);
            }

            let test_node_sock1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % nodes.len() as u16));
            let test_node_sock2 = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % nodes.len() as u16));

            println!("NODE1 BOOTSTRAP IP: 127.0.0.1:{}", test_node_sock1.clone().port());
            println!("NODE2 BOOTSTRAP IP: 127.0.0.1:{}", test_node_sock2.clone().port());

            node1.join_network(get_global_socket().unwrap().clone(), &test_node_sock1).await;
            println!("Node1 Joined Network");
            node2.join_network(get_global_socket().unwrap().clone(), &test_node_sock2).await;
            println!("Node2 Joined Network");

            let key = rand::random::<u128>();
            let value = "PLEASE DEAR GOD LET THIS WORK".to_string();
            println!("STORE:\nKey: {}, Value: {}", key, value);

            // Perform store
            let store_nodes = node1.store_value(Arc::clone(&node1.socket), key, value.clone()).await;
            println!("Send Store");
            assert_eq!(store_nodes.len(), 2, "Should have stored in 2 nodes");

            // Perform search
            let found_value_option = node2.iterative_find_value(Arc::clone(&node2.socket), key).await;
            println!("Search Value");
            assert!(found_value_option.is_some(), "Did not find value");
            let found_value = found_value_option.unwrap();

            remove_running(node1.node.lock().await.clone()).await;
            remove_running(node2.node.lock().await.clone()).await;

            assert_eq!(found_value, value, "Should find value and it should be the correct one.");

            let mut updated_nodes = nodes.clone();
            {
                let sim = SIM.lock().await;
                updated_nodes = sim.get_all_nodes().await;
            }

            // Save the modified nodes back to a new file
            let new_file_path = "./test_nodes_stored.json";
            if let Err(e) = save_simulated_nodes(new_file_path, &updated_nodes).await {
                eprintln!("Error saving nodes: {}", e);
            } else {
                println!("Saved updated nodes to {}", new_file_path);
            }
        }
        Err(e) => {
            eprintln!("Error loading nodes: {}", e);
            assert!(false, "Could not load nodes");
        },
    }
}

#[tokio::test]
async fn simulated_proxy_discovery() {
    init_socket_once().await;
    let file_path = "./test_nodes.json";

    // Load nodes from JSON
    match load_simulated_nodes(file_path).await {
        Ok(nodes) => {

            {
                SIM.lock().await.set_nodes(nodes.clone());
            }

            let mut node1 = create_test_node(rand::random::<u128>(), 6000).await;

            {
                println!("NODE1:\nID: {}", node1.node.lock().await.id);
            }

            let test_node_sock1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % nodes.len() as u16));

            println!("NODE1 BOOTSTRAP IP: 127.0.0.1:{}", test_node_sock1.clone().port());

            node1.join_network(get_global_socket().unwrap().clone(), &test_node_sock1).await;
            println!("Node1 Joined Network");

            node1.garlic.lock().await.discover_proxies(30).await;

            remove_running(node1.node.lock().await.clone()).await;

            let mut updated_nodes = nodes.clone();
            {
                let sim = SIM.lock().await;
                updated_nodes = sim.get_all_nodes().await;
            }

            // Save the modified nodes back to a new file
            let new_file_path = "./test_nodes_stored.json";
            if let Err(e) = save_simulated_nodes(new_file_path, &updated_nodes).await {
                eprintln!("Error saving nodes: {}", e);
            } else {
                println!("Saved updated nodes to {}", new_file_path);
            }
        }
        Err(e) => {
            eprintln!("Error loading nodes: {}", e);
            assert!(false, "Could not load nodes");
        },
    }
}