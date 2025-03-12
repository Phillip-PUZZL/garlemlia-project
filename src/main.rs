use std::net::SocketAddr;
use std::sync::Arc;
use rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::time;
use garlemlia::garlemlia::garlemlia::Garlemlia;
use garlemlia::simulator::simulator::{add_running, get_global_socket, init_socket_once, load_simulated_nodes, remove_running, save_simulated_nodes, SimulatedMessageHandler, SIM, generate_keys};
use garlemlia::garlemlia_structs::garlemlia_structs::{GMessage, Node, RoutingTable};

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

// TODO: Move this to the garlic_cast_tests file when testing of the test finishes XD
async fn check_node_discover() {
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

            node1.garlic.lock().await.discover_proxies(60).await;

            tokio::time::sleep(time::Duration::from_secs(1)).await;

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

async fn create_test_nodes() {
    use garlemlia::simulator::simulator;

    let test_file_path = "./test_nodes.json";
    let keys_file_path = "./keys.json";
    let nodes_to_create: usize = 10000;
    init_socket_once().await;
    simulator::run_create_network(test_file_path, nodes_to_create as u16, keys_file_path).await;

    // Load nodes from JSON
    match load_simulated_nodes(test_file_path).await {
        Ok(nodes) => {
            assert_eq!(nodes.len(), nodes_to_create, "Could not load nodes");
        }
        Err(e) => {
            eprintln!("Error loading nodes: {}", e);
            assert!(false, "Could not load nodes");
        },
    }
}

#[tokio::main]
async fn main() {
    create_test_nodes().await;
}

// Chapter 1: Introduction
// 1.1 Motivation
// 1.2 - ? Rest of intro
// Chapter 2: Statement of problem
// ^^^ Describe interest, problem to solve with new algorithm, what am I basing research on
// Chapter 3: Literature Review
// ^^^ Explain Kademlia and Garlic Cast, good attributes, bad attributes
// 