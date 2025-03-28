use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use primitive_types::U256;
use rand::seq::IndexedRandom;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use garlemlia::garlemlia::garlemlia::Garlemlia;
use garlemlia::simulator::simulator::{get_global_socket, load_simulated_nodes, save_simulated_nodes, SimulatedMessageHandler, SIM, add_running, remove_running, init_socket_once, GarlemliaInfo};
use garlemlia::garlemlia_structs::garlemlia_structs::{GMessage, RoutingTable, Node, GarlemliaData, u256_random, GarlemliaStoreRequest, GarlemliaFindRequest, GarlemliaResponse};

async fn create_test_node(id: U256, port: u16) -> Garlemlia {
    let node_actual = Node { id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port) };

    let private_key = RsaPrivateKey::from_pkcs8_pem("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCbUYL5OkM3n8A\nGwpfnpnfT66Fr9QaJg3F6marITjq46f5UX8TvxHkhVXDVfL1tEQzEYnp6+m6+y/l\nPgEvAJjfL/CeX2pIAmoUco1XQjA2Gi4+fbTCaodOLVqQruGZZdcE/UvHGdZHJwOr\nVnmSk7BAX+w4Uj5m7ycAMw+wSaU7wNZV5cQnGOAlMQE4NcJ7uMQYTVIGcI/pehPz\nYeZI2tmu4tgxBzUrMTZENAfIpCnT+d6R6WaMwk2fne/dJ1lYRK76ot9y10RgUuCj\nNn97HXfdqOlk9/uSyDRIfgyF5InqcsoAXXlg6qCwP9SrATuSImMJng5KHrUvbeCr\nUWhFRQYzAgMBAAECggEAZMcjUbL7obIKflGF1P5un7O7sIvtEwi6huXzBa0YxZfv\nT2oQxnl5mswKIlAAuZ8Q4q+qntertUHSF69GCcjzdGxy+oRWoLCvr52Y6avjNYfo\nhHfAJC33qGwVz3z2bv68r1dj2fXofcUZP8x5A6MN7rBJzv/CXLSFsLLG5QenYAqz\nRRLJlC4w7A9qqkassYPdzuFw5GkgEowrOV50DFh/Erw1o8cOHiq5R+MqKYPC1Y69\n2YXaN2qvLbFLtgkRsX9VbWS/WpkKQC8JwI7o67o0d2XFpBm+Pths+UGbALVRfxYd\nn6oi0+o4gbdVYhFcgGO5jvqQNJp+WZwvNftP48TmQQKBgQDgdnam3TlUk6nb8S7b\nnM3rFfxVWlvHNrlihr+oAQ119f36UWbMoIXx75+NUYKMHFbXKRrftj98mfOF0sYz\nYoZ6tcFsE2U7gLZEgoBBd19Y8E7KeObI9NkSe+MMEtL/1e+ivaNO7GSt2nXeiMpP\nu1YFUPDxnKX5Yh/aWeZV4z2kEQKBgQDdvniLbaf7JT9KlVEIyBgN2KXI00DlfQyF\ny0YoMZyuSjHWUo+1kOrn1ALtMHGSMToSNtCUF4Khkn77GYVmFmlfDae0KGJO2/Rg\nFV9mjcedYqBdN1eNQZjkBWC3RZ+nItlM3gRglCqy4nNg/9/n1O163ZZA9mZ9OMPW\nV5vkMZx6AwKBgDXKDar1Dp0G+ch8Jod4Lxxr21k02xOFOK20rs762ZfwCBnpUeIt\ngYu1qZ167/bVf7X14rvDd7lLR0FFfjuoG6PiVGSqzTKSKJuITmXhzlaI18jLajqz\n+iTkzUcCZ8/pG5D7Mtxh58qFtINMcnbi5L1HZUXxDRETA6EWtAzW9NmRAoGBANEZ\nk8KnHQiPDyfdthR523TzHyJJU6EUUoK4NOgiIIWaIXThVfL5PQpvunLAg9g/42rZ\nlcaQhPanlmZiopCqAaNI1SPmEQ4cDE2u2c9zUxDuuBou3biuauZay+EHHo4VJqR9\nl9Ma5UjakcKehx2uhGKgIdgQgoUCymmNI8wDnHLRAoGBAJcu7YA1i6CozXsvoDuw\nRDNCp9yHz8X6qq5OYVI4PRlYH7DiYibDiT8cQ9X2MKwHO6EQTvUJKBo3zhpjkUK0\nXQM8Xau0uiAe+IJaOS4PvsICFGOoXc8VQn99zYabXcIu31LmC/J8pFu1iY47Z20D\nkFOQz9OqdaJ3oPZ6Nq9yY92B\n-----END PRIVATE KEY-----\n").unwrap();
    let public_key = RsaPublicKey::from_public_key_pem("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwm1GC+TpDN5/ABsKX56Z\n30+uha/UGiYNxepmqyE46uOn+VF/E78R5IVVw1Xy9bREMxGJ6evpuvsv5T4BLwCY\n3y/wnl9qSAJqFHKNV0IwNhouPn20wmqHTi1akK7hmWXXBP1LxxnWRycDq1Z5kpOw\nQF/sOFI+Zu8nADMPsEmlO8DWVeXEJxjgJTEBODXCe7jEGE1SBnCP6XoT82HmSNrZ\nruLYMQc1KzE2RDQHyKQp0/nekelmjMJNn53v3SdZWESu+qLfctdEYFLgozZ/ex13\n3ajpZPf7ksg0SH4MheSJ6nLKAF15YOqgsD/UqwE7kiJjCZ4OSh61L23gq1FoRUUG\nMwIDAQAB\n-----END PUBLIC KEY-----\n").unwrap();


    let mut node = Garlemlia::new_with_details(id, "127.0.0.1", port, RoutingTable::new(node_actual.clone()), SimulatedMessageHandler::create(0), get_global_socket().unwrap().clone(), public_key, private_key, Box::new(Path::new("./running_nodes_files"))).await;

    add_running(node.node.clone().lock().await.clone(), GarlemliaInfo::from(Arc::clone(&node.node), Arc::clone(&node.message_handler), Arc::clone(&node.routing_table), Arc::clone(&node.data_store), Arc::clone(&node.garlic), Arc::clone(&node.file_storage))).await;

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

            let mut node1 = create_test_node(u256_random(), 6000).await;

            {
                println!("NODE:\nID: {}", node1.node.lock().await.id);
            }

            let test_node_sock = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % nodes.len() as u16));

            println!("BOOTSTRAP IP: 127.0.0.1:{}", test_node_sock.clone().port());

            node1.join_network(get_global_socket().unwrap().clone(), &test_node_sock).await;

            println!("Joined Network");

            for node_selected in nodes {
                // Perform lookup
                let found_nodes_selected = node1.iterative_find_node(Arc::clone(&node1.socket), node_selected.node.id).await;

                assert_eq!(found_nodes_selected[0], node_selected.node, "Should find selected, and it should be first in the list");

                if found_nodes_selected[0].id != node_selected.node.id {
                    break;
                }
            }

            {
                println!("ROUTING TABLE:\n{}", node1.routing_table.lock().await.to_string().await);
            }

            remove_running(node1.node.lock().await.clone()).await;
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

            let mut node1 = create_test_node(u256_random(), 6000).await;
            let mut node2 = create_test_node(u256_random(), 6001).await;

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

            let key = u256_random();
            let value = "PLEASE DEAR GOD LET THIS WORK".to_string();
            println!("STORE:\nKey: {}, Value: {}", key, value);

            // Perform store
            let store_nodes = node1.store_value(Arc::clone(&node1.socket), GarlemliaStoreRequest::Value { id: key, value: value.clone() }, 2).await;
            println!("Send Store");
            assert_eq!(store_nodes.len(), 2, "Should have stored in 2 nodes");

            // Perform search
            let found_value_option = node2.iterative_find_value(Arc::clone(&node2.socket), GarlemliaFindRequest::Key { id: key }).await;
            println!("Search Value");
            assert!(found_value_option.is_some(), "Did not find value");
            let found_value = found_value_option;

            remove_running(node1.node.lock().await.clone()).await;
            remove_running(node2.node.lock().await.clone()).await;

            match found_value {
                Some(found_value_yeet) => {
                    match found_value_yeet {
                        GarlemliaResponse::Value { value: found_value } => {
                            assert_eq!(found_value, value, "Should find value and it should be the correct one.");
                            println!("Found value: {}", found_value);
                        }
                        _ => {
                            assert!(false, "Value should be value type");
                        }
                    }
                }
                _ => {
                    assert!(false, "Value should be found");
                }
            }

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

            let mut node1 = create_test_node(u256_random(), 6000).await;

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