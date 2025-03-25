use std::io::{stdin, stdout, Write};
use garlemlia::garlemlia::garlemlia::Garlemlia;
use garlemlia::garlemlia_structs::garlemlia_structs::{Node, RoutingTable};
use garlemlia::simulator::simulator::{add_running, get_global_socket, init_socket_once, load_simulated_nodes, remove_running, simulated_to_gmessage, SIM, GarlemliaInfo, save_simulated_nodes, SimulatedNode};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time;
use regex::{Captures, Match, Regex};

async fn create_test_node(id: u128, port: u16) -> Garlemlia {
    let node_actual = Node { id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port) };

    let private_key = RsaPrivateKey::from_pkcs8_pem("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCbUYL5OkM3n8A\nGwpfnpnfT66Fr9QaJg3F6marITjq46f5UX8TvxHkhVXDVfL1tEQzEYnp6+m6+y/l\nPgEvAJjfL/CeX2pIAmoUco1XQjA2Gi4+fbTCaodOLVqQruGZZdcE/UvHGdZHJwOr\nVnmSk7BAX+w4Uj5m7ycAMw+wSaU7wNZV5cQnGOAlMQE4NcJ7uMQYTVIGcI/pehPz\nYeZI2tmu4tgxBzUrMTZENAfIpCnT+d6R6WaMwk2fne/dJ1lYRK76ot9y10RgUuCj\nNn97HXfdqOlk9/uSyDRIfgyF5InqcsoAXXlg6qCwP9SrATuSImMJng5KHrUvbeCr\nUWhFRQYzAgMBAAECggEAZMcjUbL7obIKflGF1P5un7O7sIvtEwi6huXzBa0YxZfv\nT2oQxnl5mswKIlAAuZ8Q4q+qntertUHSF69GCcjzdGxy+oRWoLCvr52Y6avjNYfo\nhHfAJC33qGwVz3z2bv68r1dj2fXofcUZP8x5A6MN7rBJzv/CXLSFsLLG5QenYAqz\nRRLJlC4w7A9qqkassYPdzuFw5GkgEowrOV50DFh/Erw1o8cOHiq5R+MqKYPC1Y69\n2YXaN2qvLbFLtgkRsX9VbWS/WpkKQC8JwI7o67o0d2XFpBm+Pths+UGbALVRfxYd\nn6oi0+o4gbdVYhFcgGO5jvqQNJp+WZwvNftP48TmQQKBgQDgdnam3TlUk6nb8S7b\nnM3rFfxVWlvHNrlihr+oAQ119f36UWbMoIXx75+NUYKMHFbXKRrftj98mfOF0sYz\nYoZ6tcFsE2U7gLZEgoBBd19Y8E7KeObI9NkSe+MMEtL/1e+ivaNO7GSt2nXeiMpP\nu1YFUPDxnKX5Yh/aWeZV4z2kEQKBgQDdvniLbaf7JT9KlVEIyBgN2KXI00DlfQyF\ny0YoMZyuSjHWUo+1kOrn1ALtMHGSMToSNtCUF4Khkn77GYVmFmlfDae0KGJO2/Rg\nFV9mjcedYqBdN1eNQZjkBWC3RZ+nItlM3gRglCqy4nNg/9/n1O163ZZA9mZ9OMPW\nV5vkMZx6AwKBgDXKDar1Dp0G+ch8Jod4Lxxr21k02xOFOK20rs762ZfwCBnpUeIt\ngYu1qZ167/bVf7X14rvDd7lLR0FFfjuoG6PiVGSqzTKSKJuITmXhzlaI18jLajqz\n+iTkzUcCZ8/pG5D7Mtxh58qFtINMcnbi5L1HZUXxDRETA6EWtAzW9NmRAoGBANEZ\nk8KnHQiPDyfdthR523TzHyJJU6EUUoK4NOgiIIWaIXThVfL5PQpvunLAg9g/42rZ\nlcaQhPanlmZiopCqAaNI1SPmEQ4cDE2u2c9zUxDuuBou3biuauZay+EHHo4VJqR9\nl9Ma5UjakcKehx2uhGKgIdgQgoUCymmNI8wDnHLRAoGBAJcu7YA1i6CozXsvoDuw\nRDNCp9yHz8X6qq5OYVI4PRlYH7DiYibDiT8cQ9X2MKwHO6EQTvUJKBo3zhpjkUK0\nXQM8Xau0uiAe+IJaOS4PvsICFGOoXc8VQn99zYabXcIu31LmC/J8pFu1iY47Z20D\nkFOQz9OqdaJ3oPZ6Nq9yY92B\n-----END PRIVATE KEY-----\n").unwrap();
    let public_key = RsaPublicKey::from_public_key_pem("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwm1GC+TpDN5/ABsKX56Z\n30+uha/UGiYNxepmqyE46uOn+VF/E78R5IVVw1Xy9bREMxGJ6evpuvsv5T4BLwCY\n3y/wnl9qSAJqFHKNV0IwNhouPn20wmqHTi1akK7hmWXXBP1LxxnWRycDq1Z5kpOw\nQF/sOFI+Zu8nADMPsEmlO8DWVeXEJxjgJTEBODXCe7jEGE1SBnCP6XoT82HmSNrZ\nruLYMQc1KzE2RDQHyKQp0/nekelmjMJNn53v3SdZWESu+qLfctdEYFLgozZ/ex13\n3ajpZPf7ksg0SH4MheSJ6nLKAF15YOqgsD/UqwE7kiJjCZ4OSh61L23gq1FoRUUG\nMwIDAQAB\n-----END PUBLIC KEY-----\n").unwrap();

    let node = Garlemlia::new_with_details(id, "127.0.0.1", port, RoutingTable::new(node_actual.clone()), simulated_to_gmessage(node_actual.address), get_global_socket().unwrap().clone(), public_key, private_key);

    add_running(node.node.clone().lock().await.clone(), GarlemliaInfo::from(Arc::clone(&node.node), Arc::clone(&node.message_handler), Arc::clone(&node.routing_table), Arc::clone(&node.data_store), Arc::clone(&node.garlic))).await;

    node
}

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

            {
                node1.garlic.lock().await.discover_proxies(60).await;
            }

            tokio::time::sleep(time::Duration::from_secs(3)).await;

            {
                node1.garlic.lock().await.send_search_overlay("HOWDY PARDNER".to_string(), 3).await;
            }

            tokio::time::sleep(time::Duration::from_secs(2)).await;

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

async fn garlemlia_console() {
    // TODO: Finish this to make it viable as a means to control garlemlia
    init_socket_once().await;

    let mut simulated_nodes = Vec::new();

    let mut running_nodes: Vec<Garlemlia> = Vec::new();
    let mut selected: usize = usize::MAX;

    loop {
        let mut s = String::new();
        print!("> ");
        let _ = stdout().flush();
        stdin().read_line(&mut s).expect("Did not enter a correct string");

        if let Some('\n') = s.chars().next_back() {
            s.pop();
        }
        if let Some('\r') = s.chars().next_back() {
            s.pop();
        }

        if s.starts_with("LIST RUNNING") {
            for i in 0..running_nodes.len() {
                if i == selected {
                    print!("* ");
                }
                let now_node = running_nodes[i].node.lock().await;
                println!("{}. ADDRESS: {} ID: {}", i, now_node.address, now_node.id);
            }
        } else if s.starts_with("SELECT RUNNING ") {
            let re = Regex::new(r"\d+").unwrap();
            let result: Option<Match> = re.find(&*s);
            let index: u32 = result.map(|m| m.as_str().parse::<u32>().unwrap()).unwrap_or(0);

            selected = index as usize;
        } else if s.starts_with("LOAD SIM ") {
            let re = Regex::new(r"LOAD SIM (.+)").unwrap();
            let result = re.captures(&*s);
            let Some(file_info) = result else {
                println!("NO PATH GIVEN");
                return;
            };
            let file_path = file_info[1].to_string();

            match load_simulated_nodes(&*file_path).await {
                Ok(nodes) => {
                    simulated_nodes = nodes;
                }
                Err(e) => {
                    eprintln!("Error loading nodes: {}", e);
                    assert!(false, "Could not load nodes");
                },
            }
        } else if s.starts_with("SAVE SIM ") {
            let re = Regex::new(r"SAVE SIM (.+\.json)").unwrap();
            let result: Option<Match> = re.find(&*s);
            let file_path = result.map(|m| m.as_str()).unwrap_or("");

            if let Err(e) = save_simulated_nodes(file_path, &simulated_nodes).await {
                eprintln!("Error saving nodes: {}", e);
            } else {
                println!("Saved updated nodes to {}", file_path);
            }
        } else if s.starts_with("CREATE NODE ") {
            let re = Regex::new(r"\d+").unwrap();
            let result: Option<Match> = re.find(&*s);
            let port: u16 = result.map(|m| m.as_str().parse::<u16>().unwrap()).unwrap_or(0);

            running_nodes.push(create_test_node(rand::random::<u128>(), port).await);
        } else if s.starts_with("JOIN ") {
            let re = Regex::new(r"JOIN (.+):").unwrap();
            let re2 = Regex::new(r":(\d+)").unwrap();

            let result = re.captures(&*s);
            let Some(capture_info) = result else {
                println!("NO PATH GIVEN");
                return;
            };
            let address = capture_info[1].to_string();

            let result = re2.captures(&*s);
            let Some(capture_info) = result else {
                println!("NO PATH GIVEN");
                return;
            };
            let port: u16 = capture_info[1].to_string().parse::<u16>().unwrap();

            running_nodes[selected].join_network(get_global_socket().unwrap().clone(), &SocketAddr::new(address.parse().unwrap(), port)).await;
        } else if s.starts_with("DISCOVER ") {
            let re = Regex::new(r"\d+").unwrap();
            let result: Option<Match> = re.find(&*s);
            let count: u8 = result.map(|m| m.as_str().parse::<u8>().unwrap()).unwrap_or(0);

            {
                running_nodes[selected].garlic.lock().await.discover_proxies(count).await;
            }
        } else if s.starts_with("SEARCH ") {
            if s.starts_with("SEARCH OVERLAY ") {
                let re = Regex::new(r"SEARCH OVERLAY (.+)").unwrap();
                let result: Option<Match> = re.find(&*s);
                let file_name = result.map(|m| m.as_str()).unwrap_or("");

                {
                    running_nodes[selected].garlic.lock().await.send_search_overlay(file_name.parse().unwrap(), 3).await;
                }
            } else if s.starts_with("SEARCH KADEMLIA ") {
                let re = Regex::new(r"\d+").unwrap();
                let result: Option<Match> = re.find(&*s);
                let value: u128 = result.map(|m| m.as_str().parse::<u128>().unwrap()).unwrap_or(0);

                {
                    running_nodes[selected].garlic.lock().await.send_search_kademlia(value).await;
                }
            }
        } else if s.starts_with("CREATE SIMULATED") {
            create_test_nodes().await;

            match load_simulated_nodes("./test_nodes.json").await {
                Ok(nodes) => {
                    simulated_nodes = nodes;
                }
                Err(e) => {
                    eprintln!("Error loading nodes: {}", e);
                    assert!(false, "Could not load nodes");
                },
            }
        } else if s.starts_with("QUIT") {
            break
        }
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