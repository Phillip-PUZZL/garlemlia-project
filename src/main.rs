use std::collections::HashMap;
use garlemlia::garlemlia::garlemlia::Garlemlia;
use garlemlia::garlemlia_structs::garlemlia_structs::{u256_random, GarlemliaResponse, Node, RoutingTable};
use garlemlia::simulator::simulator::{add_running, get_global_socket, init_socket_once, load_simulated_nodes, save_simulated_nodes, simulated_to_gmessage, GarlemliaInfo, SIM};
use primitive_types::U256;
use regex::{Match, Regex};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::io::{stdin, stdout, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use garlemlia::file_utils::garlemlia_files::{FileInfo, FileUpload};

async fn create_test_node(id: U256, port: u16) -> Garlemlia {
    let node_actual = Node { id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port) };

    let private_key = RsaPrivateKey::from_pkcs8_pem("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCbUYL5OkM3n8A\nGwpfnpnfT66Fr9QaJg3F6marITjq46f5UX8TvxHkhVXDVfL1tEQzEYnp6+m6+y/l\nPgEvAJjfL/CeX2pIAmoUco1XQjA2Gi4+fbTCaodOLVqQruGZZdcE/UvHGdZHJwOr\nVnmSk7BAX+w4Uj5m7ycAMw+wSaU7wNZV5cQnGOAlMQE4NcJ7uMQYTVIGcI/pehPz\nYeZI2tmu4tgxBzUrMTZENAfIpCnT+d6R6WaMwk2fne/dJ1lYRK76ot9y10RgUuCj\nNn97HXfdqOlk9/uSyDRIfgyF5InqcsoAXXlg6qCwP9SrATuSImMJng5KHrUvbeCr\nUWhFRQYzAgMBAAECggEAZMcjUbL7obIKflGF1P5un7O7sIvtEwi6huXzBa0YxZfv\nT2oQxnl5mswKIlAAuZ8Q4q+qntertUHSF69GCcjzdGxy+oRWoLCvr52Y6avjNYfo\nhHfAJC33qGwVz3z2bv68r1dj2fXofcUZP8x5A6MN7rBJzv/CXLSFsLLG5QenYAqz\nRRLJlC4w7A9qqkassYPdzuFw5GkgEowrOV50DFh/Erw1o8cOHiq5R+MqKYPC1Y69\n2YXaN2qvLbFLtgkRsX9VbWS/WpkKQC8JwI7o67o0d2XFpBm+Pths+UGbALVRfxYd\nn6oi0+o4gbdVYhFcgGO5jvqQNJp+WZwvNftP48TmQQKBgQDgdnam3TlUk6nb8S7b\nnM3rFfxVWlvHNrlihr+oAQ119f36UWbMoIXx75+NUYKMHFbXKRrftj98mfOF0sYz\nYoZ6tcFsE2U7gLZEgoBBd19Y8E7KeObI9NkSe+MMEtL/1e+ivaNO7GSt2nXeiMpP\nu1YFUPDxnKX5Yh/aWeZV4z2kEQKBgQDdvniLbaf7JT9KlVEIyBgN2KXI00DlfQyF\ny0YoMZyuSjHWUo+1kOrn1ALtMHGSMToSNtCUF4Khkn77GYVmFmlfDae0KGJO2/Rg\nFV9mjcedYqBdN1eNQZjkBWC3RZ+nItlM3gRglCqy4nNg/9/n1O163ZZA9mZ9OMPW\nV5vkMZx6AwKBgDXKDar1Dp0G+ch8Jod4Lxxr21k02xOFOK20rs762ZfwCBnpUeIt\ngYu1qZ167/bVf7X14rvDd7lLR0FFfjuoG6PiVGSqzTKSKJuITmXhzlaI18jLajqz\n+iTkzUcCZ8/pG5D7Mtxh58qFtINMcnbi5L1HZUXxDRETA6EWtAzW9NmRAoGBANEZ\nk8KnHQiPDyfdthR523TzHyJJU6EUUoK4NOgiIIWaIXThVfL5PQpvunLAg9g/42rZ\nlcaQhPanlmZiopCqAaNI1SPmEQ4cDE2u2c9zUxDuuBou3biuauZay+EHHo4VJqR9\nl9Ma5UjakcKehx2uhGKgIdgQgoUCymmNI8wDnHLRAoGBAJcu7YA1i6CozXsvoDuw\nRDNCp9yHz8X6qq5OYVI4PRlYH7DiYibDiT8cQ9X2MKwHO6EQTvUJKBo3zhpjkUK0\nXQM8Xau0uiAe+IJaOS4PvsICFGOoXc8VQn99zYabXcIu31LmC/J8pFu1iY47Z20D\nkFOQz9OqdaJ3oPZ6Nq9yY92B\n-----END PRIVATE KEY-----\n").unwrap();
    let public_key = RsaPublicKey::from_public_key_pem("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwm1GC+TpDN5/ABsKX56Z\n30+uha/UGiYNxepmqyE46uOn+VF/E78R5IVVw1Xy9bREMxGJ6evpuvsv5T4BLwCY\n3y/wnl9qSAJqFHKNV0IwNhouPn20wmqHTi1akK7hmWXXBP1LxxnWRycDq1Z5kpOw\nQF/sOFI+Zu8nADMPsEmlO8DWVeXEJxjgJTEBODXCe7jEGE1SBnCP6XoT82HmSNrZ\nruLYMQc1KzE2RDQHyKQp0/nekelmjMJNn53v3SdZWESu+qLfctdEYFLgozZ/ex13\n3ajpZPf7ksg0SH4MheSJ6nLKAF15YOqgsD/UqwE7kiJjCZ4OSh61L23gq1FoRUUG\nMwIDAQAB\n-----END PUBLIC KEY-----\n").unwrap();

    let node = Garlemlia::new_with_details(id, "127.0.0.1", port, RoutingTable::new(node_actual.clone()), simulated_to_gmessage(node_actual.address), get_global_socket().unwrap().clone(), public_key, private_key, Box::new(Path::new("./running_nodes_files"))).await;

    add_running(node.node.clone().lock().await.clone(), GarlemliaInfo::from(Arc::clone(&node.node), Arc::clone(&node.message_handler), Arc::clone(&node.routing_table), Arc::clone(&node.data_store), Arc::clone(&node.garlic), Arc::clone(&node.file_storage))).await;

    node
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

    let mut running_nodes: Vec<Garlemlia> = Vec::new();
    let mut simulated_nodes;

    let mut proxies_show = vec![];
    let mut search_proxy_ids = vec![];
    let mut selected_search_proxies = vec![];
    let mut file_proxy_ids = vec![];
    let mut selected_file_proxies = vec![];
    let mut found_files: Vec<FileInfo> = vec![];
    let mut file_info_responses: HashMap<U256, Vec<GarlemliaResponse>> = HashMap::new();
    let mut file_download_responses: HashMap<U256, Vec<GarlemliaResponse>> = HashMap::new();
    let mut pending_downloads = vec![];
    let mut downloads = HashMap::new();

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

        if s.starts_with("RUNNING") {
            for i in 0..running_nodes.len() {
                if i == selected {
                    print!("* ");
                }
                let now_node = running_nodes[i].node.lock().await;
                println!("{}. ADDRESS: {} ID: {}", i, now_node.address, now_node.id);
            }
        } else if s.starts_with("PROXIES") {
            proxies_show = running_nodes[selected].garlic.lock().await.get_proxies();
            proxies_show.sort_by_key(|p| p.neighbor_1_hops + p.neighbor_2_hops);

            for i in 0..proxies_show.len() {
                if selected_search_proxies.contains(&proxies_show[i]) {
                    print!("* ");
                }
                if selected_file_proxies.contains(&proxies_show[i]) {
                    print!("+ ");
                }
                let now_proxy = proxies_show[i].clone();
                println!("{}. TOTAL HOPS: {} N1 HOPS: {} N2 HOPS: {} SN: {}", i, now_proxy.neighbor_1_hops + now_proxy.neighbor_2_hops, now_proxy.neighbor_1_hops, now_proxy.neighbor_2_hops, now_proxy.sequence_number);
            }
        } else if s.starts_with("SELECT RUNNING ") {
            let re = Regex::new(r"\d+").unwrap();
            let result: Option<Match> = re.find(&*s);
            let index: u32 = result.map(|m| m.as_str().parse::<u32>().unwrap()).unwrap_or(0);

            selected = index as usize;
        } else if s.starts_with("SELECT S PROXIES ") {
            let re = Regex::new(r"\d+").unwrap();
            // Find all digit sequences, collect them into a Vec
            let numbers: Vec<usize> = re.find_iter(&*s).map(|m| m.as_str().parse::<usize>().unwrap()).collect();

            selected_search_proxies.clear();
            search_proxy_ids.clear();
            for num in numbers {
                selected_search_proxies.push(proxies_show[num].clone());
                search_proxy_ids.push(proxies_show[num].clone().sequence_number);
            }
        } else if s.starts_with("SELECT D PROXIES ") {
            let re = Regex::new(r"\d+").unwrap();
            // Find all digit sequences, collect them into a Vec
            let numbers: Vec<usize> = re.find_iter(&*s).map(|m| m.as_str().parse::<usize>().unwrap()).collect();

            selected_file_proxies.clear();
            file_proxy_ids.clear();
            for num in numbers {
                selected_file_proxies.push(proxies_show[num].clone());
                file_proxy_ids.push(proxies_show[num].clone().sequence_number);
            }
        } else if s.starts_with("LOAD SIM ") {
            let re = Regex::new(r"LOAD SIM (.+)").unwrap();
            let result = re.captures(&*s);
            let Some(file_info) = result else {
                println!("NO PATH GIVEN");
                continue;
            };
            let file_path = file_info[1].to_string();

            match load_simulated_nodes(&*file_path).await {
                Ok(nodes) => {
                    {
                        SIM.lock().await.set_nodes(nodes.clone());
                    }
                    simulated_nodes = nodes.clone();
                }
                Err(e) => {
                    eprintln!("Error loading nodes: {}", e);
                    assert!(false, "Could not load nodes");
                },
            }
        } else if s.starts_with("SAVE SIM ") {
            let re = Regex::new(r"SAVE SIM (.+\.json)").unwrap();
            let result = re.captures(&*s);
            let Some(file_info) = result else {
                println!("NO PATH GIVEN");
                continue;
            };
            let file_path = file_info[1].to_string();

            {
                let sim = SIM.lock().await;
                simulated_nodes = sim.get_all_nodes().await;
            }

            if let Err(e) = save_simulated_nodes(&*file_path, &simulated_nodes).await {
                eprintln!("Error saving nodes: {}", e);
            } else {
                println!("Saved updated nodes to {}", file_path);
            }
        } else if s.starts_with("JOIN ") {
            let re = Regex::new(r"JOIN (.+):").unwrap();
            let re2 = Regex::new(r":(\d+)").unwrap();

            let result = re.captures(&*s);
            let Some(capture_info) = result else {
                println!("NO PATH GIVEN");
                continue;
            };
            let address = capture_info[1].to_string();

            let result = re2.captures(&*s);
            let Some(capture_info) = result else {
                println!("NO PATH GIVEN");
                continue;
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
                let result = re.captures(&*s);
                let Some(file_info) = result else {
                    println!("NO FILE NAME GIVEN");
                    continue;
                };
                let file_name = file_info[1].to_string();

                {
                    running_nodes[selected].garlic.lock().await.search_overlay(file_name.parse().unwrap(), search_proxy_ids.clone(), search_proxy_ids.len() as u8).await;
                }
            } else if s.starts_with("SEARCH KADEMLIA ") {
                let re = Regex::new(r"\d+").unwrap();
                let result: Option<Match> = re.find(&*s);
                let value: U256 = result.map(|m| m.as_str().parse::<U256>().unwrap()).unwrap_or(U256::from(0));

                {
                    running_nodes[selected].garlic.lock().await.search_kademlia(search_proxy_ids.clone(), value).await;
                }
            }
        } else if s.starts_with("UPLOAD FILE ") {
            let re = Regex::new(r"UPLOAD FILE (.+)").unwrap();
            let result = re.captures(&*s);
            let Some(file_info) = result else {
                println!("NO FILE PATH GIVEN");
                continue;
            };
            let file_name = file_info[1].to_string();
            
            let output_folder_name;
            {
                output_folder_name = running_nodes[selected].file_storage.lock().await.temp_chunk_data_path.clone();
            }

            let info = FileUpload::encrypt_file(Box::from(Path::new(&file_name)), Box::from(Path::new(&output_folder_name))).await.unwrap();

            let encrypted_file_name = format!("{}/{}.{}.enc", output_folder_name, info.name, info.file_type);

            let chunks_info = FileUpload::split_into_chunks(Box::from(Path::new(&encrypted_file_name)), 8).await.unwrap();

            let file_upload = FileUpload::new(info, chunks_info, 10000.0);

            {
                let file_storage = running_nodes[selected].file_storage.lock().await.clone();
                running_nodes[selected].garlic.lock().await.store_file(file_upload, search_proxy_ids.clone(), file_proxy_ids.clone(), file_storage).await;
            }
        } else if s.starts_with("GET FILE INFO ") {
            let re = Regex::new(r"\d+").unwrap();
            let result: Option<Match> = re.find(&*s);
            let file_location: u16 = result.map(|m| m.as_str().parse::<u16>().unwrap()).unwrap_or(0);

            let file_info: FileInfo = found_files[file_location as usize].clone();

            {
                let request_id = running_nodes[selected].garlic.lock().await.get_file_info(search_proxy_ids.clone(), file_info.metadata_location, file_info.key_location).await.clone();
                pending_downloads.push(request_id);
                found_files[file_location as usize].set_request_id(request_id);
            }
        } else if s.starts_with("DOWNLOAD FILE ") {
            let re = Regex::new(r"\d+").unwrap();
            let result: Option<Match> = re.find(&*s);
            let file_location: u16 = result.map(|m| m.as_str().parse::<u16>().unwrap()).unwrap_or(0);

            let file_info: FileInfo = found_files[file_location as usize].clone();

            {
                let request_id = running_nodes[selected].garlic.lock().await.download_file(file_info.clone(), file_proxy_ids.clone()).await.clone();
                downloads.insert(request_id, file_info.get_request_id());
            }
        } else if s.starts_with("COLLECT SEARCHES") {
            {
                found_files.extend(running_nodes[selected].garlic.lock().await.get_search_responses());
                found_files.dedup();
            }
            
            for i in 0..found_files.len() {
                println!("{}. Name: {}, Type: {}, Size: {}", i, found_files[i].name, found_files[i].file_type, found_files[i].size);
            }
        } else if s.starts_with("COLLECT FILE INFO") {
            {
                file_info_responses = running_nodes[selected].garlic.lock().await.get_file_info_responses();
            }

            let mut le_new = vec![];
            for i in 0..pending_downloads.len() {
                let file_info = file_info_responses.get(&pending_downloads[i]).unwrap();
                for mut found_item in found_files.clone() {
                    if found_item.get_request_id() == pending_downloads[i] {
                        for item in file_info {
                            found_item = item.add_to_file_information(found_item).unwrap();
                        }
                        le_new.push(found_item.clone());

                        println!("{}. {}", i, found_item.to_string());

                        break;
                    }
                }
            }

            found_files.extend(le_new);
            found_files.dedup_by(|f, f2| f.get_request_id() == f2.get_request_id());
        } else if s.starts_with("COLLECT DOWNLOADS") {
            {
                file_download_responses = running_nodes[selected].garlic.lock().await.get_download_responses();
            }

            let mut le_new = vec![];
            for i in 0..pending_downloads.len() {
                let file_info = file_download_responses.get(&pending_downloads[i]).unwrap();
                for mut found_item in found_files.clone() {
                    if found_item.get_request_id() == pending_downloads[i] {
                        for item in file_info {
                            found_item = item.add_to_file_information(found_item).unwrap();
                        }
                        le_new.push(found_item.clone());

                        println!("{}. {}", i, found_item.to_string());

                        break;
                    }
                }
            }

            found_files.extend(le_new);
            found_files.dedup_by(|f, f2| f.get_request_id() == f2.get_request_id());
        } else if s.starts_with("CONNECT SIMULATED ") {
            let re = Regex::new(r"CONNECT SIMULATED (.+)").unwrap();
            let result = re.captures(&*s);
            let Some(node_info) = result else {
                println!("NO NODE GIVEN");
                continue;
            };
            let mut node_address = node_info[1].to_string();
            node_address = node_address.replace("::", "127.0.0.1:");

            let address_vec = node_address.split(':').collect::<Vec<&str>>();

            {
                let res = SIM.lock().await.connect(SocketAddr::new(address_vec[0].parse().unwrap(), address_vec[1].parse().unwrap())).await;

                match res {
                    Ok(_) => {}
                    Err(_) => {
                        println!("COULD NOT FIND SIMULATED NODE");
                    }
                }
            }
        } else if s.starts_with("DISCONNECT SIMULATED ") {
            let re = Regex::new(r"DISCONNECT SIMULATED (.+)").unwrap();
            let result = re.captures(&*s);
            let Some(node_info) = result else {
                println!("NO NODE GIVEN");
                continue;
            };
            let mut node_address = node_info[1].to_string();
            node_address = node_address.replace("::", "127.0.0.1:");

            let address_vec = node_address.split(':').collect::<Vec<&str>>();

            {
                let res = SIM.lock().await.disconnect(SocketAddr::new(address_vec[0].parse().unwrap(), address_vec[1].parse().unwrap())).await;

                match res {
                    Ok(_) => {}
                    Err(_) => {
                        println!("COULD NOT FIND SIMULATED NODE");
                    }
                }
            }
        }  else if s.starts_with("CREATE SIMULATED") {
            create_test_nodes().await;

            match load_simulated_nodes("./test_nodes.json").await {
                Ok(nodes) => {
                    {
                        SIM.lock().await.set_nodes(nodes.clone());
                    }
                    simulated_nodes = nodes.clone();
                }
                Err(e) => {
                    eprintln!("Error loading nodes: {}", e);
                    assert!(false, "Could not load nodes");
                },
            }
        } else if s.starts_with("CREATE ") {
            let re = Regex::new(r"\d+").unwrap();
            let result: Option<Match> = re.find(&*s);
            let port: u16 = result.map(|m| m.as_str().parse::<u16>().unwrap()).unwrap_or(0);

            running_nodes.push(create_test_node(u256_random(), port).await);
        } else if s.starts_with("INIT ") {
            if s.starts_with("INIT TEST") {
                match load_simulated_nodes("./test_nodes.json").await {
                    Ok(nodes) => {
                        {
                            SIM.lock().await.set_nodes(nodes.clone());
                        }
                        simulated_nodes = nodes.clone();
                        println!("Started {} simulated nodes!", nodes.len());
                    }
                    Err(e) => {
                        eprintln!("Error loading nodes: {}", e);
                        continue;
                    },
                }

                running_nodes.push(create_test_node(u256_random(), 6000).await);
                selected = 0;
                {
                    println!("Started and selected NODE :: {}", running_nodes[selected].node.lock().await.id);
                }

                let test_node_sock1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % simulated_nodes.len() as u16));

                running_nodes[selected].join_network(get_global_socket().unwrap().clone(), &test_node_sock1).await;
                {
                    println!("Joined network at address {} :: ROUTING TABLE :: {} ", test_node_sock1.to_string(), running_nodes[selected].routing_table.lock().await.flat_nodes().await.len());
                }

                {
                    running_nodes[selected].garlic.lock().await.discover_proxies(60).await;
                }

                sleep(Duration::from_secs(2)).await;

                {
                    proxies_show = running_nodes[selected].garlic.lock().await.get_proxies();
                    proxies_show.sort_by_key(|p| p.neighbor_1_hops + p.neighbor_2_hops);
                }

                for num in 0..3 {
                    selected_search_proxies.push(proxies_show[num].clone());
                    search_proxy_ids.push(proxies_show[num].clone().sequence_number);
                }

                for num in 1..5 {
                    selected_file_proxies.push(proxies_show[proxies_show.len() - num].clone());
                    file_proxy_ids.push(proxies_show[proxies_show.len() - num].clone().sequence_number);
                }

                let file_name = "./file_example.png";

                let output_folder_name;
                {
                    output_folder_name = running_nodes[selected].file_storage.lock().await.temp_chunk_data_path.clone();
                }

                let info = FileUpload::encrypt_file(Box::from(Path::new(&file_name)), Box::from(Path::new(&output_folder_name))).await.unwrap();

                let encrypted_file_name = format!("{}/{}.{}.enc", output_folder_name, info.name, info.file_type);

                let chunks_info = FileUpload::split_into_chunks(Box::from(Path::new(&encrypted_file_name)), 8).await.unwrap();

                let file_upload = FileUpload::new(info, chunks_info, 10000.0);

                {
                    let file_storage = running_nodes[selected].file_storage.lock().await.clone();
                    running_nodes[selected].garlic.lock().await.store_file(file_upload.clone(), search_proxy_ids.clone(), file_proxy_ids.clone(), file_storage).await;
                }

                sleep(Duration::from_secs(5)).await;

                for chunk in file_upload.chunks {
                    let chunk_file_name = hex::encode(chunk.chunk_id.to_big_endian());

                    let chunk_file_location = format!("{}/{}", output_folder_name, chunk_file_name);

                    let _chunk_delete = fs::remove_file(chunk_file_location.clone()).await;
                }

                {
                    let sim = SIM.lock().await;
                    simulated_nodes = sim.get_all_nodes().await;
                }

                if let Err(e) = save_simulated_nodes("./test_nodes_stored.json", &simulated_nodes).await {
                    eprintln!("Error saving nodes: {}", e);
                } else {
                    println!("Saved updated nodes to ./test_nodes_stored.json");
                }

                let mut metadata_loc = file_upload.metadata_location.clone();
                metadata_loc.store();
                let mut key_loc = file_upload.key_location.clone();
                key_loc.store();

                found_files.push(FileInfo::from(file_upload.name, file_upload.file_type, file_upload.size, file_upload.categories, metadata_loc.get_next(24, 1.0).unwrap(), key_loc.get_next(24, 1.0).unwrap()));
            } else {
                let re = Regex::new(r"INIT (.+\.json)").unwrap();
                let result = re.captures(&*s);
                let Some(file_info) = result else {
                    println!("NO PATH GIVEN");
                    continue;
                };
                let file_path = file_info[1].to_string();
                
                match load_simulated_nodes(&*file_path).await {
                    Ok(nodes) => {
                        {
                            SIM.lock().await.set_nodes(nodes.clone());
                        }
                        simulated_nodes = nodes.clone();
                        println!("Started {} simulated nodes!", nodes.len());
                    }
                    Err(e) => {
                        eprintln!("Error loading nodes: {}", e);
                        continue;
                    },
                }

                running_nodes.push(create_test_node(u256_random(), 6000).await);
                selected = 0;
                {
                    println!("Started and selected NODE :: {}", running_nodes[selected].node.lock().await.id);
                }

                let test_node_sock1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % simulated_nodes.len() as u16));

                running_nodes[selected].join_network(get_global_socket().unwrap().clone(), &test_node_sock1).await;
                {
                    println!("Joined network at address {} :: ROUTING TABLE :: {} ", test_node_sock1.to_string(), running_nodes[selected].routing_table.lock().await.flat_nodes().await.len());
                }
            }
        } else if s.starts_with("QUIT") {
            break
        }
    }
}

#[tokio::main]
async fn main() {
    let dir_path = Path::new("./running_nodes_files");

    if dir_path.exists() && dir_path.is_dir() {
        fs::remove_dir_all(dir_path).await.unwrap();
        println!("Old Running Nodes Folder Removed!");
    }

    fs::create_dir(dir_path).await.unwrap();

    garlemlia_console().await;
    //create_test_nodes().await;
}