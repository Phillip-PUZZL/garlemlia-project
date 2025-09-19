use std::collections::HashMap;
use std::net::{SocketAddr};
use std::path::Path;
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use primitive_types::U256;
use rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex};
use tokio::{fs, task};

use garlic_cast::GarlicCast;

use crate::garlic_cast::garlic_cast;
use crate::file_utils::garlemlia_files::FileStorage;
use crate::structs::constants::{SOCKET_DATA_MAX};
use crate::structs::file_chunks::{ChunkPartAssociations, ProcessingCheck};
use crate::structs::garlemlia_message::{GMessage, GarlemliaMessage, MessageChannel};
use crate::structs::node::Node;
use crate::structs::routing_table::RoutingTable;
use crate::structs::garlemlia_data::GarlemliaData;

mod functions;
mod find;
mod network;
mod store;

pub use functions::GarlemliaFunctions;

// Kademlia Struct
#[derive(Clone)]
pub struct Garlemlia {
    pub node: Arc<Mutex<Node>>,
    pub socket: Arc<UdpSocket>,
    pub receive_addr: SocketAddr,
    pub message_handler: Arc<Box<dyn GMessage>>,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
    pub file_storage: Arc<Mutex<FileStorage>>,
    pub garlic: Arc<Mutex<GarlicCast>>,
    pub chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
    is_processing: Arc<Mutex<ProcessingCheck>>,
    stop_signal: Arc<AtomicBool>,
    join_handle: Arc<Option<task::JoinHandle<()>>>,
}

// TODO: Implement new event thread for watching last_seen information and pinging nodes
// TODO: which have not been seen in an hour + evicting those which fail
// TODO: Add RPC ID's to messages?
impl Garlemlia {
    pub async fn new(id: U256, address: &str, port: u16, rt: RoutingTable, msg_handler: Box<dyn GMessage>, file_storage_path: Box<&Path>) -> Self {
        let mut dir_id = file_storage_path.join(id.to_string());
        dir_id.push("downloads");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("temp_chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();

        let root_dir = format!("{}/{}", file_storage_path.to_str().unwrap(), id);
        let file_storage = FileStorage::new(root_dir.clone(), format!("{}/file_storage.json", root_dir), format!("{}/downloads", root_dir), format!("{}/chunks", root_dir), format!("{}/temp_chunks", root_dir));

        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };
        let socket = Arc::new(UdpSocket::bind(format!("{}:{}", address, port)).await.unwrap());

        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let garlic = GarlicCast::new(Arc::clone(&socket), node.clone(), Arc::new(msg_handler.clone()), vec![], Some(public_key), Some(private_key));

        Self {
            node: Arc::new(Mutex::new(node)),
            socket,
            receive_addr: format!("{address}:{port}").parse().unwrap(),
            message_handler: Arc::new(msg_handler),
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            file_storage: Arc::new(Mutex::new(file_storage)),
            garlic: Arc::new(Mutex::new(garlic)),
            chunk_part_associations: Arc::new(Mutex::new(ChunkPartAssociations::new())),
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false))),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
        }
    }

    pub async fn new_with_details(id: U256, address: &str, port: u16, rt: RoutingTable, msg_handler: Box<dyn GMessage>, socket: Arc<UdpSocket>, public_key: RsaPublicKey, private_key: RsaPrivateKey, file_storage_path: Box<&Path>) -> Self {
        let mut dir_id = file_storage_path.join(id.to_string());
        dir_id.push("downloads");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("temp_chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();

        let root_dir = format!("{}/{}", file_storage_path.to_str().unwrap(), id);
        let file_storage = FileStorage::new(root_dir.clone(), format!("{}/file_storage.json", root_dir), format!("{}/downloads", root_dir), format!("{}/chunks", root_dir), format!("{}/temp_chunks", root_dir));

        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };

        let message_handler = Arc::new(msg_handler);

        let garlic = GarlicCast::new(Arc::clone(&socket), node.clone(), Arc::clone(&message_handler), vec![], Some(public_key), Some(private_key));

        Self {
            node: Arc::new(Mutex::new(node)),
            socket: Arc::clone(&socket),
            receive_addr: format!("{address}:{port}").parse().unwrap(),
            message_handler,
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            file_storage: Arc::new(Mutex::new(file_storage)),
            garlic: Arc::new(Mutex::new(garlic)),
            chunk_part_associations: Arc::new(Mutex::new(ChunkPartAssociations::new())),
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false))),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
        }
    }

    pub async fn set_node(&self, node: &mut Node) {
        self.node.lock().await.update(node);
    }

    pub async fn set_routing_table(&self, rt: RoutingTable) {
        self.routing_table.lock().await.update_from(rt).await;
    }

    pub async fn set_data_store(&self, data_store: &mut HashMap<U256, GarlemliaData>) {
        let mut ds = self.data_store.lock().await;
        ds.clear();

        for i in data_store.iter() {
            ds.insert(*i.0, i.1.clone());
        }
    }
    pub async fn set_garlic_cast(&self, gc: GarlicCast) {
        self.garlic.lock().await.update_from(gc);
    }
    

    async fn get_node(&self) -> Node {
        let node;
        {
            node = self.node.lock().await;
        }
        node.clone()
    }

    /// Function to handle messages that we receive
    async fn process_message(self_node: Node,
                             socket: Arc<UdpSocket>,
                             message_handler: Arc<Box<dyn GMessage>>,
                             routing_table: Arc<Mutex<RoutingTable>>,
                             data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                             garlic: Arc<Mutex<GarlicCast>>,
                             file_storage: Arc<Mutex<FileStorage>>,
                             chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
                             check_processing: Arc<Mutex<ProcessingCheck>>,
                             msg: GarlemliaMessage,
                             sender_node: Node,
                             src: SocketAddr) {
        match msg.clone() {
            // For ping - respond with pong
            GarlemliaMessage::Ping { .. } => {
                if let Err(e) = message_handler.send_no_recv(&socket, self_node.clone(), &src, &GarlemliaMessage::Pong { sender: self_node.clone() }).await {
                    eprintln!("Failed to send response to {}: {:?}", src, e);
                }
            }

            // For pong - add the message to the response queue
            GarlemliaMessage::Pong { sender, .. } => {
                let tx_info = message_handler.send_tx(sender_node.address, MessageChannel { node_id: sender_node.id, msg: GarlemliaMessage::Pong { sender } }).await;

                match tx_info {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                    }
                }
            }

            // For agreeing to be an alt node
            GarlemliaMessage::AgreeAlt { alt_sequence_number, sender } => {
                let mut rt = routing_table.lock().await;
                // Add to routing table if applicable
                rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;

                // Add to response queue
                let tx_info = message_handler.send_tx(sender_node.address, MessageChannel { node_id: sender_node.id, msg: GarlemliaMessage::AgreeAlt { alt_sequence_number, sender } }).await;

                match tx_info {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                    }
                }
            }

            // For a response - add to response queue after extrapolating data
            GarlemliaMessage::Response { nodes, value, sender, .. } => {
                let constructed = GarlemliaMessage::Response {
                    nodes,
                    value,
                    sender,
                };

                let tx_info = message_handler.send_tx(sender_node.address, MessageChannel { node_id: sender_node.id, msg: constructed }).await;

                match tx_info {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                    }
                }
            }

            // For all other messages
            _ => {
                {
                    // Attempt to add to routing table if applicable
                    routing_table.lock().await.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                }

                // Actually run the message
                let response = GarlemliaFunctions::run_message(self_node.clone(),
                                                               Arc::clone(&socket),
                                                               Arc::clone(&message_handler),
                                                               routing_table,
                                                               Arc::clone(&data_store),
                                                               garlic,
                                                               Arc::clone(&file_storage),
                                                               chunk_part_associations,
                                                               check_processing,
                                                               msg.clone(),
                                                               sender_node.clone()).await;

                // Check for response and send if it exists
                if response.is_some() {
                    if let Err(e) = message_handler.send_no_recv(&socket, self_node.clone(), &src, &response.unwrap()).await {
                        eprintln!("Failed to send response to {}: {:?}", src, e);
                    }
                }
            }
        }
    }

    // Start listening for messages
    pub async fn start(&mut self, orig_socket: Arc<UdpSocket>) {
        let self_node = Arc::clone(&self.node);
        let socket = Arc::clone(&orig_socket);
        let message_handler = Arc::clone(&self.message_handler);
        let routing_table = Arc::clone(&self.routing_table);
        let data_store = Arc::clone(&self.data_store);
        let garlic = Arc::clone(&self.garlic);
        let file_storage = Arc::clone(&self.file_storage);
        let chunk_part_associations = Arc::clone(&self.chunk_part_associations);
        let check_processing = Arc::clone(&self.is_processing);
        let stop_clone = Arc::clone(&self.stop_signal);
        println!("STARTING {}", socket.local_addr().unwrap());

        // Main event loop - listen for messages
        let handle = tokio::spawn(async move {
            let mut buf = [0; SOCKET_DATA_MAX];
            while !stop_clone.load(Ordering::Relaxed) {
                // Receive socket data
                if let Ok((size, src)) = socket.recv_from(&mut buf).await {
                    let self_ref;
                    {
                        self_ref = self_node.lock().await.clone();
                    }
                    // Get message content from json data
                    let msg: GarlemliaMessage = serde_json::from_slice(&buf[..size]).unwrap();

                    //println!("{} received {:?}", socket.local_addr().unwrap(), msg);

                    // Extract sender Node info
                    let sender_node = Node {
                        id: msg.sender_id(),
                        address: src,
                    };

                    if cfg!(debug_assertions) {
                        println!("Received msg {:?} from {:?} to {:?}", msg, sender_node, self_ref);
                    }

                    // Check if it is a stop message sent from self
                    match msg {
                        GarlemliaMessage::Stop {} => {
                            if sender_node.address == self_ref.address {
                                break;
                            }
                        }
                        _ => {}
                    }

                    let self_node_clone = self_node.lock().await.clone();
                    let socket_clone = Arc::clone(&socket);
                    let message_handler_clone = Arc::clone(&message_handler);
                    let routing_table_clone = Arc::clone(&routing_table);
                    let data_store_clone = Arc::clone(&data_store);
                    let garlic_clone = Arc::clone(&garlic);
                    let file_storage_clone = Arc::clone(&file_storage);
                    let chunk_part_associations_clone = Arc::clone(&chunk_part_associations);
                    let check_processing_clone = Arc::clone(&check_processing);

                    // Spawn a new thread and process the message within that thread
                    // TODO: Setup maximum processing threads
                    tokio::spawn(async move {
                        Garlemlia::process_message(self_node_clone,
                                                   socket_clone,
                                                   message_handler_clone,
                                                   routing_table_clone,
                                                   data_store_clone,
                                                   garlic_clone,
                                                   file_storage_clone,
                                                   chunk_part_associations_clone,
                                                   check_processing_clone,
                                                   msg,
                                                   sender_node,
                                                   src).await;
                    });
                }
            }
            println!("FINISHED {}", socket.local_addr().unwrap());
            drop(socket);
        });
        *Arc::get_mut(&mut self.join_handle).unwrap() = Some(handle);
    }

    /// Function for sending the stop command to the main event loop
    pub async fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);

        if let Some(handle) = Arc::get_mut(&mut self.join_handle.clone()).and_then(|h| h.take()) {
            handle.abort();
            let _ = handle.await;
        }

        self.socket.send_to(&*serde_json::to_vec(&GarlemliaMessage::Stop {}).unwrap(), &self.receive_addr).await.unwrap();
    }
}