use std::collections::HashMap;
use std::net::{SocketAddr};
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use primitive_types::U256;
use rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex};
use tokio::task;

use garlic::GarlicCast;

use crate::garlic_cast::garlic;
use crate::file_utils::garlemlia_files::FileStorage;
use crate::structs::constants::{SOCKET_DATA_MAX};
use crate::structs::file_chunks::{ChunkPartAssociations, ProcessingCheck};
use crate::structs::garlemlia_message::{GMessage, GarlemliaMessage, GarlemliaMessageHandler, MessageChannel};
use crate::structs::node::Node;
use crate::structs::routing_table::RoutingTable;
use crate::structs::garlemlia_data::{load_tracker_file, new_tracker, GarlemliaData, GarlemliaFilesTracker};

mod functions;
mod find;
mod network;
mod store;

pub use functions::GarlemliaFunctions;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use crate::helper_functions::helper_functions::u256_random;
use crate::structs::settings::{load_settings_file, new_settings, Settings};

#[derive(Clone)]
struct StartContext {
    node: Arc<Mutex<Node>>,
    socket: Arc<UdpSocket>,
    message_handler: Arc<Box<dyn GMessage>>,
    routing_table: Arc<Mutex<RoutingTable>>,
    data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
    garlic: Arc<Mutex<GarlicCast>>,
    file_storage: Arc<Mutex<FileStorage>>,
    chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
    check_processing: Arc<Mutex<ProcessingCheck>>,
    stop_signal: Arc<AtomicBool>,
    settings: Arc<Mutex<Settings>>,
}

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
    settings: Arc<Mutex<Settings>>,
    tracker: GarlemliaFilesTracker
}

// TODO: Implement new event thread for watching last_seen information and pinging nodes
// TODO: which have not been seen in an hour + evicting those which fail
impl Garlemlia {
    pub async fn new(settings_dir: Option<String>, files_dir: Option<String>, recv_port: Option<u16>) -> Self {
        let mut settings = new_settings(settings_dir, files_dir).unwrap();
        if recv_port.is_some() {
            settings.get_network_settings_mut().set_incoming_port(recv_port);
        }

        if let Err(e) = settings.save_settings().await {
            eprintln!("Failed to save settings: {: }", e);
        }

        let tracker = new_tracker(settings.get_application_settings().get_root_storage_path()).await.unwrap();
        tracker.save_tracker().await.unwrap();

        let port = settings.get_network_settings().get_incoming_port();

        let node = Node { id: u256_random(), address: format!("127.0.0.1:{port}").parse().unwrap() };
        let socket = Arc::new(UdpSocket::bind(format!("127.0.0.1:{port}")).await.unwrap());

        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        settings.get_node_settings_mut().set_private_key(Some(private_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()));
        settings.get_node_settings_mut().set_public_key(Some(public_key.to_public_key_pem(LineEnding::LF).unwrap().to_string()));
        if let Err(e) = settings.save_settings().await {
            eprintln!("Failed to save settings: {: }", e);
        }

        let msg_handler = GarlemliaMessageHandler::create(10);

        let garlic = GarlicCast::new(Arc::clone(&socket), node.clone(),
                                     Arc::new(msg_handler.clone()), vec![],
                                     Some(public_key), Some(private_key));

        let rt = RoutingTable::new(node.clone());

        Self {
            node: Arc::new(Mutex::new(node)),
            socket,
            receive_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            message_handler: Arc::new(msg_handler),
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            file_storage: Arc::new(Mutex::new(tracker.get_downloads().clone())),
            garlic: Arc::new(Mutex::new(garlic)),
            chunk_part_associations: Arc::new(Mutex::new(ChunkPartAssociations::new())),
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false))),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
            settings: Arc::new(Mutex::new(settings)),
            tracker
        }
    }

    pub async fn new_with_id(settings_dir: Option<String>, files_dir: Option<String>, recv_port: Option<u16>, id: U256) -> Self {
        let mut settings = new_settings(settings_dir, files_dir).unwrap();
        if recv_port.is_some() {
            settings.get_network_settings_mut().set_incoming_port(recv_port);
        }

        if let Err(e) = settings.save_settings().await {
            eprintln!("Failed to save settings: {: }", e);
        }

        let tracker = new_tracker(settings.get_application_settings().get_root_storage_path()).await.unwrap();
        tracker.save_tracker().await.unwrap();

        let port = settings.get_network_settings().get_incoming_port();

        let node = Node { id, address: format!("127.0.0.1:{port}").parse().unwrap() };
        let socket = Arc::new(UdpSocket::bind(format!("127.0.0.1:{port}")).await.unwrap());

        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        settings.get_node_settings_mut().set_private_key(Some(private_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()));
        settings.get_node_settings_mut().set_public_key(Some(public_key.to_public_key_pem(LineEnding::LF).unwrap().to_string()));
        if let Err(e) = settings.save_settings().await {
            eprintln!("Failed to save settings: {: }", e);
        }

        let msg_handler = GarlemliaMessageHandler::create(10);

        let garlic = GarlicCast::new(Arc::clone(&socket), node.clone(),
                                     Arc::new(msg_handler.clone()), vec![],
                                     Some(public_key), Some(private_key));

        let rt = RoutingTable::new(node.clone());

        Self {
            node: Arc::new(Mutex::new(node)),
            socket,
            receive_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            message_handler: Arc::new(msg_handler),
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            file_storage: Arc::new(Mutex::new(tracker.get_downloads().clone())),
            garlic: Arc::new(Mutex::new(garlic)),
            chunk_part_associations: Arc::new(Mutex::new(ChunkPartAssociations::new())),
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false))),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
            settings: Arc::new(Mutex::new(settings)),
            tracker
        }
    }

    pub async fn load(settings_path: String) -> Self {
        let settings = load_settings_file(settings_path).await.unwrap();

        let tracker = load_tracker_file(settings.get_application_settings().get_tracker_file_path()).await.unwrap();

        let port = settings.get_network_settings().get_incoming_port();

        let node = Node { id: u256_random(), address: format!("127.0.0.1:{port}").parse().unwrap() };
        let socket = Arc::new(UdpSocket::bind(format!("127.0.0.1:{port}")).await.unwrap());

        let private_key = RsaPrivateKey::from_pkcs1_pem(settings.get_node_settings().get_private_key().unwrap().as_str()).unwrap();
        let public_key = RsaPublicKey::from_pkcs1_pem(settings.get_node_settings().get_public_key().unwrap().as_str()).unwrap();

        let msg_handler = GarlemliaMessageHandler::create(10);

        let garlic = GarlicCast::new(Arc::clone(&socket), node.clone(),
                                     Arc::new(msg_handler.clone()), vec![],
                                     Some(public_key), Some(private_key));

        let mut rt = RoutingTable::new(node.clone());
        for node in settings.get_network_settings().get_known_nodes() {
            rt.add_node(&Arc::new(msg_handler.clone()), node, &socket).await;
        }

        Self {
            node: Arc::new(Mutex::new(node)),
            socket,
            receive_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            message_handler: Arc::new(msg_handler),
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            file_storage: Arc::new(Mutex::new(tracker.get_downloads().clone())),
            garlic: Arc::new(Mutex::new(garlic)),
            chunk_part_associations: Arc::new(Mutex::new(ChunkPartAssociations::new())),
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false))),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
            settings: Arc::new(Mutex::new(settings)),
            tracker
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
                let mut rt = routing_table.lock().await;
                // Add to the routing table if applicable
                rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;

                if let Err(e) = message_handler.send_no_recv(&socket, self_node.clone(),
                                                             &src,
                                                             &GarlemliaMessage::Pong {
                                                                 sender: self_node.clone()
                                                             }).await {
                    eprintln!("Failed to send response to {}: {:?}", src, e);
                }
            }

            // For pong - add the message to the response queue
            GarlemliaMessage::Pong { sender, .. } => {
                let tx_info = message_handler.send_tx(sender_node.address,
                                                      MessageChannel {
                                                          node_id: sender_node.id,
                                                          msg: GarlemliaMessage::Pong { sender }
                                                      }).await;

                match tx_info {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Failed to send TX for the message from {}: {:?}", src, e);
                    }
                }
            }

            // For agreeing to be an alt node
            GarlemliaMessage::AgreeAlt { alt_sequence_number, sender } => {
                let mut rt = routing_table.lock().await;
                // Add to the routing table if applicable
                rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;

                // Add to the response queue
                let tx_info = message_handler.send_tx(sender_node.address,
                                                      MessageChannel {
                                                          node_id: sender_node.id,
                                                          msg: GarlemliaMessage::AgreeAlt {
                                                              alt_sequence_number, sender
                                                          }
                                                      }).await;

                match tx_info {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                    }
                }
            }

            // For a response - add to the response queue after extrapolating data
            GarlemliaMessage::Response { nodes, value, sender, .. } => {
                let constructed = GarlemliaMessage::Response {
                    nodes,
                    value,
                    sender,
                };

                let tx_info = message_handler.send_tx(sender_node.address,
                                                      MessageChannel {
                                                          node_id: sender_node.id,
                                                          msg: constructed
                                                      }).await;

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
                    routing_table.lock().await.add_node_from_responder(Arc::clone(&message_handler),
                                                                       sender_node.clone(),
                                                                       Arc::clone(&socket)).await;
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

                // Check for the response and send if it exists
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
        let ctx = StartContext {
            node: Arc::clone(&self.node),
            socket: Arc::clone(&orig_socket),
            message_handler: Arc::clone(&self.message_handler),
            routing_table: Arc::clone(&self.routing_table),
            data_store: Arc::clone(&self.data_store),
            garlic: Arc::clone(&self.garlic),
            file_storage: Arc::clone(&self.file_storage),
            chunk_part_associations: Arc::clone(&self.chunk_part_associations),
            check_processing: Arc::clone(&self.is_processing),
            stop_signal: Arc::clone(&self.stop_signal),
            settings: Arc::clone(&self.settings),
        };

        println!("STARTING {}", ctx.socket.local_addr().unwrap());

        let handle = tokio::spawn(async move {
            Garlemlia::run_event_loop(ctx).await;
        });

        *Arc::get_mut(&mut self.join_handle).unwrap() = Some(handle);
    }

    async fn run_event_loop(ctx: StartContext) {
        let mut buf = [0; SOCKET_DATA_MAX];

        while !ctx.stop_signal.load(Ordering::Relaxed) {
            let Ok((size, src)) = ctx.socket.recv_from(&mut buf).await else {
                continue;
            };

            if let Err(e) = Garlemlia::handle_incoming_packet(&ctx, &buf[..size], src).await {
                eprintln!("Failed to handle packet from {}: {}", src, e);
            }
        }

        println!("FINISHED {}", ctx.socket.local_addr().unwrap());
    }

    async fn handle_incoming_packet(
        ctx: &StartContext,
        data: &[u8],
        src: SocketAddr,
    ) -> Result<(), String> {
        let self_ref = ctx.node.lock().await.clone();

        let msg: GarlemliaMessage =
            serde_json::from_slice(data).map_err(|e| format!("Invalid message JSON: {e}"))?;

        let sender_node = Node {
            id: msg.sender_id(),
            address: src,
        };

        if cfg!(debug_assertions) {
            println!("Received msg {:?} from {:?} to {:?}", msg, sender_node, self_ref);
        }

        if Garlemlia::is_self_stop_message(&msg, &sender_node, &self_ref) {
            ctx.stop_signal.store(true, Ordering::Relaxed);
            return Ok(());
        }

        Garlemlia::spawn_message_processor(ctx, msg, sender_node, src);
        Garlemlia::sync_known_nodes(&ctx.routing_table, &ctx.settings).await;

        Ok(())
    }

    fn is_self_stop_message(msg: &GarlemliaMessage, sender_node: &Node, self_ref: &Node) -> bool {
        matches!(msg, GarlemliaMessage::Stop {} if sender_node.address == self_ref.address)
    }

    fn spawn_message_processor(
        ctx: &StartContext,
        msg: GarlemliaMessage,
        sender_node: Node,
        src: SocketAddr,
    ) {
        let node = Arc::clone(&ctx.node);
        let socket = Arc::clone(&ctx.socket);
        let message_handler = Arc::clone(&ctx.message_handler);
        let routing_table = Arc::clone(&ctx.routing_table);
        let data_store = Arc::clone(&ctx.data_store);
        let garlic = Arc::clone(&ctx.garlic);
        let file_storage = Arc::clone(&ctx.file_storage);
        let chunk_part_associations = Arc::clone(&ctx.chunk_part_associations);
        let check_processing = Arc::clone(&ctx.check_processing);

        tokio::spawn(async move {
            let self_node = node.lock().await.clone();

            Garlemlia::process_message(
                self_node,
                socket,
                message_handler,
                routing_table,
                data_store,
                garlic,
                file_storage,
                chunk_part_associations,
                check_processing,
                msg,
                sender_node,
                src,
            ).await;
        });
    }

    async fn sync_known_nodes(
        routing_table: &Arc<Mutex<RoutingTable>>,
        settings: &Arc<Mutex<Settings>>,
    ) {
        let rt = routing_table.lock().await;
        let mut settings_locked = settings.lock().await;

        let mut old_nodes = settings_locked.get_network_settings().get_known_nodes();
        old_nodes.sort_by_key(|n| n.id);

        let mut new_nodes = rt.flat_nodes().await;
        new_nodes.sort_by_key(|n| n.id);

        if old_nodes != new_nodes {
            settings_locked
                .get_network_settings_mut()
                .set_known_nodes(new_nodes);

            if let Err(e) = settings_locked.save_settings().await {
                eprintln!("Failed to save settings: {}", e);
            }
        }
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