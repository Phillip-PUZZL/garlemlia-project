use crate::core::constants::SOCKET_DATA_MAX;
use crate::data::garlemlia_protocol::GarlemliaMessage;
use crate::net::node::Node;
use crate::routing::runtime::{Garlemlia, StartContext};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub(crate) async fn run_event_loop(ctx: StartContext) {
    let mut buf = [0; SOCKET_DATA_MAX];

    while !ctx.stop_signal.load(Ordering::Relaxed) {
        let Ok((size, src)) = ctx.socket.recv_from(&mut buf).await else {
            continue;
        };

        if let Err(e) = handle_incoming_packet(&ctx, &buf[..size], src).await {
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
        println!(
            "Received msg {:?} from {:?} to {:?}",
            msg, sender_node, self_ref
        );
    }

    if is_self_stop_message(&msg, &sender_node, &self_ref) {
        ctx.stop_signal.store(true, Ordering::Relaxed);
        return Ok(());
    }

    spawn_message_processor(ctx, msg, sender_node, src);
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
        )
        .await;
    });
}
