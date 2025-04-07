use garlemlia::garlemlia::garlemlia::Garlemlia;
use garlemlia::garlemlia_structs::garlemlia_structs::{u256_random, GMessage, GarlemliaFindRequest, GarlemliaMessageHandler, GarlemliaResponse, GarlemliaStoreRequest, Node, RoutingTable, DEFAULT_K};
use primitive_types::U256;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

async fn create_test_node(id: U256, port: u16) -> Garlemlia {
    let mut node = Garlemlia::new(id, "127.0.0.1", port, RoutingTable::new(Node {id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port)}), GarlemliaMessageHandler::create(1), Box::new(Path::new("./running_nodes_files"))).await;

    // Spawn a task to keep the node running and listening
    node.start(Arc::clone(&node.socket)).await;

    node
}

#[tokio::test]
async fn test_iterative_find_node() {
    // Create multiple nodes and bind them to real sockets
    let mut node1 = create_test_node(U256::from(1), 8005).await;
    let mut node2 = create_test_node(U256::from(2), 8006).await;
    let node3 = create_test_node(U256::from(3), 8007).await;

    let node3_addr = node3.node.lock().await.address;
    let node2_info = node2.node.lock().await.clone();

    node1.join_network_no_refresh(Arc::clone(&node1.socket), &node3_addr).await;
    node2.join_network_no_refresh(Arc::clone(&node2.socket), &node3_addr).await;

    // Perform lookup
    let found_nodes = node1.iterative_find_node(Arc::clone(&node1.socket), U256::from(2)).await;

    node1.stop().await;
    node2.stop().await;
    node3.stop().await;

    println!("found_nodes: {:?}\nrouting_table: {:?}", found_nodes, node1.routing_table);

    assert!(!found_nodes.is_empty() && found_nodes[0] == node2_info, "Should find node 2 and it should be first in the list");
}

#[tokio::test]
async fn test_add_node_to_routing_table() {
    let kad = create_test_node(U256::from(1), 8080).await;
    let node = Node {
        id: U256::from(42),
        address: "127.0.0.1:8001".parse().unwrap(),
    };

    kad.add_node(&kad.socket, node.clone()).await;

    let rt = kad.routing_table.lock().await;

    let index = rt.bucket_index(node.id);

    kad.stop().await;

    println!("rt: {:?}", rt);

    assert!(rt.buckets().await.get(&index).unwrap().contains(node.id), "Node should be in the routing table");
}

#[tokio::test]
async fn test_add_node_ping() {
    let kad = create_test_node(U256::from(1), 8081).await;
    let test = create_test_node(U256::from(128), 8082).await;

    let base_id: U256 = U256::from(128);
    let bucket_index;

    {
        let rt = kad.routing_table.lock().await;
        bucket_index = rt.bucket_index(base_id);
    }

    // Generate nodes that belong in the same bucket
    let mut nodes = Vec::new();
    for i in 1..DEFAULT_K {
        let id = base_id + i;
        nodes.push(Node {
            id,
            address: format!("127.0.0.1:{}", U256::from(8000) + base_id + i).parse().unwrap(),
        });
    }

    let test_info = test.node.lock().await.clone();

    // Insert all nodes into the routing table
    kad.add_node(&kad.socket, test_info.clone()).await;
    for node in &nodes {
        kad.add_node(&kad.socket, node.clone()).await;
    }

    let orig;
    {
        let rt = kad.routing_table.lock().await;
        orig = rt.buckets().await.get(&bucket_index).unwrap().clone();
    }

    // One extra node to force a ping
    let overflow_node = Node {
        id: base_id + (DEFAULT_K),
        address: "127.0.0.1:9000".parse().unwrap(),
    };
    kad.add_node(&kad.socket, overflow_node.clone()).await;

    let mut new;
    {
        let rt = kad.routing_table.lock().await;
        new = rt.buckets().await.get(&bucket_index).unwrap().clone();
    }

    // Ensure that the original bucket is the same
    println!("Routing Table Before Overflow: {:?}", orig);
    println!("Routing Table After Overflow: {:?}", new);
    assert_eq!(new.nodes[DEFAULT_K - 1], test_info.clone(), "Bucket should have same nodes");

    test.stop().await;

    kad.add_node(&kad.socket, overflow_node.clone()).await;

    {
        let rt = kad.routing_table.lock().await;
        new = rt.buckets().await.get(&bucket_index).unwrap().clone();
        println!("Routing Table After Guaranteed LRU Removal: {:?}", rt.buckets().await.get(&bucket_index).unwrap());
    }

    // Ensure that the original bucket has new node
    assert_eq!(new.nodes[DEFAULT_K - 1], overflow_node, "Bucket should have new LRU");
    {
        let rt = kad.routing_table.lock().await;
        assert!(
            rt.buckets().await.get(&bucket_index).unwrap().contains(overflow_node.id),
            "Overflow node should be in the bucket"
        );
    }

    kad.stop().await;
}

#[tokio::test]
async fn test_iterative_find_value() {
    // Create multiple nodes and bind them to real sockets
    let mut node1 = create_test_node(U256::from(1), 8001).await;
    let mut node2 = create_test_node(U256::from(2), 8002).await;
    let node3 = create_test_node(U256::from(3), 8003).await;
    let mut node4 = create_test_node(U256::from(4), 8004).await;

    let node3_info = node3.node.lock().await.clone();
    let node1_info = node1.node.lock().await.clone();

    // Let nodes join the network
    node4.join_network_no_refresh(Arc::clone(&node4.socket), &node1_info.address).await;
    node1.join_network_no_refresh(Arc::clone(&node1.socket), &node3_info.address).await;
    node2.join_network_no_refresh(Arc::clone(&node2.socket), &node1_info.address).await;

    sleep(Duration::from_secs(1)).await;

    // Store a value in node1
    node1.store_value(Arc::clone(&node1.socket), GarlemliaStoreRequest::Value { id: U256::from(2), value: "Hello, world!".to_string() }, 2).await;
    sleep(Duration::from_secs(1)).await;

    // Attempt to retrieve the stored value from node4
    let value = node4.iterative_find_value(Arc::clone(&node4.socket), GarlemliaFindRequest::Key { id: U256::from(2), request_id: u256_random() }).await;

    node1.stop().await;
    node2.stop().await;
    node3.stop().await;
    node4.stop().await;

    match value {
        Some(value) => {
            match value {
                GarlemliaResponse::Value { value } => {
                    assert_eq!(value, "Hello, world!".to_string(), "Value should 'Hello, World!'");
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


}