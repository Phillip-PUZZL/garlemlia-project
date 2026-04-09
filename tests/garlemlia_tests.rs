use garlemlia::core::constants::DEFAULT_K;
use garlemlia::core::u256_random;
use garlemlia::data::garlemlia_protocol::{
    GarlemliaFindRequest, GarlemliaResponse, GarlemliaStoreRequest,
};
use garlemlia::net::node::Node;
use garlemlia::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;
use garlemlia::routing::lookup::iterative::Iterative;
use garlemlia::routing::network::bootstrap::Bootstrap;
use garlemlia::routing::network::refresh::Refresh;
use garlemlia::routing::runtime::Garlemlia;
use garlemlia::routing::storage::store::Store;
use primitive_types::U256;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

async fn create_test_node(id: U256, port: u16) -> Garlemlia {
    let mut node = Garlemlia::new_with_id(
        Some(format!("./running_nodes_files/{port}").to_string()),
        Some(format!("./running_nodes_files/{port}/node_files").to_string()),
        Some(port),
        id,
    )
    .await;

    // Spawn a task to keep the node running and listening
    node.start(Arc::clone(&node.socket)).await;

    node
}

#[tokio::test]
async fn test_iterative_find_node() {
    let mut node1 = create_test_node(U256::from(1), 8005).await;
    let mut node2 = create_test_node(U256::from(2), 8006).await;
    let node3 = create_test_node(U256::from(3), 8007).await;

    let node3_addr = node3.node.lock().await.address;
    let node2_info = node2.node.lock().await.clone();

    let node1_socket = Arc::clone(&node1.socket);
    let node2_socket = Arc::clone(&node2.socket);

    Bootstrap::join_no_refresh(&mut node1, node1_socket, &node3_addr).await;
    Bootstrap::join_no_refresh(&mut node2, node2_socket, &node3_addr).await;

    let found_nodes = Iterative::find_node(
        &GarlemliaContext::from(&node1, Arc::clone(&node1.socket)).await,
        node2_info.id,
    )
    .await;

    node1.stop().await;
    node2.stop().await;
    node3.stop().await;

    println!(
        "found_nodes: {:?}\nrouting_table: {:?}",
        found_nodes, node1.routing_table
    );

    assert!(
        !found_nodes.is_empty() && found_nodes[0] == node2_info,
        "Should find node 2 and it should be first in the list"
    );
}

#[tokio::test]
async fn test_add_node_to_routing_table() {
    let mut kad = create_test_node(U256::from(1), 8080).await;
    let socket = Arc::clone(&kad.socket);
    let node = Node {
        id: U256::from(42),
        address: "127.0.0.1:8001".parse().unwrap(),
    };

    Refresh::add_node(&mut kad, &socket, node.clone()).await;

    let rt = kad.routing_table.lock().await;

    let index = rt.bucket_index(node.id);

    kad.stop().await;

    println!("rt: {:?}", rt);

    assert!(
        rt.buckets().await.get(&index).unwrap().contains(node.id),
        "Node should be in the routing table"
    );
}

#[tokio::test]
async fn test_add_node_ping() {
    let mut kad = create_test_node(U256::from(1), 8081).await;
    let socket = Arc::clone(&kad.socket);
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
            address: format!("127.0.0.1:{}", U256::from(8000) + base_id + i)
                .parse()
                .unwrap(),
        });
    }

    let test_info = test.node.lock().await.clone();

    // Insert all nodes into the routing table
    Refresh::add_node(&mut kad, &socket, test_info.clone()).await;
    for node in &nodes {
        Refresh::add_node(&mut kad, &socket, node.clone()).await;
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
    Refresh::add_node(&mut kad, &socket, overflow_node.clone()).await;

    let mut new;
    {
        let rt = kad.routing_table.lock().await;
        new = rt.buckets().await.get(&bucket_index).unwrap().clone();
    }

    // Ensure that the original bucket is the same
    println!("Routing Table Before Overflow: {:?}", orig);
    println!("Routing Table After Overflow: {:?}", new);
    assert_eq!(
        new.nodes[DEFAULT_K - 1],
        test_info.clone(),
        "Bucket should have same nodes"
    );

    test.stop().await;

    Refresh::add_node(&mut kad, &socket, overflow_node.clone()).await;

    {
        let rt = kad.routing_table.lock().await;
        new = rt.buckets().await.get(&bucket_index).unwrap().clone();
        println!(
            "Routing Table After Guaranteed LRU Removal: {:?}",
            rt.buckets().await.get(&bucket_index).unwrap()
        );
    }

    // Ensure that the original bucket has a new node
    assert_eq!(
        new.nodes[DEFAULT_K - 1],
        overflow_node,
        "Bucket should have new LRU"
    );
    {
        let rt = kad.routing_table.lock().await;
        assert!(
            rt.buckets()
                .await
                .get(&bucket_index)
                .unwrap()
                .contains(overflow_node.id),
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

    let node4_info = node4.node.lock().await.clone();
    let node3_info = node3.node.lock().await.clone();
    let node2_info = node2.node.lock().await.clone();
    let node1_info = node1.node.lock().await.clone();

    let node1_socket = Arc::clone(&node1.socket);
    let node2_socket = Arc::clone(&node2.socket);
    let node4_socket = Arc::clone(&node4.socket);

    // Let nodes join the network
    Bootstrap::join_no_refresh(&mut node4, node4_socket, &node1_info.address).await;
    Bootstrap::join_no_refresh(&mut node1, node1_socket, &node3_info.address).await;
    Bootstrap::join_no_refresh(&mut node2, node2_socket, &node1_info.address).await;

    sleep(Duration::from_secs(1)).await;

    // Store a value in node1
    Store::store_value(
        &GarlemliaContext::from(&node1, Arc::clone(&node1.socket)).await,
        GarlemliaStoreRequest::Value {
            id: node2_info.id,
            value: "Hello, world!".to_string(),
        },
        2,
    )
    .await;
    sleep(Duration::from_secs(1)).await;

    // Attempt to retrieve the stored value from node4
    let value = Iterative::find_value(
        &GarlemliaContext::from(&node4, Arc::clone(&node4.socket)).await,
        GarlemliaFindRequest::Key {
            id: node4_info.id,
            request_id: u256_random(),
        },
    )
    .await;

    node1.stop().await;
    node2.stop().await;
    node3.stop().await;
    node4.stop().await;

    match value {
        Some(value) => match value {
            GarlemliaResponse::Value { value } => {
                assert_eq!(
                    value,
                    "Hello, world!".to_string(),
                    "Value should 'Hello, World!'"
                );
            }
            _ => {
                assert!(false, "Value should be value type");
            }
        },
        _ => {
            assert!(false, "Value should be found");
        }
    }
}
