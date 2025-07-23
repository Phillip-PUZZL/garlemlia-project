use std::collections::HashMap;
use primitive_types::U256;
use rsa::pkcs8::EncodePublicKey;
use tokio::task::JoinHandle;
use crate::garlic_cast::garlic_cast::clove_operations::CloveOperations;
use crate::garlic_cast::garlic_cast::proxy_management::ProxyManagement;
use crate::garlic_cast::garlic_cast::proxy_request::ProxyRequest;
use crate::garlic_cast::request_info::{InitiatorRequest, Proxy};
use crate::helper_functions::helper_functions::u256_random;
use crate::structs::constants::{DEFAULT_TTL, MIN_SEARCH_COUNT};
use crate::structs::garlic_message::{Clove, CloveMessage, CloveRequestID};
use super::GarlicCast;

pub(crate) trait SearchOperations {
    async fn search_kademlia(&mut self, proxy_id_pool: Vec<U256>, key: U256);
    fn create_search_message(
        &self,
        req: &str,
        request_id_full: &CloveRequestID,
        proxy_id: U256,
    ) -> CloveMessage;
    async fn spawn_search_tasks(
        &self,
        req: &str,
        request_id: U256,
        proxies: &mut Vec<Proxy>,
        total_sent: u8,
        remaining: u8,
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>>;
    async fn search_overlay(&mut self, req: String, proxy_id_pool: Vec<U256>, count: u8);
}

impl SearchOperations for GarlicCast {
    /// Asynchronously searches the Kademlia DHT network for a specified key using available proxy nodes.
    ///
    /// This function sends a `SearchGarlemlia` request to a set of chosen proxies from the provided pool of
    /// proxy identifiers (`proxy_id_pool`). The search is initiated by randomly selecting a proxy from the pool
    /// until a request is successfully sent. The search request is included in a `CloveMessage`, signed, and
    /// broadcasted as encrypted cloves to the selected proxy.
    ///
    /// # Arguments
    ///
    /// * `proxy_id_pool` - A vector of `U256` identifier values representing the pool of proxy nodes that can
    ///   be used for the search.
    /// * `key` - The `U256` key being searched for in the Kademlia Distributed Hash Table (DHT).
    ///
    /// # Behavior
    ///
    /// - A unique `request_id` is generated using the `u256_random` function.
    /// - The `proxy_id_pool` is filtered to retain proxies that are present in the object's proxy pool (`self.proxies`).
    /// - Proxies are randomly selected from the filtered pool to send the `SearchGarlemlia` request.
    /// - An encrypted message (cloves) is generated and signed using the selected proxy's public key.
    /// - The `send_to_proxy` function is called to send the `SearchGarlemlia` message.
    /// - The method tracks requests and their associated proxies in the `requests_as_initiator` map.
    /// - The search stops when a message is successfully sent or when no proxies are left in the pool.
    ///
    /// # Implementation Details
    ///
    /// - The request sent includes a `request_id`, which uniquely identifies this search request.
    /// - Each proxy node is represented with its `sequence_number` and `public_key`.
    /// - Proxies that were successfully communicated with are stored in the `proxies` array in the
    ///   `InitiatorRequest` structure, along with their respective associations.
    /// - If the search fails to find or communicate with any proxies, no request is initiated.
    ///
    /// # Example
    /// // Initialize a vector of proxy IDs and a key to search.
    /// let proxy_id_pool = vec![u256::from(1), u256::from(2), u256::from(3)];
    /// let key_to_search = u256::from(1234);
    ///
    /// // Call the search_kademlia function.
    /// self.search_kademlia(proxy_id_pool, key_to_search).await;
    ///
    /// # Panics
    /// This function does not explicitly panic under normal conditions. However, any unexpected
    /// errors in generating the `request_id`, sending the request, or cloning/dropping proxies
    /// may propagate if not handled appropriately.
    ///
    /// # Errors
    /// This function assumes the `send_to_proxy` method handles any errors related to network communication.
    /// Failure to send to any proxy will result in an incomplete search request.
    ///
    /// # Note
    /// - The `rand::random_range` function assumes a valid range is provided, and the random selection
    ///   is within bounds.
    /// - Any updates to `self.proxies` should ensure thread safety, as clones are explicitly created
    ///   during this operation.
    ///
    /// # Dependencies
    /// - The `GarlicCast::generate_cloves` function is used to generate signed and encrypted message cloves.
    /// - The helper structure `CloveMessage` represents the search message.
    /// - The `self.requests_as_initiator` map is updated to track active and completed requests.
    ///
    /// # Limitations
    /// - This function depends on randomized proxy selection, which may lead to variable behavior
    ///   in large-scale networks or with a large number of proxies.
    /// - Proxies must have preconfigured public keys for message encryption.
    async fn search_kademlia(&mut self, proxy_id_pool: Vec<U256>, key: U256) {
        let request_id = u256_random();
        let mut proxy_request = InitiatorRequest {
            request_id,
            validator_required: false,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        let proxies_init = self.proxies.clone();

        let mut proxies = vec![];
        for proxy in proxies_init {
            if proxy_id_pool.contains(&proxy.sequence_number) {
                proxies.push(proxy);
            }
        }

        let mut sent = false;

        while !sent && proxies.len() > 0 {
            let temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

            //let proxy_id = rand::random::<U256>();
            let msg = CloveMessage::SearchGarlemlia {
                request_id: CloveRequestID::new(request_id, 0),
                key
            };

            let cloves = GarlicCast::generate_cloves(msg.clone(), 2, temp_proxy.sequence_number, Some( temp_proxy.clone().public_key), Some(CloveRequestID::new(request_id, 0))).unwrap();

            sent = self.send_to_proxy(temp_proxy.clone(), cloves).await;

            if sent {
                proxy_request.proxies.push(temp_proxy);
            }
        }

        self.requests_as_initiator.insert(request_id, proxy_request);
    }

    fn create_search_message(
        &self,
        req: &str,
        request_id_full: &CloveRequestID,
        proxy_id: U256,
    ) -> CloveMessage {
        CloveMessage::SearchOverlay {
            request_id: request_id_full.clone(),
            proxy_id,
            search_term: req.to_string(),
            public_key: self.public_key.clone()
                .unwrap()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap(),
            ttl: DEFAULT_TTL,
        }
    }

    async fn spawn_search_tasks(
        &self,
        req: &str,
        request_id: U256,
        proxies: &mut Vec<Proxy>,
        total_sent: u8,
        remaining: u8,
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>> {
        let mut tasks = Vec::new();

        for i in 0..remaining {
            let proxy_id = u256_random();
            let request_id_full = CloveRequestID::new(request_id, (total_sent + i) as u64);
            let msg = self.create_search_message(req, &request_id_full, proxy_id);

            if let Some(temp_proxy) = proxies.get(rand::random_range(0..proxies.len())).cloned() {
                proxies.retain(|p| p.sequence_number != temp_proxy.sequence_number);

                let task = self.spawn_proxy_task(
                    msg,
                    proxy_id,
                    temp_proxy,
                    request_id_full,
                ).await;

                tasks.push(task);
            }
        }

        tasks
    }

    /// Conducts an asynchronous search operation using proxy nodes.
    ///
    /// # Arguments
    /// - `req` - A string representing the search request.
    /// - `proxy_id_pool` - A vector of `U256` values that represent the available proxy nodes.
    /// - `count` - A `u8` value representing the number of search requests to perform.
    ///   The actual count will be at least `MIN_SEARCH_COUNT` to ensure a minimum search size.
    ///
    /// # Behavior
    /// 1. The function calculates the actual number of requests (`count_actual`) to issue,
    ///    ensuring it is at least `MIN_SEARCH_COUNT` if the provided `count` is smaller.
    /// 2. A unique request ID is generated using `u256_random()`.
    /// 3. A proxy request object is created using `create_initiator_request`.
    /// 4. The provided pool of proxy IDs is filtered using `filter_proxies`.
    /// 5. It then enters a loop until the total number of successfully sent requests matches `count_actual`.
    ///    - The remaining number of requests is calculated by subtracting the number already sent.
    ///    - Asynchronous tasks are spawned for searching using `spawn_search_tasks`.
    ///    - Each task result is awaited and processed using `handle_proxy_task_result`.
    ///      - A successful result increments the count of total sent requests.
    ///      - An error during a task logs an error message but does not stop execution.
    /// 6. Once all requests are processed, the `proxy_request` is stored in the `requests_as_initiator` map
    ///    with the associated `request_id`.
    ///
    /// # Notes
    /// - The search process makes use of proxy nodes for distributed search functionality.
    /// - Error handling is performed on a per-task basis, ensuring that failed tasks do not terminate the entire process.
    ///
    /// # Panics
    /// This function assumes that the associated state and helper methods (`create_initiator_request`,
    /// `filter_proxies`, `spawn_search_tasks`, and `handle_proxy_task_result`) are implemented correctly.
    /// Improper implementation or misuse could cause runtime errors.
    ///
    /// # Example
    ///
    /// let mut service = SearchService::new();
    /// let proxy_pool = vec![U256::from(1), U256::from(2), U256::from(3)];
    /// service.search_overlay("sample_request".to_string(), proxy_pool, 5).await;
    ///
    async fn search_overlay(&mut self, req: String, proxy_id_pool: Vec<U256>, count: u8) {
        let count_actual = count.max(MIN_SEARCH_COUNT);
        let request_id = u256_random();
        let mut proxy_request = self.create_initiator_request(request_id);
        let mut proxies = self.filter_proxies(proxy_id_pool);
        let mut total_sent = 0;

        while total_sent < count_actual {
            let remaining = count_actual - total_sent;
            let tasks = self.spawn_search_tasks(
                &req, request_id, &mut proxies, total_sent, remaining,
            ).await;

            for task in tasks {
                match self.handle_proxy_task_result(task, &mut proxy_request).await {
                    Ok(()) => total_sent += 1,
                    Err(e) => log::error!("Task error: {}", e),
                }
            }
        }

        self.requests_as_initiator.insert(request_id, proxy_request);
    }
}