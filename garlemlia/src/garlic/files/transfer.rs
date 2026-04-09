use crate::core::constants::MAX_BATCH_SIZE;
use crate::core::u256_random;
use crate::data::garlemlia_protocol::GarlemliaResponse;
use crate::garlic::forwarding::proxy_runtime::{ProxyRuntime, TraitProxyRuntime};
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::state::request_state::Proxy;
use crate::garlic::{
    Clove, CloveMessage, CloveProtocol, CloveRequestID, FileCloveMessage, TraitCloveProtocol,
};
use primitive_types::U256;
use tokio::task::JoinHandle;

#[allow(dead_code)]
pub struct DownloadState {
    pub(crate) chunk_ids: Vec<U256>,
    total_chunks: usize,
    chunks_requested: u64,
    pub(crate) chunks_downloaded: usize,
}
impl DownloadState {
    pub(crate) fn new(chunk_ids: Vec<U256>) -> Self {
        let total_chunks = chunk_ids.len();
        Self {
            chunk_ids,
            total_chunks,
            chunks_requested: 0,
            chunks_downloaded: 0,
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.chunks_downloaded >= self.total_chunks
    }

    fn get_batch_size(&self) -> usize {
        (self.total_chunks - self.chunks_downloaded).min(MAX_BATCH_SIZE)
    }
}

pub(crate) trait TraitTransfer {
    async fn spawn_file_upload_tasks(
        garlic: &GarlicCast,
        messages: &[FileCloveMessage],
        proxies: &[Proxy],
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>>;
    async fn spawn_file_download_tasks(
        garlic: &GarlicCast,
        state: &mut DownloadState,
        proxies: &[Proxy],
        request_id: U256,
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>>;
    async fn create_download_task(
        garlic: &GarlicCast,
        request_id: U256,
        chunks_requested: u64,
        chunk_id: &U256,
        proxies: &[Proxy],
        proxy_index: usize,
    ) -> JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>;
    async fn send_chunk_part(
        garlic: &mut GarlicCast,
        request_id: U256,
        response: GarlemliaResponse,
        remove_self: bool,
    );
}

pub struct Transfer;
impl TraitTransfer for Transfer {
    async fn spawn_file_upload_tasks(
        garlic: &GarlicCast,
        messages: &[FileCloveMessage],
        proxies: &[Proxy],
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>> {
        let mut tasks = Vec::new();
        let mut available_proxies = proxies.to_vec();

        for msg in messages {
            if let Some(temp_proxy) = available_proxies
                .get(rand::random_range(0..available_proxies.len()))
                .cloned()
            {
                available_proxies.retain(|p| p.sequence_number != temp_proxy.sequence_number);

                let proxy_id = u256_random();
                let request_id = msg.message.request_id().unwrap();

                let task = ProxyRuntime::spawn_proxy_task(
                    garlic,
                    msg.message.clone(),
                    proxy_id,
                    temp_proxy,
                    request_id,
                )
                .await;

                tasks.push(task);
            }
        }

        tasks
    }

    async fn spawn_file_download_tasks(
        garlic: &GarlicCast,
        state: &mut DownloadState,
        proxies: &[Proxy],
        request_id: U256,
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>> {
        let mut batch_tasks = Vec::new();
        // Get maximum number of chunks to download in this batch
        let batch_size = state.get_batch_size();

        // Create tasks for each chunk in the batch
        for _ in 0..batch_size {
            // If there are still chunks to be downloaded
            if let Some(chunk_id) = state.chunk_ids.get(0) {
                // Create a download task for this chunk
                // Uses round-robin proxy selection based on chunks_requested counter
                let task = Self::create_download_task(
                    garlic,
                    request_id,
                    state.chunks_requested,
                    chunk_id,
                    proxies,
                    state.chunks_requested as usize % proxies.len(), // Round-robin proxy selection
                )
                .await;

                // Update download state
                state.chunks_requested += 1;
                state.chunk_ids.remove(0); // Remove chunk from pending list
                batch_tasks.push(task);
            }
        }

        batch_tasks
    }

    async fn create_download_task(
        garlic: &GarlicCast,
        request_id: U256,
        chunks_requested: u64,
        chunk_id: &U256,
        proxies: &[Proxy],
        proxy_index: usize,
    ) -> JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>> {
        // Create search message for the specific chunk
        let msg = CloveMessage::SearchGarlemlia {
            request_id: CloveRequestID::new(request_id, chunks_requested),
            key: chunk_id.clone(),
        };

        // Clone the selected proxy since it will be moved into the spawned task
        let proxy = proxies[proxy_index].clone();

        // Spawn the actual proxy routing task
        ProxyRuntime::spawn_proxy_task(
            garlic,
            msg,
            *chunk_id,
            proxy,
            CloveRequestID::new(request_id, chunks_requested),
        )
        .await
    }

    /// Sends a chunk part as a proxy to the specified request.
    ///
    /// This function handles sending a part of data associated with a given `request_id` by generating cloves
    /// (a part of the Garlic protocol) and sending them to the intended proxy. It also handles optional self-removal
    /// from the proxy request list.
    ///
    /// # Parameters
    ///
    /// - `request_id`:
    ///   The unique identifier (`U256`) for the request associated with the chunk being sent.
    ///
    /// - `response`:
    ///   The `GarlemliaResponse` to be wrapped into a `CloveMessage` and sent to the proxy. This contains the data
    ///   to be sent as part of the chunk.
    ///
    /// - `remove_self`:
    ///   A boolean flag indicating whether or not the current request should be removed from the list of requests
    ///   handled by this proxy. If `true`, the removal logic should clear the associated request data.
    ///
    /// # Behavior
    ///
    /// 1. Checks if the given `request_id` exists in the current proxy's request list (`requests_as_proxy`).
    /// 2. If found:
    ///    - Clones the associated request to fetch its initiator (`proxy`).
    ///    - Generates a unique `CloveRequestID` using the `request_id` and a random index.
    ///    - Constructs a `CloveMessage::Response` carrying the `request_id` and the provided `response`.
    ///    - Generates cloves using the `GarlicCast::generate_cloves` function.
    ///    - Sends the generated cloves to the intended proxy using the `send_to_proxy` method.
    /// 3. If `remove_self` is `true`, the function includes a commented-out logic (yet to be implemented)
    ///    to remove the current `request_id` entry from the `requests_as_proxy` list.
    ///
    /// # Notes
    ///
    /// - The function uses an asynchronous design pattern (`async fn`) so it must be awaited for proper
    ///   execution.
    /// - The `rand` crate is used to generate a random 64-bit index for the `CloveRequestID`.
    /// - Error handling is not explicitly defined in the provided code; potential unwrap calls on
    ///   optional values and result types may panic.
    ///
    /// # Example
    ///
    /// let mut handler = ProxyHandler::new();
    /// let request_id = U256::from(42u64);
    /// let response = GarlemliaResponse::new(...);
    ///
    /// handler.send_chunk_part(request_id, response, true).await;
    ///
    /// # Potential To-Do
    /// - Implement the `requests_as_proxy.remove` logic based on the `remove_self` flag to handle
    ///   request cleanup effectively.
    /// - Add robust error-handling around unwrap calls and result propagations.
    async fn send_chunk_part(
        garlic: &mut GarlicCast,
        request_id: U256,
        response: GarlemliaResponse,
        remove_self: bool,
    ) {
        let current_request = garlic.requests_as_proxy.get(&request_id.clone()).cloned();

        let index = rand::random::<u64>();

        if current_request.is_some() {
            let proxy = current_request.unwrap().initiator.clone();

            let msg = CloveMessage::Response {
                request_id: CloveRequestID::new(request_id, index),
                data: response,
            };

            let cloves = CloveProtocol::generate(
                msg.clone(),
                2,
                proxy.sequence_number,
                Some(proxy.clone().public_key),
                Some(CloveRequestID::new(request_id, index)),
            )
            .unwrap();

            garlic.send_to_proxy(proxy, cloves).await;
        }

        if remove_self {
            //self.requests_as_proxy.remove(&request_id);
        }
    }
}
