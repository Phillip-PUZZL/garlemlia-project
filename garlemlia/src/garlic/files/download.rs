use crate::core::u256_random;
use crate::files::file_info::FileInfo;
use crate::garlic::files::transfer::{DownloadState, TraitTransfer, Transfer};
use crate::garlic::forwarding::proxy_discovery::{ProxyDiscovery, TraitProxyDiscovery};
use crate::garlic::forwarding::proxy_runtime::{ProxyRuntime, TraitProxyRuntime};
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::state::request_state::{InitiatorRequest, Proxy};
use crate::garlic::{Clove, CloveMessage, CloveProtocol, CloveRequestID, TraitCloveProtocol};
use crate::time::time_based_hash::HashLocation;
use chrono::{Timelike, Utc};
use primitive_types::U256;
use std::collections::HashMap;
use tokio::task::JoinHandle;

#[allow(dead_code)]
pub(crate) trait TraitDownload {
    async fn get_file_info(
        garlic: &mut GarlicCast,
        search_id_pool: Vec<U256>,
        metadata_location: Vec<HashLocation>,
        key_location: Vec<HashLocation>,
    ) -> U256;
    async fn download_file(
        garlic: &mut GarlicCast,
        file_info: FileInfo,
        file_id_pool: Vec<U256>,
    ) -> U256;
    async fn handle_failed_download(
        garlic: &mut GarlicCast,
        state: &mut DownloadState,
        proxy_request: &mut InitiatorRequest,
        error_code: u8,
        proxy: Proxy,
        cloves: Vec<Clove>,
        chunk_id: U256,
    );
    async fn handle_download_responses(
        garlic: &mut GarlicCast,
        state: &mut DownloadState,
        proxy_request: &mut InitiatorRequest,
        tasks: Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>>,
    );
}

pub struct Download;
impl TraitDownload for Download {
    /// Asynchronously generates a request to retrieve file information and distributes it across two proxies based on the provided search IDs, metadata locations, and key locations.
    ///
    /// # Arguments
    ///
    /// * `search_id_pool` - A vector of `U256` identifiers that represent the search IDs used to filter the proxies for this operation.
    /// * `metadata_location` - A vector of `HashLocation` elements that correspond to metadata storage locations.
    /// * `key_location` - A vector of `HashLocation` elements that correspond to key storage locations.
    ///
    /// # Returns
    ///
    /// Returns a `U256` identifier (`request_id`) that uniquely identifies the request generated for this operation. This `request_id` is associated with the initiated request and will be stored in the `requests_as_initiator` map.
    ///
    /// # Details
    ///
    /// 1. Generates a unique `request_id` using a random `U256` value.
    /// 2. Sets up an `InitiatorRequest` object with the generated `request_id` and initializes relevant request fields.
    /// 3. Filters available proxies from `garlic.proxies` based on the `search_id_pool` parameter.
    /// 4. Selects the metadata and key storage locations for the current hour from the provided `metadata_location` and `key_location` vectors.
    /// 5. Distributes a search request (in the form of `CloveMessage::SearchGarlemlia`) to two selected proxies:
    ///     - The first message uses the metadata location.
    ///     - The second message uses the key location.
    /// 6. Each request is encapsulated in `GarlicCast` cloves, signed, and sent to the corresponding proxy using the `send_to_proxy` method.
    /// 7. Updates the `proxy_request` object with the proxies used in the operation and associates it with the generated `request_id` in the `requests_as_initiator` map.
    ///
    /// # Error Handling
    ///
    /// * Assumes that the metadata and key storage locations within the current hour always exist in `metadata_location` and `key_location`.
    /// * Panics if no matching locations are found for the current hour in either `metadata_location` or `key_location`.
    ///
    /// # Example
    ///
    /// use some_library::{U256, HashLocation, ExampleStruct};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut example_instance = ExampleStruct::new();
    ///     let search_id_pool = vec![U256::from(1), U256::from(2)];
    ///     let metadata_location = vec![...]; // A vector of HashLocation objects
    ///     let key_location = vec![...]; // A vector of HashLocation objects
    ///
    ///     let request_id = example_instance.get_file_info(search_id_pool, metadata_location, key_location).await;
    ///
    ///     println!("Generated Request ID: {:?}", request_id);
    /// }
    ///
    /// # Notes
    ///
    /// * This function leverages randomness (`rand::random_range`) to select proxies and may not behave deterministically on every invocation.
    /// * The function maintains state in `garlic.requests_as_initiator`, allowing tracking of initiated requests.
    /// * Ensure that the `proxies` field in `garlic` is correctly populated before invoking this function.
    async fn get_file_info(
        garlic: &mut GarlicCast,
        search_id_pool: Vec<U256>,
        metadata_location: Vec<HashLocation>,
        key_location: Vec<HashLocation>,
    ) -> U256 {
        // Generate a random request ID for tracking this operation
        let request_id = u256_random();

        // Initialize request tracking structure
        let mut proxy_request = InitiatorRequest {
            request_id,
            validator_required: false,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        // Filter proxies that match any ID in the search pool
        let proxies_init = garlic.proxies.clone();

        let mut proxies = vec![];
        for proxy in proxies_init.clone() {
            if search_id_pool.contains(&proxy.sequence_number) {
                proxies.push(proxy);
            }
        }

        // Get metadata and key locations for current hour
        let metadata_loc = metadata_location
            .iter()
            .find(|l| l.time.hour() == Utc::now().hour())
            .unwrap()
            .clone()
            .id;
        let key_loc = key_location
            .iter()
            .find(|l| l.time.hour() == Utc::now().hour())
            .unwrap()
            .clone()
            .id;

        // Send requests to two different proxies
        let mut total_sent = 0;
        while total_sent < 2 {
            // Randomly select a proxy from filtered list
            let temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

            // First proxy gets metadata location, second gets key location
            let key = if total_sent == 0 {
                metadata_loc
            } else {
                key_loc
            };

            // Create search message
            let msg = CloveMessage::SearchGarlemlia {
                request_id: CloveRequestID::new(request_id, total_sent),
                key,
            };

            // Generate encrypted cloves for the message
            let cloves = CloveProtocol::generate(
                msg.clone(),
                2,
                temp_proxy.sequence_number,
                Some(temp_proxy.clone().public_key),
                Some(msg.request_id().unwrap()),
            )
            .unwrap();

            // Attempt to send cloves to proxy
            let sent = garlic.send_to_proxy(temp_proxy.clone(), cloves).await;

            // If send successful, track proxy used
            if sent {
                proxy_request.proxies.push(temp_proxy);
                total_sent += 1;
            }
        }

        // Store request tracking info and return request ID
        garlic
            .requests_as_initiator
            .insert(request_id, proxy_request);

        request_id
    }

    /// Downloads a file by initiating multiple download tasks and aggregating the results.
    ///
    /// This asynchronous function manages the download process by:
    /// 1. Generating a unique request ID.
    /// 2. Filtering proxies that can be used for downloading file chunks.
    /// 3. Creating and maintaining a `DownloadState` instance to track the progress of the download.
    /// 4. Spawning download tasks for requested file chunks using the filtered proxies.
    /// 5. Handling download responses and updating the download state until all file chunks are complete.
    ///
    /// Once the file is fully downloaded, the request is stored as an initiator request.
    ///
    /// # Arguments
    ///
    /// * `file_info` - A `FileInfo` struct containing metadata about the file to be downloaded, including the chunks required.
    /// * `file_id_pool` - A `Vec<U256>` representing the pool of file-specific proxy identifiers that can be used for downloading.
    ///
    /// # Returns
    ///
    /// Returns a `U256` representing the unique request ID for this file download.
    ///
    /// # Example
    ///
    ///
    /// let file_info = FileInfo { needed_chunks: vec![...] };
    /// let file_id_pool = vec![...];
    ///
    /// let request_id = downloader.download_file(file_info, file_id_pool).await;
    /// println!("Download initiated with request ID: {:?}", request_id);
    ///
    ///
    /// # Notes
    ///
    /// * The function proceeds in an iterative fashion, attempting to download file chunks in parallel
    ///   using available proxies and awaiting their results.
    /// * The download is considered complete when all required chunks have been successfully retrieved.
    /// * The `requests_as_initiator` map is updated to associate the request ID with its corresponding proxy request.
    ///
    /// # Errors
    ///
    /// This function does not explicitly return errors but will propagate any runtime issues
    /// encountered during the download process (e.g., network failures, proxy timeouts).
    ///
    /// # Panics
    ///
    /// This function may panic if any unexpected issues occur during the spawning of tasks
    /// or handling of responses. Proper error handling should be implemented in the related methods.
    async fn download_file(
        garlic: &mut GarlicCast,
        file_info: FileInfo,
        file_id_pool: Vec<U256>,
    ) -> U256 {
        let request_id = u256_random();
        let mut proxy_request = garlic.create_initiator_request(request_id);
        let file_chunk_proxies = ProxyDiscovery::filter_proxies(garlic, file_id_pool);

        let mut download_state =
            DownloadState::new(file_info.needed_chunks.iter().map(|c| c.chunk_id).collect());

        while !download_state.is_complete() {
            let tasks = Transfer::spawn_file_download_tasks(
                garlic,
                &mut download_state,
                &file_chunk_proxies,
                request_id,
            )
            .await;

            Self::handle_download_responses(garlic, &mut download_state, &mut proxy_request, tasks)
                .await;
        }

        garlic
            .requests_as_initiator
            .insert(request_id, proxy_request);
        request_id
    }

    async fn handle_failed_download(
        garlic: &mut GarlicCast,
        state: &mut DownloadState,
        proxy_request: &mut InitiatorRequest,
        error_code: u8,
        proxy: Proxy,
        cloves: Vec<Clove>,
        chunk_id: U256,
    ) {
        if let Some(updated_proxy) =
            ProxyRuntime::handle_proxy_forwarding(garlic, error_code, proxy, cloves).await
        {
            state.chunks_downloaded += 1;
            proxy_request.proxies.push(updated_proxy);
        } else {
            state.chunk_ids.push(chunk_id);
        }
    }

    async fn handle_download_responses(
        garlic: &mut GarlicCast,
        state: &mut DownloadState, // Tracks progress of chunk downloads
        proxy_request: &mut InitiatorRequest, // Stores proxy information and responses
        // Vector of tasks that return either success (U256, Proxy) or failure (error_code, Proxy, Cloves, chunk_id)
        tasks: Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>>,
    ) {
        for task in tasks {
            match task.await {
                Ok(result) => {
                    match result {
                        // Successful download case
                        Ok((_, proxy)) => {
                            state.chunks_downloaded += 1; // Increment successful download counter
                            proxy_request.proxies.push(proxy); // Store the proxy for future use
                        }
                        // Failed download case
                        Err((error_code, proxy, cloves, chunk_id)) => {
                            // Attempt to recover from failure via proxy forwarding
                            Self::handle_failed_download(
                                garlic,
                                state,
                                proxy_request,
                                error_code, // Indicates type of failure
                                proxy,      // The proxy that failed
                                cloves,     // Message fragments that failed to process
                                chunk_id,   // ID of chunk that failed to download
                            )
                            .await;
                        }
                    }
                }
                // Task itgarlic failed (e.g. panic, cancellation)
                Err(e) => log::error!(
                    "{}: Unexpected error in download task: {}",
                    garlic.local_node.address,
                    e
                ),
            }
        }
    }
}
