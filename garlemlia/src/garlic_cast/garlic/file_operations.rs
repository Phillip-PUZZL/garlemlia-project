use std::collections::HashMap;
use std::time::Duration;
use chrono::{Timelike, Utc};
use primitive_types::U256;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use crate::file_utils::garlemlia_files::{FileInfo, FileStorage, FileUpload};
use crate::garlic_cast::garlic::clove_operations::CloveOperations;
use crate::garlic_cast::garlic::proxy_management::ProxyManagement;
use crate::garlic_cast::garlic::proxy_request::ProxyRequest;
use crate::garlic_cast::request_info::{InitiatorRequest, Proxy};
use crate::helper_functions::helper_functions::u256_random;
use crate::structs::constants::MAX_BATCH_SIZE;
use crate::structs::garlemlia_message::GarlemliaResponse;
use crate::structs::garlic_message::{Clove, CloveMessage, CloveRequestID, FileCloveMessage};
use crate::time_hash::time_based_hash::HashLocation;
use super::GarlicCast;

pub struct DownloadState {
    chunk_ids: Vec<U256>,
    total_chunks: usize,
    chunks_requested: u64,
    chunks_downloaded: usize,
}

impl DownloadState {
    fn new(chunk_ids: Vec<U256>) -> Self {
        let total_chunks = chunk_ids.len();
        Self {
            chunk_ids,
            total_chunks,
            chunks_requested: 0,
            chunks_downloaded: 0,
        }
    }

    fn is_complete(&self) -> bool {
        self.chunks_downloaded >= self.total_chunks
    }

    fn get_batch_size(&self) -> usize {
        (self.total_chunks - self.chunks_downloaded).min(MAX_BATCH_SIZE)
    }
}

pub(crate) trait FileOperations {
    async fn handle_failed_download(
        &mut self,
        state: &mut DownloadState,
        proxy_request: &mut InitiatorRequest,
        error_code: u8,
        proxy: Proxy,
        cloves: Vec<Clove>,
        chunk_id: U256,
    );
    async fn handle_download_responses(
        &mut self,
        state: &mut DownloadState,
        proxy_request: &mut InitiatorRequest,
        tasks: Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>>,
    );
    async fn store_file(
        &mut self,
        file_info: FileUpload,
        search_id_pool: Vec<U256>,
        file_id_pool: Vec<U256>,
        file_storage: FileStorage
    );
    async fn store_chunks(&mut self, request_id: U256, file_info: FileUpload, file_id_pool: Vec<U256>, file_storage: FileStorage) -> Vec<Proxy>;
    async fn spawn_file_upload_tasks(
        &self,
        messages: &[FileCloveMessage],
        proxies: &[Proxy],
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>>;
    async fn get_file_info(&mut self, search_id_pool: Vec<U256>, metadata_location: Vec<HashLocation>, key_location: Vec<HashLocation>) -> U256;
    async fn download_file(&mut self, file_info: FileInfo, file_id_pool: Vec<U256>) -> U256;
    async fn spawn_file_download_tasks(
        &self,
        state: &mut DownloadState,
        proxies: &[Proxy],
        request_id: U256,
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>>;
    async fn create_download_task(
        &self,
        request_id: U256,
        chunks_requested: u64,
        chunk_id: &U256,
        proxies: &[Proxy],
        proxy_index: usize,
    ) -> JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>;
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
    async fn send_chunk_part(&mut self, request_id: U256, response: GarlemliaResponse, remove_self: bool);
}

impl FileOperations for GarlicCast {
    async fn handle_failed_download(
        &mut self,
        state: &mut DownloadState,
        proxy_request: &mut InitiatorRequest,
        error_code: u8,
        proxy: Proxy,
        cloves: Vec<Clove>,
        chunk_id: U256,
    ) {
        if let Some(updated_proxy) = self.handle_proxy_forwarding(error_code, proxy, cloves).await {
            state.chunks_downloaded += 1;
            proxy_request.proxies.push(updated_proxy);
        } else {
            state.chunk_ids.push(chunk_id);
        }
    }

    async fn handle_download_responses(
        &mut self,
        state: &mut DownloadState,         // Tracks progress of chunk downloads
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
                            state.chunks_downloaded += 1;  // Increment successful download counter
                            proxy_request.proxies.push(proxy); // Store the proxy for future use
                        }
                        // Failed download case
                        Err((error_code, proxy, cloves, chunk_id)) => {
                            // Attempt to recover from failure via proxy forwarding
                            self.handle_failed_download(
                                state,
                                proxy_request,
                                error_code,     // Indicates type of failure
                                proxy,          // The proxy that failed
                                cloves,         // Message fragments that failed to process
                                chunk_id        // ID of chunk that failed to download
                            ).await;
                        }
                    }
                }
                // Task itself failed (e.g. panic, cancellation)
                Err(e) => log::error!(
                    "{}: Unexpected error in download task: {}",
                    self.local_node.address,
                    e
                ),
            }
        }
    }

    /// Asynchronously stores a file by managing its metadata, splitting it into chunks,
    /// distributing data through proxies, and tracking the request lifecycle.
    ///
    /// This function orchestrates the process of uploading a file, including storing
    /// metadata, handling file chunks, and managing network proxies to ensure successful distribution.
    ///
    /// # Arguments
    ///
    /// * `file_info` - A `FileUpload` struct containing information about the file being uploaded, including metadata and key locations.
    /// * `search_id_pool` - A vector of `U256` representing a pool of identifiers for proxy searching to distribute file data.
    /// * `file_id_pool` - A vector of `U256` representing a unique identifier pool for file chunks.
    /// * `file_storage` - A `FileStorage` instance to facilitate the storing of file chunks.
    ///
    /// # Steps
    ///
    /// 1. **Generate a Request ID**:
    ///    A unique `request_id` is created for the current file upload operation using the `u256_random` utility function.
    ///
    /// 2. **Initialize Proxy Request**:
    ///    A new initiator request (`proxy_request`) is prepared to manage communication with proxies for the file upload.
    ///
    /// 3. **Filter Proxies**:
    ///    A subset of proxies is selected by invoking `filter_proxies` with the provided `search_id_pool`.
    ///
    /// 4. **Store Metadata**:
    ///    File metadata and encryption key locations are persisted using `store` methods within the `file_info` object.
    ///
    /// 5. **Upload Metadata**:
    ///    Metadata upload messages are generated using `CloveMessage::file_metadata_upload` and tasks are dispatched to upload metadata.
    ///    - Each message is sent asynchronously to proxies using `spawn_file_upload_tasks`.
    ///    - Task results are processed with `handle_proxy_task_result`, ensuring proper logging and continuation of upload attempts until messages are successfully sent.
    ///
    /// 6. **Handle File Chunks**:
    ///    File data is divided into chunks and distributed across proxies via the `store_chunks` method. The resulting proxies engaged in chunk storage are appended to `proxy_request`.
    ///
    /// 7. **Finalize and Deduplicate Proxies**:
    ///    The list of proxies involved in the operation is sorted and deduplicated based on their `sequence_number` to ensure integrity and prevent duplicates.
    ///
    /// 8. **Track Request**:
    ///    The finalized `proxy_request` is stored in the `requests_as_initiator` map using the `request_id` as the key for future reference or management.
    ///
    /// # Errors
    ///
    /// Any errors encountered during the upload tasks or proxy handling are logged using `log::error`. The function attempts to recover from transient issues by retrying specific tasks.
    ///
    /// # Notes
    ///
    /// * This function assumes an asynchronous runtime for managing async calls and tasks.
    /// * The result of each chunk storage interaction is appended to the list of proxies in the `proxy_request`.
    /// * Proper deduplication ensures clean management of proxies involved in the upload.
    ///
    /// # Example
    ///
    ///
    /// let mut uploader = FileUploader::new();
    /// let file_info = FileUpload::new(/* parameters */);
    /// let search_id_pool = vec![U256::from(1), U256::from(2)];
    /// let file_id_pool = vec![U256::from(100), U256::from(200)];
    /// let file_storage = FileStorage::new();
    ///
    /// uploader.store_file(file_info, search_id_pool, file_id_pool, file_storage).await;
    ///
    async fn store_file(
        &mut self,
        mut file_info: FileUpload,
        search_id_pool: Vec<U256>,
        file_id_pool: Vec<U256>,
        file_storage: FileStorage
    ) {
        // Create initial request tracking structure with generated request ID
        let request_id = u256_random();
        let mut proxy_request = self.create_initiator_request(request_id);

        // Get subset of proxies for metadata distribution
        let file_info_proxies = self.filter_proxies(search_id_pool);

        // Store file metadata
        file_info.metadata_location.store();
        file_info.key_location.store();

        let file_info_messages = CloveMessage::file_metadata_upload(file_info.clone(), Some(request_id)).await;
        // Track number of successfully sent metadata messages
        let mut total_sent = 0;
        let messages_len = file_info_messages.len();

        // Keep trying until all metadata messages are sent
        while total_sent < messages_len {
            // Spawn tasks for remaining unsent messages
            let tasks = self.spawn_file_upload_tasks(
                &file_info_messages[total_sent..],
                &file_info_proxies
            ).await;

            // Process results and track successful sends
            for task in tasks {
                match self.handle_proxy_task_result(task, &mut proxy_request).await {
                    Ok(()) => total_sent += 1,
                    Err(e) => log::error!("Task error: {}", e),
                }
            }
        }

        // Handle file chunks
        let chunk_proxies = self.store_chunks(request_id, file_info, file_id_pool, file_storage).await;
        // Add proxies used for chunk storage to the request tracking
        proxy_request.proxies.extend(chunk_proxies);

        // Sort and deduplicate proxies based on sequence number to ensure unique entries
        // Finalize and store request
        proxy_request.proxies.sort_by_key(|p| p.sequence_number);
        proxy_request.proxies.dedup_by_key(|p| p.sequence_number);

        // Store finalized request for future reference
        self.requests_as_initiator.insert(request_id, proxy_request);
    }

    /// Asynchronously uploads file chunks to a distributed peer-to-peer network through a set of proxy nodes.
    /// The function selects available proxies based on a predefined pool, assigns file chunks to proxies for upload,
    /// manages retries for failed transmissions, and provides real-time upload progress updates in the console.
    /// Creates and spawns a batch of file download tasks
    ///
    /// # Arguments
    /// * `state` - Current state of the download process, including chunk IDs and progress tracking
    /// * `proxies` - List of available proxy nodes that can handle download requests
    /// * `request_id` - Unique identifier for this download request
    /// - `file_info` (FileUpload): Metadata and data pertaining to the file being uploaded, including file chunks.
    /// - `file_id_pool` (Vec<U256>): A pool of proxy node identifiers that are eligible to process the file chunks.
    /// - `file_storage` (FileStorage): A struct representing the storage medium or backend service handling temporary or persistent storage of file data.
    ///
    /// # Returns
    /// Vector of JoinHandles for spawned tasks, where each task can either:
    /// * Success: Return tuple (chunk_id, proxy_used)
    /// * Failure: Return tuple (error_code, proxy_used, cloves, chunk_id)
    /// A `Vec<Proxy>` containing the proxies successfully used during the file chunk upload process.
    ///
    /// # Behavior
    /// 1. **Proxy Selection**:
    ///    - Filters the available proxies (`self.proxies`) to determine those eligible for the upload based on `file_id_pool`.
    /// 2. **Chunk Distribution & Retrying**:
    ///    - Iterates over the file chunks in `file_info`.
    ///    - For each chunk, creates upload-specific messages using `CloveMessage::file_chunk_to_upload`.
    ///    - Transmissions are retried if an initial attempt fails, and failed proxies are removed from further consideration.
    ///    - Employs a round-robin mechanism to distribute file chunks among eligible proxies.
    /// 3. **Progress Monitoring**:
    ///    - Calculates and logs the percentage of completion at fixed intervals (1% increments).
    /// 4. **Proxy Usage Tracking**:
    ///    - Maintains a list of successfully used proxies, ensuring that only unique proxies are included in the result by sorting and deduplication.
    ///
    /// # Remarks
    /// - The function sleeps briefly between operations to control the rate of network requests (`Duration::from_millis(30)` for transmission, `Duration::from_millis(1000)` at the end).
    /// - Progress is displayed in the format: `UPLOADING... <percentage_completed>: <chunks_sent>/<total_chunks>`.
    /// - Failed proxies are identified by their inability to process `send_to_proxy`, after which they are removed from future attempts.
    ///
    /// # Errors
    /// - This function does not explicitly return errors but skips non-functional proxies, retrying with another available proxy.
    /// - No explicit error handling mechanism is provided for failures in creating or sending clove messages.
    ///
    /// # Example Usage
    ///
    /// let request_id = U256::from(1234);
    /// let file_info = FileUpload { /* file metadata and chunks */ };
    /// let file_id_pool = vec![U256::from(1), U256::from(2)];
    /// let file_storage = FileStorage::new();
    ///
    /// let result = instance.store_chunks(request_id, file_info, file_id_pool, file_storage).await;
    /// for proxy in result {
    ///     println!("Used Proxy: {:?}", proxy);
    /// }
    ///
    async fn store_chunks(&mut self, request_id: U256, file_info: FileUpload, file_id_pool: Vec<U256>, file_storage: FileStorage) -> Vec<Proxy> {
        // Track which proxies were successfully used during upload
        let mut proxies_used = vec![];

        // Create a copy of available proxies to avoid mutating self.proxies directly
        let proxies_init = self.proxies.clone();

        // Filter proxies to only those whose sequence numbers are in the file_id_pool
        let mut file_chunk_proxies = vec![];
        for proxy in proxies_init {
            if file_id_pool.contains(&proxy.sequence_number) {
                file_chunk_proxies.push(proxy);
            }
        }

        // Track upload progress
        let mut file_chunks_sent = 0;
        let mut percent_threshold = 0.0; // Used for progress reporting at 1% intervals

        // Process each chunk in the file
        for chunk in file_info.chunks.clone() {
            // Check if we've hit next progress threshold (every 1%)
            if percent_threshold <= file_chunks_sent as f64/file_info.chunks.len() as f64 {
                println!("UPLOADING... {:.1}%: {}/{}",
                         file_chunks_sent as f64/file_info.chunks.len() as f64 * 100.0,
                         file_chunks_sent,
                         file_info.chunks.len()
                );
                percent_threshold = percent_threshold + 0.01;
            }

            // Convert chunk into uploadable messages
            let this_chunk_info = CloveMessage::file_chunk_to_upload(chunk, file_storage.clone(), Some(request_id)).await;

            // Try to send each message part
            for message in this_chunk_info {
                sleep(Duration::from_millis(30)).await;  // Rate limiting
                let mut sent = false;

                // Keep trying proxies until message is sent or we run out of proxies
                while !sent && file_chunk_proxies.len() > 0 {
                    // Select proxy using round-robin distribution
                    let temp_proxy = file_chunk_proxies.get(file_chunks_sent % file_chunk_proxies.len()).unwrap().clone();

                    // Prepare message for transmission with encryption/routing info
                    let cloves = GarlicCast::generate_cloves(
                        message.clone().message,
                        2,  // Number of cloves to generate
                        temp_proxy.sequence_number,
                        Some(temp_proxy.clone().public_key),
                        Some(message.message.request_id().unwrap())
                    ).unwrap();

                    // Attempt to send via a selected proxy
                    sent = self.send_to_proxy(temp_proxy.clone(), cloves).await;

                    if sent {
                        proxies_used.push(temp_proxy);
                    } else {
                        // Remove failed proxy from consideration
                        file_chunk_proxies.remove(file_chunks_sent % file_chunk_proxies.len());
                        println!("FAILED TO SEND!!");
                    }
                }
            }

            file_chunks_sent += 1;
        }

        // Show final progress
        println!("UPLOADING... {:.1}%: {}/{}",
                 file_chunks_sent as f64/file_info.chunks.len() as f64 * 100.0,
                 file_chunks_sent,
                 file_info.chunks.len()
        );
        sleep(Duration::from_millis(1000)).await;

        // Deduplicate the list of used proxies before returning
        proxies_used.sort_by_key(|p| p.sequence_number);
        proxies_used.dedup_by_key(|p| p.sequence_number);

        proxies_used
    }

    async fn spawn_file_upload_tasks(
        &self,
        messages: &[FileCloveMessage],
        proxies: &[Proxy],
    ) -> Vec<JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>> {
        let mut tasks = Vec::new();
        let mut available_proxies = proxies.to_vec();

        for msg in messages {
            if let Some(temp_proxy) = available_proxies.get(rand::random_range(0..available_proxies.len())).cloned() {
                available_proxies.retain(|p| p.sequence_number != temp_proxy.sequence_number);

                let proxy_id = u256_random();
                let request_id = msg.message.request_id().unwrap();

                let task = self.spawn_proxy_task(
                    msg.message.clone(),
                    proxy_id,
                    temp_proxy,
                    request_id
                ).await;

                tasks.push(task);
            }
        }

        tasks
    }

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
    /// 3. Filters available proxies from `self.proxies` based on the `search_id_pool` parameter.
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
    /// * The function maintains state in `self.requests_as_initiator`, allowing tracking of initiated requests.
    /// * Ensure that the `proxies` field in `self` is correctly populated before invoking this function.
    async fn get_file_info(&mut self, search_id_pool: Vec<U256>, metadata_location: Vec<HashLocation>, key_location: Vec<HashLocation>) -> U256 {
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
        let proxies_init = self.proxies.clone();

        let mut proxies = vec![];
        for proxy in proxies_init.clone() {
            if search_id_pool.contains(&proxy.sequence_number) {
                proxies.push(proxy);
            }
        }

        // Get metadata and key locations for current hour
        let metadata_loc = metadata_location.iter()
            .find(|l| l.time.hour() == Utc::now().hour())
            .unwrap()
            .clone()
            .id;
        let key_loc = key_location.iter()
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
                key
            };

            // Generate encrypted cloves for the message
            let cloves = GarlicCast::generate_cloves(
                msg.clone(),
                2,
                temp_proxy.sequence_number,
                Some(temp_proxy.clone().public_key),
                Some(msg.request_id().unwrap())
            ).unwrap();

            // Attempt to send cloves to proxy
            let sent = self.send_to_proxy(temp_proxy.clone(), cloves).await;

            // If send successful, track proxy used
            if sent {
                proxy_request.proxies.push(temp_proxy);
                total_sent += 1;
            }
        }

        // Store request tracking info and return request ID
        self.requests_as_initiator.insert(request_id, proxy_request);

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
    async fn download_file(&mut self, file_info: FileInfo, file_id_pool: Vec<U256>) -> U256 {
        let request_id = u256_random();
        let mut proxy_request = self.create_initiator_request(request_id);
        let file_chunk_proxies = self.filter_proxies(file_id_pool);

        let mut download_state = DownloadState::new(
            file_info.needed_chunks.iter().map(|c| c.chunk_id).collect()
        );

        while !download_state.is_complete() {
            let tasks = self.spawn_file_download_tasks(
                &mut download_state,
                &file_chunk_proxies,
                request_id
            ).await;

            self.handle_download_responses(&mut download_state, &mut proxy_request, tasks).await;
        }

        self.requests_as_initiator.insert(request_id, proxy_request);
        request_id
    }

    async fn spawn_file_download_tasks(
        &self,
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
                let task = self.create_download_task(
                    request_id,
                    state.chunks_requested,
                    chunk_id,
                    proxies,
                    state.chunks_requested as usize % proxies.len() // Round-robin proxy selection
                ).await;

                // Update download state
                state.chunks_requested += 1;
                state.chunk_ids.remove(0); // Remove chunk from pending list
                batch_tasks.push(task);
            }
        }

        batch_tasks
    }

    async fn create_download_task(
        &self,
        request_id: U256,
        chunks_requested: u64,
        chunk_id: &U256,
        proxies: &[Proxy],
        proxy_index: usize,
    ) -> JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>> {
        // Create search message for the specific chunk
        let msg = CloveMessage::SearchGarlemlia {
            request_id: CloveRequestID::new(request_id, chunks_requested),
            key: chunk_id.clone()
        };

        // Clone the selected proxy since it will be moved into the spawned task
        let proxy = proxies[proxy_index].clone();

        // Spawn the actual proxy routing task
        self.spawn_proxy_task(
            msg,
            *chunk_id,
            proxy,
            CloveRequestID::new(request_id, chunks_requested)
        ).await
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
    async fn send_chunk_part(&mut self, request_id: U256, response: GarlemliaResponse, remove_self: bool) {
        let current_request = self.requests_as_proxy.get(&request_id.clone()).cloned();

        let index = rand::random::<u64>();

        if current_request.is_some() {
            let proxy = current_request.unwrap().initiator.clone();

            let msg = CloveMessage::Response {
                request_id: CloveRequestID::new(request_id, index),
                data: response
            };

            let cloves = GarlicCast::generate_cloves(msg.clone(), 2, proxy.sequence_number, Some(proxy.clone().public_key), Some(CloveRequestID::new(request_id, index))).unwrap();

            self.send_to_proxy(proxy, cloves).await;
        }

        if remove_self {
            //self.requests_as_proxy.remove(&request_id);
        }
    }
}