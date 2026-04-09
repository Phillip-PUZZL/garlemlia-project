use crate::core::u256_random;
use crate::files::storage::FileStorage;
use crate::files::upload::FileUpload;
use crate::garlic::files::transfer::{TraitTransfer, Transfer};
use crate::garlic::forwarding::proxy_discovery::{ProxyDiscovery, TraitProxyDiscovery};
use crate::garlic::forwarding::proxy_runtime::{ProxyRuntime, TraitProxyRuntime};
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::state::request_state::Proxy;
use crate::garlic::{CloveMessage, CloveProtocol, TraitCloveProtocol};
use primitive_types::U256;
use std::time::Duration;
use tokio::time::sleep;

#[allow(dead_code)]
pub(crate) trait TraitUpload {
    async fn store_file(
        garlic: &mut GarlicCast,
        file_info: FileUpload,
        search_id_pool: Vec<U256>,
        file_id_pool: Vec<U256>,
        file_storage: FileStorage,
    );
    async fn store_chunks(
        garlic: &mut GarlicCast,
        request_id: U256,
        file_info: FileUpload,
        file_id_pool: Vec<U256>,
        file_storage: FileStorage,
    ) -> Vec<Proxy>;
}

pub struct Upload;
impl TraitUpload for Upload {
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
        garlic: &mut GarlicCast,
        mut file_info: FileUpload,
        search_id_pool: Vec<U256>,
        file_id_pool: Vec<U256>,
        file_storage: FileStorage,
    ) {
        // Create initial request tracking structure with generated request ID
        let request_id = u256_random();
        let mut proxy_request = garlic.create_initiator_request(request_id);

        // Get subset of proxies for metadata distribution
        let file_info_proxies = ProxyDiscovery::filter_proxies(garlic, search_id_pool);

        // Store file metadata
        file_info.metadata_location.store();
        file_info.key_location.store();

        let file_info_messages =
            CloveMessage::file_metadata_upload(file_info.clone(), Some(request_id)).await;
        // Track number of successfully sent metadata messages
        let mut total_sent = 0;
        let messages_len = file_info_messages.len();

        // Keep trying until all metadata messages are sent
        while total_sent < messages_len {
            // Spawn tasks for remaining unsent messages
            let tasks = Transfer::spawn_file_upload_tasks(
                garlic,
                &file_info_messages[total_sent..],
                &file_info_proxies,
            )
            .await;

            // Process results and track successful sends
            for task in tasks {
                match ProxyRuntime::handle_proxy_task_result(garlic, task, &mut proxy_request).await
                {
                    Ok(()) => total_sent += 1,
                    Err(e) => log::error!("Task error: {}", e),
                }
            }
        }

        // Handle file chunks
        let chunk_proxies =
            Upload::store_chunks(garlic, request_id, file_info, file_id_pool, file_storage).await;
        // Add proxies used for chunk storage to the request tracking
        proxy_request.proxies.extend(chunk_proxies);

        // Sort and deduplicate proxies based on sequence number to ensure unique entries
        // Finalize and store request
        proxy_request.proxies.sort_by_key(|p| p.sequence_number);
        proxy_request.proxies.dedup_by_key(|p| p.sequence_number);

        // Store finalized request for future reference
        garlic
            .requests_as_initiator
            .insert(request_id, proxy_request);
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
    ///    - Filters the available proxies (`garlic.proxies`) to determine those eligible for the upload based on `file_id_pool`.
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
    async fn store_chunks(
        garlic: &mut GarlicCast,
        request_id: U256,
        file_info: FileUpload,
        file_id_pool: Vec<U256>,
        file_storage: FileStorage,
    ) -> Vec<Proxy> {
        // Track which proxies were successfully used during upload
        let mut proxies_used = vec![];

        // Create a copy of available proxies to avoid mutating garlic.proxies directly
        let proxies_init = garlic.proxies.clone();

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
            if percent_threshold <= file_chunks_sent as f64 / file_info.chunks.len() as f64 {
                println!(
                    "UPLOADING... {:.1}%: {}/{}",
                    file_chunks_sent as f64 / file_info.chunks.len() as f64 * 100.0,
                    file_chunks_sent,
                    file_info.chunks.len()
                );
                percent_threshold = percent_threshold + 0.01;
            }

            // Convert chunk into uploadable messages
            let this_chunk_info =
                CloveMessage::file_chunk_to_upload(chunk, file_storage.clone(), Some(request_id))
                    .await;

            // Try to send each message part
            for message in this_chunk_info {
                sleep(Duration::from_millis(30)).await; // Rate limiting
                let mut sent = false;

                // Keep trying proxies until message is sent or we run out of proxies
                while !sent && file_chunk_proxies.len() > 0 {
                    // Select proxy using round-robin distribution
                    let temp_proxy = file_chunk_proxies
                        .get(file_chunks_sent % file_chunk_proxies.len())
                        .unwrap()
                        .clone();

                    // Prepare message for transmission with encryption/routing info
                    let cloves = CloveProtocol::generate(
                        message.clone().message,
                        2, // Number of cloves to generate
                        temp_proxy.sequence_number,
                        Some(temp_proxy.clone().public_key),
                        Some(message.message.request_id().unwrap()),
                    )
                    .unwrap();

                    // Attempt to send via a selected proxy
                    sent = garlic.send_to_proxy(temp_proxy.clone(), cloves).await;

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
        println!(
            "UPLOADING... {:.1}%: {}/{}",
            file_chunks_sent as f64 / file_info.chunks.len() as f64 * 100.0,
            file_chunks_sent,
            file_info.chunks.len()
        );
        sleep(Duration::from_millis(1000)).await;

        // Deduplicate the list of used proxies before returning
        proxies_used.sort_by_key(|p| p.sequence_number);
        proxies_used.dedup_by_key(|p| p.sequence_number);

        proxies_used
    }
}
