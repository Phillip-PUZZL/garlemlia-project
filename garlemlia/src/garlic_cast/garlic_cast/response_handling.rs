use std::collections::HashMap;
use primitive_types::U256;
use crate::file_utils::garlemlia_files::FileInfo;
use crate::structs::garlemlia_message::GarlemliaResponse;
use crate::structs::garlic_message::{CloveMessage, CloveRequestID};
use crate::structs::node::Node;
use super::GarlicCast;

pub(crate) trait ResponseHandling {
    fn get_download_responses(&self) -> HashMap<U256, Vec<GarlemliaResponse>>;
    fn get_file_info_responses(&self) -> HashMap<U256, Vec<GarlemliaResponse>>;
    fn get_search_responses(&self) -> Vec<FileInfo>;
    /// Handles the event when a file chunk is downloaded by a peer node.
    ///
    /// This method is triggered when a file chunk has been successfully downloaded. It updates the corresponding
    /// request metadata by appending the response data (including details about the downloaded chunk) to the
    /// list of responses maintained for the request.
    ///
    /// # Parameters
    /// - `request_id`: A `U256` identifier representing the unique ID of the download request.
    /// - `chunk_id`: A `U256` identifier representing the unique ID of the downloaded file chunk.
    /// - `sender`: A `Node` object representing the peer node that downloaded the file chunk.
    ///
    /// # Behavior
    /// - Attempts to retrieve the metadata for the file download request matching `request_id` by accessing
    ///   the `requests_as_initiator` map.
    /// - If the request metadata is found:
    ///   - Appends a `CloveMessage::Response` containing a `GarlemliaResponse::FileChunkInfo` to the request's
    ///     response list. This encapsulates metadata such as the `request_id`, `chunk_id`, and sender information.
    /// - If the request metadata is not found, the function will silently do nothing (no error handling implemented).
    ///
    /// # Notes
    /// - The `chunk_size` and `parts_count` fields in the `GarlemliaResponse::FileChunkInfo` are currently set to `0`.
    ///   Ensure to update these values if accurate chunk metadata needs to be provided.
    /// - This function assumes the presence of prior initialization of the `requests_as_initiator` map and its entries.
    ///
    /// # Example (Pseudo-scenario)
    ///
    /// let mut download_handler = FileDownloadHandler::new();
    /// let request_id = U256::from(1);
    /// let chunk_id = U256::from(10);
    /// let sender_node = Node::new(...);
    ///
    /// download_handler.file_chunk_downloaded(request_id, chunk_id, sender_node).await;
    ///
    /// // Internally updates the request metadata for `request_id`
    /// // Adds a response detailing the downloaded chunk.
    ///
    /// # Potential Enhancements
    /// - Add error handling/logging if `request_id` is not found in the `requests_as_initiator` map.
    /// - Populate the `chunk_size` and `parts_count` fields with appropriate chunk-specific information.
    async fn file_chunk_downloaded(&mut self, request_id: U256, chunk_id: U256, sender: Node);
}

impl ResponseHandling for GarlicCast {
    /// Retrieves a collection of download responses organized by a unique identifier (U256).
    ///
    /// This function iterates through the requests where the current instance is the
    /// initiator, and extracts relevant `GarlemliaResponse::FileChunkInfo` responses
    /// from the nested `CloveMessage` structure. Each unique identifier (`U256`) is
    /// associated with a vector of these specific response types.
    ///
    /// # Returns
    /// A `HashMap` where:
    /// * The key is a `U256` representing a unique identifier.
    /// * The value is a `Vec<GarlemliaResponse>` containing extracted `FileChunkInfo` responses.
    ///
    /// # Examples
    ///
    /// let responses = instance.get_download_responses();
    /// for (request_id, file_chunk_responses) in responses {
    ///     println!("Request ID: {:?}", request_id);
    ///     for response in file_chunk_responses {
    ///         println!("Response: {:?}", response);
    ///     }
    /// }
    ///
    /// # Notes
    /// * This function clones `self.requests_as_initiator` to work with its contents
    ///   without modifying the original data.
    /// * Non-`GarlemliaResponse::FileChunkInfo` responses are ignored.
    /// * Responses of other types within the `CloveMessage` structure are skipped.
    ///
    /// # Assumptions
    /// * `self.requests_as_initiator` is a collection of `(U256, RequestData)` tuples,
    ///   where `RequestData` has a `responses` field containing a vector of `CloveMessage`.
    /// * The association between response data and request ID relies on the logic
    ///   encapsulated in the `CloveMessage` and `GarlemliaResponse` enums.
    ///
    /// # Panics
    /// * The function will panic if the `response_hash` map is accessed with a key
    ///   that does not exist. This occurs because `.unwrap()` is used directly. Ensure
    ///   that the input data is consistent to avoid runtime issues.
    fn get_download_responses(&self) -> HashMap<U256, Vec<GarlemliaResponse>> {
        let mut response_hash: HashMap<U256, Vec<GarlemliaResponse>> = HashMap::new();

        for (request_id, request_data) in &self.requests_as_initiator {
            let responses = request_data.responses.iter().filter_map(|msg| {
                match msg {
                    CloveMessage::Response { data, .. } => {
                        match data {
                            GarlemliaResponse::FileChunkInfo { .. } => Some(data.clone()),
                            _ => None
                        }
                    }
                    _ => None
                }
            }).collect();

            response_hash.insert(*request_id, responses);
        }

        response_hash
    }

    /// Retrieves a mapping of file requests and their corresponding responses.
    ///
    /// This method processes the incoming responses for file requests where the current instance is the initiator.
    /// It returns a `HashMap` where the keys (`U256`) represent unique identifiers for file requests, and
    /// the values are vectors containing relevant `GarlemliaResponse` objects such as `MetaData` or `FileKey`.
    ///
    /// # Returns
    /// A `HashMap<U256, Vec<GarlemliaResponse>>`:
    /// - `U256` - The unique identifier for a file request.
    /// - `Vec<GarlemliaResponse>` - A collection of relevant responses (`MetaData` or `FileKey` types) 
    ///   associated with the corresponding request.
    ///
    /// # Process
    /// 1. Clones the file request data (`requests_as_initiator`) to avoid modifying the original.
    /// 2. Iterates through the cloned file requests.
    /// 3. For each request, initializes an empty vector in the output `HashMap`.
    /// 4. Looks into the responses of the current request:
    ///    - Filters out only the `CloveMessage::Response` messages.
    ///    - Further narrows down to `GarlemliaResponse::MetaData` and `GarlemliaResponse::FileKey`.
    ///    - Adds the valid `GarlemliaResponse` data to the corresponding request's entry in the result.
    ///
    /// # Example
    ///
    /// let file_info_responses = self.get_file_info_responses();
    /// for (request_id, responses) in file_info_responses {
    ///     println!("Request ID: {:?}", request_id);
    ///     for response in responses {
    ///         println!("Response: {:?}", response);
    ///     }
    /// }
    ///
    /// # Note
    /// - If no valid `GarlemliaResponse` objects are found for a request, its vector in the `HashMap` will be empty.
    /// - This method assumes that all `GarlemliaResponse::MetaData` and `GarlemliaResponse::FileKey` responses 
    ///   are relevant and should be retained.
    ///
    /// # Panics
    /// This function will panic if:
    /// - The `HashMap` entry for a request ID is accessed with `unwrap()` during mutation, and the entry is unexpectedly missing.
    ///   However, this is unlikely since the entry is inserted at the beginning of the loop before any modification.
    fn get_file_info_responses(&self) -> HashMap<U256, Vec<GarlemliaResponse>> {
        let responses = self.requests_as_initiator.clone();

        let mut response_hash = HashMap::new();
        for i in responses {
            response_hash.insert(i.0, vec![]);
            for j in i.1.responses {
                match j {
                    CloveMessage::Response { data, .. } => {
                        match data.clone() {
                            GarlemliaResponse::MetaData { .. } | GarlemliaResponse::FileKey { .. } => {
                                response_hash.get_mut(&i.0).unwrap().push(data);
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }

        response_hash
    }

    /// Retrieves and processes search responses, returning a list of distinct `FileInfo` objects sorted by request ID.
    ///
    /// This method processes the stored search request data (`requests_as_initiator`) to extract
    /// relevant file information (e.g., name, file type, size, categories, metadata location, and key location)
    /// from the responses. Each `FileInfo` object is augmented with its associated request ID,
    /// and the result is sorted and deduplicated based on the request ID.
    ///
    /// # Returns
    ///
    /// A `Vec<FileInfo>` containing unique and sorted file information extracted from the search responses.
    ///
    /// # Process
    /// 1. Clone and iterate through all stored search requests.
    /// 2. Extract responses from each request and check if they are instances of `CloveMessage::Response`.
    /// 3. If the response contains a `GarlemliaResponse::FileName`, create a `FileInfo` object
    ///    from its data and associate it with the request ID.
    /// 4. Collect all valid `FileInfo` objects into a vector.
    /// 5. Sort the vector by request ID.
    /// 6. Deduplicate entries with the same request ID to ensure uniqueness.
    ///
    /// # Example
    ///
    /// let search_responses = object.get_search_responses();
    /// for file_info in search_responses {
    ///     println!("File name: {}, Request ID: {}", file_info.get_name(), file_info.get_request_id());
    /// }
    ///
    /// # Notes
    ///
    /// - This method assumes that each valid `GarlemliaResponse::FileName` is processed
    ///   into a `FileInfo` object and that the request ID is set via `set_request_id`.
    /// - Only unique `FileInfo` objects identified by their request ID are included in the final result.
    fn get_search_responses(&self) -> Vec<FileInfo> {
        // Clone the HashMap of initiator requests to avoid borrowing conflicts
        let responses = self.requests_as_initiator.clone();

        let mut response_vec = vec![];

        // Iterate through all initiator requests
        // i.1 contains InitiatorRequest data, i.0 contains the request ID (U256)
        for i in responses {
            // Process each response stored in the InitiatorRequest
            for j in i.1.responses {
                match j {
                    // Only handle Response variant of CloveMessage
                    CloveMessage::Response { data, .. } => {
                        match data {
                            // Extract file information only from FileName responses
                            GarlemliaResponse::FileName {
                                name,
                                file_type,
                                size,
                                categories,
                                metadata_location,
                                key_location
                            } => {
                                // Create new FileInfo object from response data
                                let mut insert_to_vec = FileInfo::from(
                                    name,
                                    file_type,
                                    size,
                                    categories,
                                    metadata_location,
                                    key_location
                                );
                                // Associate the FileInfo with its request ID for tracking
                                insert_to_vec.set_request_id(i.0);
                                response_vec.push(insert_to_vec);
                            }
                            // Ignore other response types
                            _ => {}
                        }
                    }
                    // Ignore other message types
                    _ => {}
                }
            }
        }

        // Sort FileInfo objects by their request IDs for consistent ordering
        response_vec.sort_by_key(|fi| fi.get_request_id());
        // Remove duplicate FileInfo objects with the same request ID
        response_vec.dedup_by_key(|fi| fi.get_request_id());

        response_vec
    }

    /// Handles the event when a file chunk is downloaded by a peer node.
    ///
    /// This method is triggered when a file chunk has been successfully downloaded. It updates the corresponding
    /// request metadata by appending the response data (including details about the downloaded chunk) to the
    /// list of responses maintained for the request.
    ///
    /// # Parameters
    /// - `request_id`: A `U256` identifier representing the unique ID of the download request.
    /// - `chunk_id`: A `U256` identifier representing the unique ID of the downloaded file chunk.
    /// - `sender`: A `Node` object representing the peer node that downloaded the file chunk.
    ///
    /// # Behavior
    /// - Attempts to retrieve the metadata for the file download request matching `request_id` by accessing
    ///   the `requests_as_initiator` map.
    /// - If the request metadata is found:
    ///   - Appends a `CloveMessage::Response` containing a `GarlemliaResponse::FileChunkInfo` to the request's
    ///     response list. This encapsulates metadata such as the `request_id`, `chunk_id`, and sender information.
    /// - If the request metadata is not found, the function will silently do nothing (no error handling implemented).
    ///
    /// # Notes
    /// - The `chunk_size` and `parts_count` fields in the `GarlemliaResponse::FileChunkInfo` are currently set to `0`.
    ///   Ensure to update these values if accurate chunk metadata needs to be provided.
    /// - This function assumes the presence of prior initialization of the `requests_as_initiator` map and its entries.
    ///
    /// # Example (Pseudo-scenario)
    ///
    /// let mut download_handler = FileDownloadHandler::new();
    /// let request_id = U256::from(1);
    /// let chunk_id = U256::from(10);
    /// let sender_node = Node::new(...);
    ///
    /// download_handler.file_chunk_downloaded(request_id, chunk_id, sender_node).await;
    ///
    /// // Internally updates the request metadata for `request_id`
    /// // Adds a response detailing the downloaded chunk.
    ///
    /// # Potential Enhancements
    /// - Add error handling/logging if `request_id` is not found in the `requests_as_initiator` map.
    /// - Populate the `chunk_size` and `parts_count` fields with appropriate chunk-specific information.
    async fn file_chunk_downloaded(&mut self, request_id: U256, chunk_id: U256, sender: Node) {
        let request_info = self.requests_as_initiator.get_mut(&request_id);

        if request_info.is_some() {
            let proxy_request = request_info.unwrap();

            proxy_request.responses.push(CloveMessage::Response {
                request_id: CloveRequestID::new(request_id, 0),
                data: GarlemliaResponse::FileChunkInfo {
                    request_id,
                    chunk_id,
                    chunk_size: 0,
                    parts_count: 0,
                    sender
                }
            });
        }
    }
}