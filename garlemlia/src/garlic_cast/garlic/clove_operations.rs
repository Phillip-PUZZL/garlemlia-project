use std::error::Error;
use primitive_types::U256;
use rsa::{RsaPrivateKey, RsaPublicKey};
use crate::garlic_cast::garlic::utils::{clove_to_message, encrypt_key, encrypt_message, generate_cloves, generate_encryption_key, generate_reed_solomon_shards, pad_message};
use crate::helper_functions::helper_functions::u256_random;
use crate::structs::constants::{DATA_SHARDS, DEFAULT_INDEX, MIN_PROXY_COUNT};
use crate::structs::error::CloveMessageError;
use crate::structs::garlic_message::{Clove, CloveMessage, CloveRequestID};
use super::GarlicCast;

pub(crate) trait CloveOperations {
    fn generate_cloves(
        msg: CloveMessage,
        count: u8,
        sequence_number: U256,
        recipient_pub_key: Option<RsaPublicKey>,
        request_id: Option<CloveRequestID>,
    ) -> Result<Vec<Clove>, Box<dyn Error>>;
    fn clove_generator(
        msg_serialized: Vec<u8>,
        count: u8,
        sequence_number: U256,
        recipient_pub_key: Option<RsaPublicKey>,
        request_id: CloveRequestID,
    ) -> Result<Vec<Clove>, Box<dyn Error>>;
    fn reconstruct_encrypted_clove_message(
        clove_1: Clove,
        clove_2: Clove,
        private_key: RsaPrivateKey,
    ) -> Result<CloveMessage, CloveMessageError>;
    fn reconstruct_clove_message(
        clove_1: Clove,
        clove_2: Clove,
    ) -> Result<CloveMessage, CloveMessageError>;
}

impl CloveOperations for GarlicCast {
    /// Generate cloves for message transmission with optional RSA encryption
    fn generate_cloves(
        msg: CloveMessage,
        count: u8,
        sequence_number: U256,
        recipient_pub_key: Option<RsaPublicKey>,
        request_id: Option<CloveRequestID>,
    ) -> Result<Vec<Clove>, Box<dyn Error>> {
        let msg_serialized = bincode::serialize(&msg)
            .map_err(|e| Box::new(e) as Box<dyn Error>)?;

        let request_id = request_id.unwrap_or_else(|| {
            CloveRequestID::new(u256_random(), DEFAULT_INDEX)
        });

        GarlicCast::clove_generator(
            msg_serialized,
            count,
            sequence_number,
            recipient_pub_key,
            request_id,
        )
    }

    /// Generates a set of `Clove` objects containing encrypted message data and keys, partitioned across shards
    /// using Reed-Solomon erasure coding.
    ///
    /// # Parameters
    /// - `msg_serialized` (`Vec<u8>`): The serialized message to be processed.
    /// - `count` (`u8`): The number of cloves (or shards) to generate. This will be clamped to a minimum value `MIN_PROXY_COUNT`.
    /// - `sequence_number` (`U256`): A unique sequence number for identifying the cloves in a sequence.
    /// - `recipient_pub_key` (`Option<RsaPublicKey>`): The optional RSA public key of the recipient. If provided, it will
    ///   be used to encrypt the generated symmetric encryption key.
    /// - `request_id` (`CloveRequestID`): An identifier for associating the cloves with a specific request.
    ///
    /// # Returns
    /// - `Result<Vec<Clove>, Box<dyn Error>>`:
    ///   - On success, returns a `Vec<Clove>` containing the generated clove objects.
    ///   - On failure, returns an error wrapped in a `Box<dyn Error>`.
    ///
    /// # Workflow
    /// 1. Ensures that the number of shards (`count`) meets the minimum proxy count threshold (`MIN_PROXY_COUNT`).
    /// 2. Generates a symmetric encryption key.
    /// 3. Pads the input message bytes to meet encryption requirements.
    /// 4. Encrypts the padded message using the generated symmetric key.
    /// 5. Encrypts the symmetric key itself using the recipient's RSA public key, if provided.
    /// 6. Uses Reed-Solomon erasure coding to split the encrypted message data and encrypted symmetric key
    ///    into multiple data and key shards.
    /// 7. Calls `generate_cloves`, which constructs the `Clove` objects by combining sequence information,
    ///    request identifiers, and shard data.
    ///
    /// # Errors
    /// This function may return various errors depending on execution failures, such as
    /// - Failure to generate the symmetric encryption key.
    /// - Failure to properly encrypt the message or key.
    /// - Errors during Reed-Solomon shard generation.
    /// - Any issues arising from `generate_cloves`.
    ///
    /// # Example
    ///
    /// use some_module::{clove_generator, CloveRequestID, RsaPublicKey};
    /// use ethereum_types::U256;
    ///
    /// let message = b"Hello, secure world!".to_vec();
    /// let count = 5;
    /// let sequence_number = U256::from(1234);
    /// let recipient_pub_key = Some(get_recipient_public_key());
    /// let request_id = CloveRequestID::new();
    ///
    /// let cloves = clove_generator(message, count, sequence_number, recipient_pub_key, request_id);
    /// match cloves {
    ///     Ok(cloves_vec) => {
    ///         for clove in cloves_vec {
    ///             println!("Generated Clove: {:?}", clove);
    ///         }
    ///     }
    ///     Err(e) => eprintln!("Failed to generate cloves: {}", e),
    /// }
    ///
    ///
    /// # Notes
    /// - The generated cloves can be used for secure, fault-tolerant transmission or storage of encrypted message data.
    /// - Since Reed-Solomon coding is employed, a subset of shards (meeting the data shard threshold) is sufficient to
    ///   reconstruct the original message and key.
    /// - Ensure that `MIN_PROXY_COUNT` and `DATA_SHARDS` are properly configured to meet your redundancy and reliability needs.
    fn clove_generator(
        msg_serialized: Vec<u8>,
        count: u8,
        sequence_number: U256,
        recipient_pub_key: Option<RsaPublicKey>,
        request_id: CloveRequestID,
    ) -> Result<Vec<Clove>, Box<dyn Error>> {
        let actual_count = count.max(MIN_PROXY_COUNT);
        let encryption_key = generate_encryption_key()?;
        let padded_message = pad_message(&msg_serialized);
        let encrypted_data = encrypt_message(&padded_message, &encryption_key)?;
        let encrypted_key = encrypt_key(encryption_key.to_vec(), recipient_pub_key)?;

        let (data_shards_vec, key_shards_vec) = generate_reed_solomon_shards(
            encrypted_data,
            encrypted_key,
            actual_count,
        )?;

        generate_cloves(
            sequence_number,
            request_id,
            data_shards_vec,
            key_shards_vec,
            count.max(DATA_SHARDS as u8),
            actual_count,
        )
    }


    /// Reconstructs a CloveMessage from two clove fragments with RSA decryption.
    ///
    /// # Arguments
    /// * `clove_1` - First clove fragment
    /// * `clove_2` - Second clove fragment
    /// * `private_key` - RSA private key for decryption
    ///
    /// # Returns
    /// * `Result<CloveMessage, CloveMessageError>` - Reconstructed and decrypted message or error
    fn reconstruct_encrypted_clove_message(
        clove_1: Clove,
        clove_2: Clove,
        private_key: RsaPrivateKey,
    ) -> Result<CloveMessage, CloveMessageError> {
        clove_to_message(clove_1, clove_2, Some(private_key))
            .map_err(|e| CloveMessageError::DecryptionError(e))
    }

    /// Reconstructs a CloveMessage from two clove fragments without RSA decryption.
    ///
    /// # Arguments
    /// * `clove_1` - First clove fragment
    /// * `clove_2` - Second clove fragment
    ///
    /// # Returns
    /// * `Result<CloveMessage, CloveMessageError>` - Reconstructed message or error
    fn reconstruct_clove_message(
        clove_1: Clove,
        clove_2: Clove,
    ) -> Result<CloveMessage, CloveMessageError> {
        clove_to_message(clove_1, clove_2, None)
            .map_err(|e| CloveMessageError::DecodingError(e))
    }
}