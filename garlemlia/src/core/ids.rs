use primitive_types::U256;
use rand::{rng, RngCore};

/// Generate a random 256-bit unsigned integer
pub fn u256_random() -> U256 {
    let mut rng = rng();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    U256::from_big_endian(&buf)
}
