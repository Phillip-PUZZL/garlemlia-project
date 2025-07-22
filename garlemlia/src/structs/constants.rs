// Default KBucket size
pub const DEFAULT_K: usize = 20;
// Maximum KBucket size (currently unused)
pub const MAX_K: usize = 40;
// Number of parallel iterations to perform on iterative lookups + maximum results
pub const LOOKUP_ALPHA: usize = 3;
// Maximum total network packet size to send
pub const SOCKET_DATA_MAX: usize = 49152;
// Maximum total network packet size which can be allocated for file data
pub const SOCKET_FILE_DATA_MAX: usize = 32768;