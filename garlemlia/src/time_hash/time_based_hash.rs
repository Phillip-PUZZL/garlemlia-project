use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use primitive_types::U256;
use rsa::sha2::Sha256;
use serde::{Deserialize, Serialize};
use crate::garlemlia_structs::garlemlia_structs::u256_random;

use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HashLocations {
    time: DateTime<Utc>,
    id: U256
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RotatingHash {
    seed: U256,
    rotation_time_hours: f64,
    stored_on: Option<DateTime<Utc>>
}

impl RotatingHash {
    pub fn new(rotation_time_hours: f64) -> RotatingHash {
        RotatingHash {
            seed: u256_random(),
            rotation_time_hours,
            stored_on: None
        }
    }

    pub fn store(&mut self) {
        let now = Utc::now();
        self.stored_on = Some(Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), now.hour(), 0, 0).unwrap());
    }

    pub fn get_current(&self) -> Option<U256> {
        match self.stored_on {
            Some(stored_time) => {
                RotatingHash::compute_rotating_id(self.seed, stored_time, self.rotation_time_hours, Utc::now())
            }
            None => {
                None
            }
        }
    }

    pub fn get_next(&self, hours: u8) -> Option<Vec<HashLocations>> {
        match self.stored_on {
            Some(stored_time) => {
                let mut value_vec = vec![];
                let now = Utc::now();

                for i in 0..hours {
                    let analysis_time = Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), now.hour() + i as u32, 0, 0).unwrap();
                    let time_id = RotatingHash::compute_rotating_id(self.seed, stored_time, self.rotation_time_hours, analysis_time);

                    match time_id {
                        Some(time_id) => {
                            value_vec.push(HashLocations { time: analysis_time, id: time_id });
                        }
                        None => {
                            return None;
                        }
                    }
                }

                Some(value_vec)
            }
            None => {
                None
            }
        }
    }

    pub fn next_rotation(&self) -> Option<f64> {
        match self.stored_on {
            Some(stored_time) => {
                let rotation_secs = (self.rotation_time_hours * 3600.0) as i64;

                let next_rotation_time = stored_time + Duration::seconds(rotation_secs);

                let secs_remaining = next_rotation_time.timestamp() - Utc::now().timestamp();

                Some(secs_remaining as f64 / 3600.0)
            }
            None => {
                None
            }
        }
    }

    pub fn compute_rotating_id(seed: U256, stored_on: DateTime<Utc>, rotation_hours: f64, time: DateTime<Utc>) -> Option<U256> {
        let rotation_seconds = (rotation_hours * 3600.0).round() as i64;
        let elapsed = time.timestamp() - stored_on.timestamp();

        let periods_elapsed: i64;
        if elapsed <= 0 {
            periods_elapsed = 0;
        } else {
            periods_elapsed = elapsed / rotation_seconds;
        };

        let counter_bytes = periods_elapsed.to_be_bytes();

        let mac = HmacSha256::new_from_slice(&seed.to_big_endian());

        match mac {
            Ok(mut mac) => {
                mac.update(&counter_bytes);
                let result = mac.finalize().into_bytes();

                let mut id_bytes = [0u8; 32];
                id_bytes.copy_from_slice(&result);

                Some(U256::from_big_endian(&id_bytes))
            }
            Err(_) => {
                None
            }
        }
    }
}