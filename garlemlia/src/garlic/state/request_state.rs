use crate::garlic::{CloveMessage, CloveNode};
use chrono::{DateTime, Utc};
use primitive_types::U256;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serializable version of proxy struct for storage in a JSON file
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SerializableProxy {
    sequence_number: U256,
    neighbor_1: CloveNode,
    neighbor_2: CloveNode,
    neighbor_1_hops: u16,
    neighbor_2_hops: u16,
    public_key: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    used_last: DateTime<Utc>,
}

impl SerializableProxy {
    pub fn from(proxy: Proxy) -> SerializableProxy {
        SerializableProxy {
            sequence_number: proxy.sequence_number,
            neighbor_1: proxy.neighbor_1,
            neighbor_2: proxy.neighbor_2,
            neighbor_1_hops: proxy.neighbor_1_hops,
            neighbor_2_hops: proxy.neighbor_2_hops,
            public_key: proxy
                .public_key
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap(),
            used_last: proxy.used_last,
        }
    }

    pub fn to_proxy(self) -> Proxy {
        Proxy {
            sequence_number: self.sequence_number,
            neighbor_1: self.neighbor_1,
            neighbor_2: self.neighbor_2,
            neighbor_1_hops: self.neighbor_1_hops,
            neighbor_2_hops: self.neighbor_2_hops,
            public_key: RsaPublicKey::from_public_key_pem(&*self.public_key).unwrap(),
            used_last: self.used_last,
        }
    }

    pub fn hashmap_to_serializable(
        proxies: HashMap<U256, Proxy>,
    ) -> HashMap<U256, SerializableProxy> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, SerializableProxy::from(item.1));
        }

        proxies_serial
    }

    pub fn hashmap_to_proxy(proxies: HashMap<U256, SerializableProxy>) -> HashMap<U256, Proxy> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, item.1.to_proxy());
        }

        proxies_serial
    }

    pub fn vec_to_serializable(proxies: Vec<Proxy>) -> Vec<SerializableProxy> {
        let mut proxies_serial = vec![];

        for proxy in proxies {
            proxies_serial.push(SerializableProxy::from(proxy));
        }

        proxies_serial
    }

    pub fn vec_to_proxy(proxies_serial: Vec<SerializableProxy>) -> Vec<Proxy> {
        let mut proxies = vec![];

        for proxy in proxies_serial {
            proxies.push(proxy.to_proxy());
        }

        proxies
    }
}

/// Struct holding Proxy peer information
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proxy {
    pub sequence_number: U256,
    pub neighbor_1: CloveNode,
    pub neighbor_2: CloveNode,
    pub neighbor_1_hops: u16,
    pub neighbor_2_hops: u16,
    pub public_key: RsaPublicKey,
    pub used_last: DateTime<Utc>,
}

/// Serializable version of initiator request struct
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableInitiatorRequest {
    request_id: U256,
    validator_required: bool,
    proxies: Vec<SerializableProxy>,
    proxy_id_associations: HashMap<U256, SerializableProxy>,
    responses: Vec<CloveMessage>,
}

impl SerializableInitiatorRequest {
    pub fn from(initiator_request: InitiatorRequest) -> SerializableInitiatorRequest {
        SerializableInitiatorRequest {
            request_id: initiator_request.request_id,
            validator_required: initiator_request.validator_required,
            proxies: SerializableProxy::vec_to_serializable(initiator_request.proxies),
            proxy_id_associations: SerializableProxy::hashmap_to_serializable(
                initiator_request.proxy_id_associations,
            ),
            responses: initiator_request.responses,
        }
    }

    pub fn to_initiator_request(self) -> InitiatorRequest {
        InitiatorRequest {
            request_id: self.request_id,
            validator_required: self.validator_required,
            proxies: SerializableProxy::vec_to_proxy(self.proxies),
            proxy_id_associations: SerializableProxy::hashmap_to_proxy(self.proxy_id_associations),
            responses: self.responses,
        }
    }

    pub fn hashmap_to_serializable(
        proxies: HashMap<U256, InitiatorRequest>,
    ) -> HashMap<U256, SerializableInitiatorRequest> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, SerializableInitiatorRequest::from(item.1));
        }

        proxies_serial
    }

    pub fn hashmap_to_initiator_request(
        proxies: HashMap<U256, SerializableInitiatorRequest>,
    ) -> HashMap<U256, InitiatorRequest> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, item.1.to_initiator_request());
        }

        proxies_serial
    }
}

/// Initiator request struct for holding information about a request coming from an
/// initiator
#[derive(Clone, Debug, PartialEq)]
pub struct InitiatorRequest {
    pub request_id: U256,
    pub validator_required: bool,
    pub proxies: Vec<Proxy>,
    pub proxy_id_associations: HashMap<U256, Proxy>,
    pub responses: Vec<CloveMessage>,
}

/// Serializable version of a proxy request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableProxyRequest {
    sequence_number: U256,
    request_id: U256,
    self_proxy_id: Option<U256>,
    validator_required: bool,
    initiator: SerializableProxy,
    sent: DateTime<Utc>,
    request: CloveMessage,
}

impl SerializableProxyRequest {
    pub fn from(initiator_request: ProxyRequest) -> SerializableProxyRequest {
        SerializableProxyRequest {
            sequence_number: initiator_request.sequence_number,
            request_id: initiator_request.request_id,
            self_proxy_id: initiator_request.self_proxy_id,
            validator_required: initiator_request.validator_required,
            initiator: SerializableProxy::from(initiator_request.initiator),
            sent: initiator_request.sent,
            request: initiator_request.request,
        }
    }

    pub fn to_proxy_request(self) -> ProxyRequest {
        ProxyRequest {
            sequence_number: self.sequence_number,
            request_id: self.request_id,
            self_proxy_id: self.self_proxy_id,
            validator_required: self.validator_required,
            initiator: self.initiator.to_proxy(),
            sent: self.sent,
            request: self.request,
        }
    }

    pub fn hashmap_to_serializable(
        proxies: HashMap<U256, ProxyRequest>,
    ) -> HashMap<U256, SerializableProxyRequest> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, SerializableProxyRequest::from(item.1));
        }

        proxies_serial
    }

    pub fn hashmap_to_proxy_request(
        proxies: HashMap<U256, SerializableProxyRequest>,
    ) -> HashMap<U256, ProxyRequest> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, item.1.to_proxy_request());
        }

        proxies_serial
    }
}

/// Struct containing information about a request to a Proxy
#[derive(Clone, Debug, PartialEq)]
pub struct ProxyRequest {
    pub sequence_number: U256,
    pub request_id: U256,
    pub self_proxy_id: Option<U256>,
    pub validator_required: bool,
    pub initiator: Proxy,
    pub sent: DateTime<Utc>,
    pub request: CloveMessage,
}
