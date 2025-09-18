use crate::structs::node::Node;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{env, fs};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn new_settings_file(settings_directory: Option<String>, files_directory: Option<String>) -> Result<Settings, Box<dyn std::error::Error>> {
    let settings_dir = format!("{}/settings.config", settings_directory.unwrap_or(env::current_dir().unwrap().to_str().unwrap().to_string())).to_string();
    let files_dir = files_directory.unwrap_or(env::current_dir().unwrap().to_str().unwrap().to_string());

    let files_dir_path = Path::new(&files_dir);

    if !files_dir_path.is_dir() {
        fs::create_dir(&files_dir)?;
        fs::create_dir(files_dir_path.join("temporary"))?;
        fs::create_dir(files_dir_path.join("downloads"))?;
        fs::create_dir(files_dir_path.join("uploads"))?;
    }

    let application_settings = ApplicationSettings {
        temporary_storage_path: format!("{}/temporary", &files_dir).to_string(),
        download_file_storage_path: format!("{}/downloads", &files_dir).to_string(),
        upload_file_storage_path: format!("{}/uploads", &files_dir).to_string()
    };

    let network_settings = NetworkSettings {
        random_incoming_port: false,
        incoming_port: Some(50132),
        known_nodes: vec![],
        random_outgoing_ports: true,
        outgoing_ports: vec![],
    };

    let node_settings = NodeSettings {
        private_key: None,
        public_key: None
    };

    let settings = Settings {
        settings_path: settings_dir,
        application_settings,
        network_settings,
        node_settings,
    };

    Ok(settings)
}

pub async fn load_settings_file(settings_path: String) -> Result<Settings, Box<dyn std::error::Error>> {
    let mut file = File::open(settings_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    let settings: Settings = serde_json::from_str(&contents)?;

    Ok(settings)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    settings_path: String,
    application_settings: ApplicationSettings,
    network_settings: NetworkSettings,
    node_settings: NodeSettings
}

impl Settings {
    pub fn new(settings_path: String, application_settings: ApplicationSettings, network_settings: NetworkSettings, node_settings: NodeSettings) -> Self {
        Self {
            settings_path,
            application_settings,
            network_settings,
            node_settings
        }
    }

    pub fn get_settings_path(&self) -> &str {
        self.settings_path.as_str()
    }

    pub fn get_application_settings(&self) -> &ApplicationSettings {
        &self.application_settings
    }

    pub fn get_network_settings(&self) -> &NetworkSettings {
        &self.network_settings
    }

    pub fn get_node_settings(&self) -> &NodeSettings {
        &self.node_settings
    }

    pub fn get_application_settings_mut(&mut self) -> &mut ApplicationSettings {
        &mut self.application_settings
    }

    pub fn get_network_settings_mut(&mut self) -> &mut NetworkSettings {
        &mut self.network_settings
    }

    pub fn get_node_settings_mut(&mut self) -> &mut NodeSettings {
        &mut self.node_settings
    }

    pub fn set_settings_path(&mut self, settings_path: String) {
        self.settings_path = settings_path;
    }

    pub fn set_application_settings(&mut self, application_settings: ApplicationSettings) {
        self.application_settings = application_settings;
    }

    pub fn set_network_settings(&mut self, network_settings: NetworkSettings) {
        self.network_settings = network_settings;
    }

    pub fn set_node_settings(&mut self, node_settings: NodeSettings) {
        self.node_settings = node_settings;
    }

    pub async fn save_settings(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(&self)?;
        let mut file = File::create(&self.settings_path).await?;
        file.write_all(json_string.as_bytes()).await?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplicationSettings {
    temporary_storage_path: String,
    download_file_storage_path: String,
    upload_file_storage_path: String
}

impl ApplicationSettings {
    pub fn new(temporary_storage_path: String, download_file_storage_path: String, upload_file_storage_path: String) -> Self {
        Self {
            temporary_storage_path,
            download_file_storage_path,
            upload_file_storage_path
        }
    }

    pub fn set_temporary_storage_path(&mut self, temporary_storage_path: String) {
        self.temporary_storage_path = temporary_storage_path;
    }

    pub fn set_download_file_storage_path(&mut self, download_file_storage_path: String) {
        self.download_file_storage_path = download_file_storage_path;
    }

    pub fn set_upload_file_storage_path(&mut self, upload_file_storage_path: String) {
        self.upload_file_storage_path = upload_file_storage_path;
    }

    pub fn get_temporary_storage_path(&self) -> String {
        self.temporary_storage_path.clone()
    }

    pub fn get_download_file_storage_path(&self) -> String {
        self.download_file_storage_path.clone()
    }

    pub fn get_upload_file_storage_path(&self) -> String {
        self.upload_file_storage_path.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSettings {
    random_incoming_port: bool,
    incoming_port: Option<u16>,
    known_nodes: Vec<Node>,
    random_outgoing_ports: bool,
    outgoing_ports: Vec<u16>
}

impl NetworkSettings {
    pub fn new(incoming_port: Option<u16>, known_nodes: Vec<Node>) -> Self {
        Self {
            random_incoming_port: false,
            incoming_port,
            known_nodes,
            random_outgoing_ports: true,
            outgoing_ports: Vec::new()
        }
    }

    pub fn set_random_incoming_port(&mut self, random_incoming_port: bool) {
        self.random_incoming_port = random_incoming_port;
    }

    pub fn set_incoming_port(&mut self, incoming_port: Option<u16>) {
        self.incoming_port = incoming_port;
    }

    pub fn set_known_nodes(&mut self, known_nodes: Vec<Node>) {
        self.known_nodes = known_nodes;
    }

    pub fn set_random_outgoing_ports(&mut self, random_outgoing_ports: bool) {
        self.random_outgoing_ports = random_outgoing_ports;
    }

    pub fn set_outgoing_ports(&mut self, outgoing_ports: Vec<u16>) {
        self.outgoing_ports = outgoing_ports;
    }

    pub fn get_random_incoming_port(&self) -> bool {
        self.random_incoming_port
    }

    pub fn get_incoming_port(&self) -> u16 {
        self.incoming_port.unwrap_or(0)
    }

    pub fn get_outgoing_ports(&self) -> Vec<u16> {
        self.outgoing_ports.clone()
    }

    pub fn get_random_outgoing_ports(&self) -> bool {
        self.random_outgoing_ports
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSettings {
    private_key: Option<String>,
    public_key: Option<String>
}

impl NodeSettings {
    pub fn new(private_key: Option<String>, public_key: Option<String>) -> Self {
        Self {
            private_key,
            public_key
        }
    }

    pub fn set_private_key(&mut self, private_key: Option<String>) {
        self.private_key = private_key;
    }

    pub fn set_public_key(&mut self, public_key: Option<String>) {
        self.public_key = public_key;
    }

    pub fn get_private_key(&self) -> Option<String> {
        self.private_key.clone()
    }

    pub fn get_public_key(&self) -> Option<String> {
        self.public_key.clone()
    }
}