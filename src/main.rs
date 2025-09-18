use garlemlia::structs::settings::{load_settings_file};

#[tokio::main]
async fn main() {
    let mut gamer = load_settings_file("./settings.config".to_string()).await.unwrap();

    gamer.get_network_settings_mut().set_incoming_port(Some(50133));

    println!("{:?}", gamer.get_network_settings().get_incoming_port());

    gamer.save_settings().await.unwrap();
}