use garlemlia::structs::settings::{new_settings_file};

#[tokio::main]
async fn main() {
    let mut gamer = new_settings_file(None, None).unwrap();

    gamer.save_settings().await.unwrap();
}