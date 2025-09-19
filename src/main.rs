use garlemlia::structs::garlemlia_data::new_tracker;
use garlemlia::structs::settings::{new_settings};

#[tokio::main]
async fn main() {
    let gamer = new_settings(None, None).unwrap();
    gamer.save_settings().await.unwrap();

    let tracker = new_tracker(gamer.get_application_settings().get_root_storage_path()).await.unwrap();
    tracker.save_tracker().await.unwrap();
}