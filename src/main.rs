use garlemlia::data::garlemlia_data::new_tracker;
use garlemlia::data::settings::new_settings;

#[tokio::main]
async fn main() {
    let gamer = new_settings(None, None).unwrap();
    gamer.save_settings().await.unwrap();

    let tracker = new_tracker(gamer.get_application_settings().get_root_storage_path())
        .await
        .unwrap();
    tracker.save_tracker().await.unwrap();
}
