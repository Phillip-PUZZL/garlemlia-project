use garlemlia::data::garlemlia_data::new_tracker;
use garlemlia::data::settings::new_settings;
use garlemlia_tui::{run_terminal_app, TerminalApp};
use garlemlia_tui::models::{JobRow, JobState};
use garlemlia_tui::models::job::NewJobRow;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let gamer = new_settings(None, None).unwrap();
    gamer.save_settings().await.unwrap();

    let tracker = new_tracker(gamer.get_application_settings().get_root_storage_path())
        .await
        .unwrap();
    tracker.save_tracker().await.unwrap();

    let mut app = TerminalApp::new();
    app.set_title("Garlemlia Console");
    app.set_node_label("node@127.0.0.1:4040");
    app.set_jobs(vec![
        JobRow::new(1, "bootstrap routing-table refresh", JobState::Routing, 78, 12, "42 req/s", 5, "8s"),
        JobRow::new(2, "store chunk 2/16 for movie-night.mp4", JobState::Storing, 31, 6, "1.9 MiB/s", 3, "24s"),
        JobRow::new(3, "overlay search: soundtrack", JobState::Searching, 52, 8, "11 hits", 4, "14s"),
        JobRow::new(4, "download metadata for cool-file.txt", JobState::Downloading, 63, 4, "640 KiB/s", 2, "17s"),
        JobRow::new(5, "download chunk 7/32 for archive.tar.zst", JobState::Downloading, 17, 10, "3.2 MiB/s", 6, "1m 42s"),
        JobRow::new(6, "validator agreement propagation", JobState::Routing, 88, 9, "24 msg/s", 5, "4s"),
        JobRow::new(7, "local key material save", JobState::Complete, 100, 0, "-", 0, "-")
    ]);
    app.add_job(
        NewJobRow::new("bootstrap proxies", JobState::Routing, 23, 17, "14 msg/s", 0, "18s")
    );

    run_terminal_app(app)
}
