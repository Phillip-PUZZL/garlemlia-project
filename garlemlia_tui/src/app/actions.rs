use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use super::state::TerminalApp;

pub fn handle_key_event(app: &mut TerminalApp, key: KeyEvent) {
    if key.kind != KeyEventKind::Press {
        return;
    }

    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Up => app.prev_job(),
        KeyCode::Down => app.next_job(),
        KeyCode::Left => app.prev_filter(),
        KeyCode::Right | KeyCode::Tab => app.next_filter(),
        _ => {}
    }
}