use ratatui::{layout::{Constraint, Direction, Layout}, Frame};

use crate::app::state::TerminalApp;
use crate::ui::{filters, footer, header, jobs};

pub fn draw(frame: &mut Frame, app: &TerminalApp) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(frame.area());

    header::draw(frame, root[0], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(40)])
        .split(root[1]);

    filters::draw(frame, body[0], app);
    jobs::draw(frame, body[1], app);
    footer::draw(frame, root[2], app);
}