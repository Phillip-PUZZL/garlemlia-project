use ratatui::{prelude::*, widgets::Paragraph};

use crate::app::state::TerminalApp;

pub fn draw(frame: &mut Frame, area: Rect, app: &TerminalApp) {
    let text = Line::from(vec![
        Span::styled(format!(" {} ", app.title), Style::default().fg(Color::Yellow).bold()),
        Span::styled("- ", Style::default().fg(Color::LightBlue)),
        Span::styled(format!("{} ", app.node_label), Style::default().fg(Color::Green)),
        Span::styled("- testing frontend", Style::default().fg(Color::LightBlue)),
    ]);

    let header = Paragraph::new(text).style(Style::default().bg(Color::Blue));
    frame.render_widget(header, area);
}