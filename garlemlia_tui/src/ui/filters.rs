use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState},
};

use crate::app::state::TerminalApp;

pub fn draw(frame: &mut Frame, area: Rect, app: &TerminalApp) {
    let items: Vec<ListItem> = app
        .filters
        .iter()
        .map(|entry| {
            let padding = 14usize.saturating_sub(entry.kind.label().len());
            let line = Line::from(vec![
                Span::styled("• ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!(" {}", entry.kind.label()),
                    Style::default().fg(entry.kind.accent()).bold(),
                ),
                Span::raw(" ".repeat(padding)),
                Span::styled(entry.count.to_string(), Style::default().fg(Color::White)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Filter ")
                .border_style(Style::default().fg(Color::Gray)),
        )
        .highlight_style(Style::default().bg(Color::White).fg(Color::Black).bold())
        .highlight_symbol("");

    let mut state = ListState::default();
    state.select(Some(app.selected_filter));
    frame.render_stateful_widget(list, area, &mut state);
}