use ratatui::{prelude::*, widgets::Paragraph};

use crate::app::state::TerminalApp;

pub fn draw(frame: &mut Frame, area: Rect, app: &TerminalApp) {
    let visible = app.visible_jobs().len();
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(format!(" Jobs: {} ", app.jobs.len()), Style::default().fg(Color::Yellow).bold()),
        Span::styled(format!(" Visible: {} ", visible), Style::default().fg(Color::Cyan).bold()),
        //Span::styled(format!(" Tick: {} ", app.tick), Style::default().fg(Color::Green).bold()),
        Span::styled(" Proxies: 0 ", Style::default().fg(Color::Green).bold()),
        Span::styled(" Proxy For: 0 ", Style::default().fg(Color::Green).bold()),
        Span::raw(" "),
        Span::styled("Press ", Style::default().fg(Color::White)),
        Span::styled("[q]", Style::default().fg(Color::Yellow).bold()),
        Span::styled(" to quit · ", Style::default().fg(Color::White)),
        Span::styled("[h]", Style::default().fg(Color::Yellow).bold()),
        Span::styled(" for help · arrows/tab to navigate", Style::default().fg(Color::White)),
    ]))
        .style(Style::default().bg(Color::Blue));

    frame.render_widget(footer, area);
}