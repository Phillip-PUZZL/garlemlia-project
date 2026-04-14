use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Row, Table},
};

use crate::app::state::TerminalApp;

pub fn draw(frame: &mut Frame, area: Rect, app: &TerminalApp) {
    let jobs = app.visible_jobs();

    let header = Row::new(vec![
        Cell::from("#"),
        Cell::from("Name"),
        Cell::from("State"),
        Cell::from("Prog"),
        Cell::from("Peers"),
        Cell::from("Rate"),
        Cell::from("Hops"),
        Cell::from("ETA"),
    ])
        .style(Style::default().fg(Color::Yellow).bold());

    let rows: Vec<Row> = jobs
        .iter()
        .enumerate()
        .map(|(index, job)| {
            let is_selected = index == app.selected_job;
            let base_style = if is_selected {
                Style::default().bg(Color::White).fg(Color::Black)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(job.id.to_string()),
                Cell::from(job.name.clone()),
                Cell::from(job.state.as_str()).style(Style::default().fg(job.state.color()).bold()),
                Cell::from(format!("{}%", job.progress)),
                Cell::from(job.peers.to_string()),
                Cell::from(job.rate.clone()),
                Cell::from(job.hops.to_string()),
                Cell::from(job.eta.clone()),
            ])
                .style(base_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Min(28),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Length(8),
        ],
    )
        .header(header)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Gray)))
        .column_spacing(1);

    frame.render_widget(table, area);
}