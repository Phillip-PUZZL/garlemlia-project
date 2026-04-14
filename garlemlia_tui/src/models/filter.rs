use ratatui::style::Color;

use super::job::{JobRow, JobState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    All,
    Routing,
    Store,
    Search,
    Transfer,
    Complete,
    Failed,
    Local,
}

impl FilterKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Routing => "Routing",
            Self::Store => "Store",
            Self::Search => "Search",
            Self::Transfer => "Transfer",
            Self::Complete => "Complete",
            Self::Failed => "Failed",
            Self::Local => "Local",
        }
    }

    pub fn accent(self) -> Color {
        match self {
            Self::All => Color::White,
            Self::Routing => Color::LightGreen,
            Self::Store => Color::Yellow,
            Self::Search => Color::Cyan,
            Self::Transfer => Color::Magenta,
            Self::Complete => Color::Green,
            Self::Failed => Color::Red,
            Self::Local => Color::Blue,
        }
    }

    pub fn matches(self, job: &JobRow) -> bool {
        match self {
            Self::All => true,
            Self::Routing => job.state == JobState::Routing,
            Self::Store => job.state == JobState::Storing,
            Self::Search => job.state == JobState::Searching,
            Self::Transfer => job.state == JobState::Downloading,
            Self::Complete => job.state == JobState::Complete,
            Self::Failed => job.state == JobState::Failed,
            Self::Local => job.name.contains("local"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilterEntry {
    pub kind: FilterKind,
    pub count: usize,
}

impl FilterEntry {
    pub fn new(kind: FilterKind, count: usize) -> Self {
        Self { kind, count }
    }
}