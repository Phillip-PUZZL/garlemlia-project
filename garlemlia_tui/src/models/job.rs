use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Routing,
    Storing,
    Searching,
    Downloading,
    Complete,
    Failed,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routing => "ROUTING",
            Self::Storing => "STORING",
            Self::Searching => "SEARCH",
            Self::Downloading => "TRANSFER",
            Self::Complete => "DONE",
            Self::Failed => "FAILED",
        }
    }

    pub fn color(self) -> Color {
        match self {
            Self::Routing => Color::LightGreen,
            Self::Storing => Color::Yellow,
            Self::Searching => Color::Cyan,
            Self::Downloading => Color::Magenta,
            Self::Complete => Color::Green,
            Self::Failed => Color::Red,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: u32,
    pub name: String,
    pub state: JobState,
    pub progress: u16,
    pub peers: u16,
    pub rate: String,
    pub hops: u16,
    pub eta: String,
}

impl JobRow {
    pub fn new(
        id: u32,
        name: impl Into<String>,
        state: JobState,
        progress: u16,
        peers: u16,
        rate: impl Into<String>,
        hops: u16,
        eta: impl Into<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            state,
            progress,
            peers,
            rate: rate.into(),
            hops,
            eta: eta.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewJobRow {
    pub name: String,
    pub state: JobState,
    pub progress: u16,
    pub peers: u16,
    pub rate: String,
    pub hops: u16,
    pub eta: String,
}

impl NewJobRow {
    pub fn new(
        name: impl Into<String>,
        state: JobState,
        progress: u16,
        peers: u16,
        rate: impl Into<String>,
        hops: u16,
        eta: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            state,
            progress,
            peers,
            rate: rate.into(),
            hops,
            eta: eta.into(),
        }
    }

    pub fn to(&self, id: u32) -> JobRow {
        JobRow::new(id, self.name.clone(), self.state, self.progress, self.peers, self.rate.clone(), self.hops, self.eta.clone())
    }
}