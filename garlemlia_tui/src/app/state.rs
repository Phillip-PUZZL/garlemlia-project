use crate::models::{FilterEntry, FilterKind, JobRow, JobState};
use crate::models::job::NewJobRow;

#[derive(Debug)]
pub struct TerminalApp {
    pub filters: Vec<FilterEntry>,
    pub jobs: Vec<JobRow>,
    pub selected_filter: usize,
    pub selected_job: usize,
    pub should_quit: bool,
    pub tick: u64,
    pub node_label: String,
    pub title: String,
}

impl TerminalApp {
    pub fn new() -> Self {
        let mut app = Self {
            filters: vec![
                FilterEntry::new(FilterKind::All, 0),
                FilterEntry::new(FilterKind::Routing, 0),
                FilterEntry::new(FilterKind::Store, 0),
                FilterEntry::new(FilterKind::Search, 0),
                FilterEntry::new(FilterKind::Transfer, 0),
                FilterEntry::new(FilterKind::Complete, 0),
                FilterEntry::new(FilterKind::Failed, 0),
                FilterEntry::new(FilterKind::Local, 0),
            ],
            jobs: vec![],
            selected_filter: 0,
            selected_job: 0,
            should_quit: false,
            tick: 0,
            node_label: "".into(),
            title: "".into(),
        };

        app.refresh_counts();
        app
    }

    pub fn visible_jobs(&self) -> Vec<&JobRow> {
        let filter = self.filters[self.selected_filter].kind;
        self.jobs.iter().filter(|job| filter.matches(job)).collect()
    }

    pub fn next_filter(&mut self) {
        self.selected_filter = (self.selected_filter + 1) % self.filters.len();
        self.selected_job = 0;
    }

    pub fn prev_filter(&mut self) {
        if self.selected_filter == 0 {
            self.selected_filter = self.filters.len() - 1;
        } else {
            self.selected_filter -= 1;
        }
        self.selected_job = 0;
    }

    pub fn next_job(&mut self) {
        let len = self.visible_jobs().len();
        if len > 0 {
            self.selected_job = (self.selected_job + 1) % len;
        }
    }

    pub fn prev_job(&mut self) {
        let len = self.visible_jobs().len();
        if len == 0 {
            return;
        }

        if self.selected_job == 0 {
            self.selected_job = len - 1;
        } else {
            self.selected_job -= 1;
        }
    }

    pub fn on_tick(&mut self) {
        self.tick += 1;

        for job in &mut self.jobs {
            match job.state {
                JobState::Routing | JobState::Storing | JobState::Searching | JobState::Downloading => {
                    if job.progress < 100 {
                        job.progress = (job.progress + 1).min(100);
                    } else {
                        job.state = JobState::Complete;
                        job.rate = "-".into();
                        job.eta = "-".into();
                    }
                }
                JobState::Complete | JobState::Failed => {}
            }
        }

        self.refresh_counts();
        self.clamp_selected_job();
    }

    pub fn refresh_counts(&mut self) {
        for filter in &mut self.filters {
            filter.count = self.jobs.iter().filter(|job| filter.kind.matches(job)).count();
        }
    }

    pub fn set_jobs(&mut self, jobs: Vec<JobRow>) {
        self.jobs = jobs;
        self.refresh_counts();
        self.clamp_selected_job();
    }

    pub fn add_job(&mut self, job: NewJobRow) {
        self.jobs.push(job.to(self.get_jobs().len() as u32 + 1));
        self.refresh_counts();
        self.clamp_selected_job();
    }

    pub fn get_jobs(&self) -> Vec<&JobRow> {
        self.jobs.iter().collect()
    }

    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    pub fn set_node_label(&mut self, node_label: impl Into<String>) {
        self.node_label = node_label.into();
    }

    fn clamp_selected_job(&mut self) {
        let visible_len = self.visible_jobs().len();
        if visible_len == 0 {
            self.selected_job = 0;
        } else if self.selected_job >= visible_len {
            self.selected_job = visible_len - 1;
        }
    }
}