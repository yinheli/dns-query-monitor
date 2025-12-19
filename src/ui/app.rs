use crate::dns::{DnsState, SortBy};

pub struct App {
    pub dns_state: DnsState,
    pub sort_by: SortBy,
    pub filter: String,
    pub filter_input: String,
    pub filter_mode: bool,
    pub scroll_state: usize,
}

impl App {
    pub fn new(dns_state: DnsState) -> Self {
        Self {
            dns_state,
            sort_by: SortBy::LastQuery,
            filter: String::new(),
            filter_input: String::new(),
            filter_mode: false,
            scroll_state: 0,
        }
    }

    pub fn toggle_sort(&mut self) {
        self.sort_by = match self.sort_by {
            SortBy::LastQuery => SortBy::Count,
            SortBy::Count => SortBy::Domain,
            SortBy::Domain => SortBy::LastQuery,
        };
        self.scroll_state = 0;
    }

    pub fn enter_filter_mode(&mut self) {
        self.filter_mode = true;
        self.filter_input = self.filter.clone();
    }

    pub fn exit_filter_mode(&mut self) {
        self.filter_mode = false;
        self.filter_input.clear();
    }

    pub fn apply_filter(&mut self) {
        self.filter = self.filter_input.clone();
        self.filter_mode = false;
        self.scroll_state = 0;
    }

    pub fn filter_input_char(&mut self, c: char) {
        self.filter_input.push(c);
    }

    pub fn filter_backspace(&mut self) {
        self.filter_input.pop();
    }

    pub fn scroll_up(&mut self) {
        self.scroll_state = self.scroll_state.saturating_sub(1);
    }

    pub fn scroll_down(&mut self, max: usize) {
        if self.scroll_state < max.saturating_sub(1) {
            self.scroll_state += 1;
        }
    }

    pub fn page_up(&mut self) {
        self.scroll_state = self.scroll_state.saturating_sub(10);
    }

    pub fn page_down(&mut self, max: usize) {
        self.scroll_state = (self.scroll_state + 10).min(max.saturating_sub(1));
    }

    pub fn home(&mut self) {
        self.scroll_state = 0;
    }

    pub fn end(&mut self, max: usize) {
        self.scroll_state = max.saturating_sub(1);
    }
}
