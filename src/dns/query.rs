use super::types;
use chrono::{DateTime, Local};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    LastQuery,
    Count,
    Domain,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub domain: String,
    pub src_ip: IpAddr,
    pub query_type: u16,
    pub answer: Option<String>,
    pub timestamp: DateTime<Local>,
}

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub domain: String,
    pub src_ips: Vec<IpAddr>,
    pub query_types: HashSet<u16>,
    pub answers: Vec<String>,
    pub last_query: DateTime<Local>,
    pub count: u64,
}

impl DnsQuery {
    pub fn new(
        domain: String,
        src_ip: IpAddr,
        query_type: u16,
        answer: Option<String>,
        timestamp: DateTime<Local>,
    ) -> Self {
        let mut query_types = HashSet::new();
        query_types.insert(query_type);

        let answers = if let Some(ans) = answer {
            vec![ans]
        } else {
            Vec::new()
        };

        Self {
            domain,
            src_ips: vec![src_ip],
            query_types,
            answers,
            last_query: timestamp,
            count: 1,
        }
    }

    pub fn update(
        &mut self,
        src_ip: IpAddr,
        query_type: u16,
        answer: Option<String>,
        timestamp: DateTime<Local>,
    ) {
        if !self.src_ips.contains(&src_ip) {
            self.src_ips.push(src_ip);
        }
        self.query_types.insert(query_type);
        if let Some(ans) = answer
            && !self.answers.contains(&ans)
        {
            self.answers.push(ans);
        }
        if timestamp > self.last_query {
            self.last_query = timestamp;
        }
        self.count += 1;
    }

    pub fn src_ip_list(&self) -> String {
        const MAX_DISPLAY_IPS: usize = 2;

        if self.src_ips.len() <= MAX_DISPLAY_IPS {
            self.src_ips
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            let displayed: Vec<String> = self
                .src_ips
                .iter()
                .take(MAX_DISPLAY_IPS)
                .map(std::string::ToString::to_string)
                .collect();
            format!(
                "{}, ... (+{})",
                displayed.join(", "),
                self.src_ips.len() - MAX_DISPLAY_IPS
            )
        }
    }

    pub fn answer_list(&self) -> String {
        const MAX_DISPLAY_ANSWERS: usize = 3;

        if self.answers.is_empty() {
            return "-".to_string();
        }

        if self.answers.len() <= MAX_DISPLAY_ANSWERS {
            self.answers.join(", ")
        } else {
            let displayed: Vec<&String> = self.answers.iter().take(MAX_DISPLAY_ANSWERS).collect();
            format!(
                "{}, ... (+{})",
                displayed
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                self.answers.len() - MAX_DISPLAY_ANSWERS
            )
        }
    }

    pub fn query_type_list(&self) -> String {
        let mut type_codes: Vec<u16> = self.query_types.iter().copied().collect();
        type_codes.sort_unstable();

        type_codes
            .iter()
            .map(|t| types::type_name(*t))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

const MAX_QUERIES: usize = 10000;

#[derive(Debug)]
pub struct DnsQueryAggregator {
    queries: HashMap<String, DnsQuery>,
}

impl DnsQueryAggregator {
    pub fn new() -> Self {
        Self {
            queries: HashMap::new(),
        }
    }

    pub fn add_record(&mut self, record: DnsRecord) {
        if let Some(query) = self.queries.get_mut(&record.domain) {
            query.update(
                record.src_ip,
                record.query_type,
                record.answer,
                record.timestamp,
            );
        } else {
            if self.queries.len() >= MAX_QUERIES
                && let Some(oldest_domain) = self.find_oldest_query()
            {
                self.queries.remove(&oldest_domain);
            }

            self.queries.insert(
                record.domain.clone(),
                DnsQuery::new(
                    record.domain,
                    record.src_ip,
                    record.query_type,
                    record.answer,
                    record.timestamp,
                ),
            );
        }
    }

    fn find_oldest_query(&self) -> Option<String> {
        self.queries
            .iter()
            .min_by_key(|(_, q)| q.last_query)
            .map(|(domain, _)| domain.clone())
    }

    pub fn get_queries(&self, sort_by: SortBy, filter: Option<&str>) -> Vec<DnsQuery> {
        let mut queries: Vec<DnsQuery> = self
            .queries
            .values()
            .filter(|q| {
                if let Some(filter_pattern) = filter {
                    q.domain.contains(filter_pattern)
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        match sort_by {
            SortBy::LastQuery => {
                queries.sort_by(|a, b| b.last_query.cmp(&a.last_query));
            }
            SortBy::Count => {
                queries.sort_by(|a, b| b.count.cmp(&a.count));
            }
            SortBy::Domain => {
                queries.sort_by(|a, b| a.domain.cmp(&b.domain));
            }
        }

        queries
    }

    pub fn total_queries(&self) -> usize {
        self.queries.len()
    }

    pub fn total_count(&self) -> u64 {
        self.queries.values().map(|q| q.count).sum()
    }
}
