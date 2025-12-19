use crate::dns::{DnsQuery, DnsQueryEvent, DnsRecord, SortBy};
use anyhow::Result;
use chrono::{DateTime, Local};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

use super::query::DnsQueryAggregator;

pub struct DnsCollector {
    aggregator: Arc<RwLock<DnsQueryAggregator>>,
    rx: mpsc::Receiver<DnsQueryEvent>,
}

impl DnsCollector {
    pub fn new(rx: mpsc::Receiver<DnsQueryEvent>) -> Self {
        Self {
            aggregator: Arc::new(RwLock::new(DnsQueryAggregator::new())),
            rx,
        }
    }

    pub fn aggregator(&self) -> Arc<RwLock<DnsQueryAggregator>> {
        Arc::clone(&self.aggregator)
    }

    pub async fn run(mut self) -> Result<()> {
        while let Some(event) = self.rx.recv().await {
            let record = Self::parse_event(event);
            let mut agg = match self.aggregator.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            agg.add_record(record);
        }
        Ok(())
    }

    fn parse_event(event: DnsQueryEvent) -> DnsRecord {
        let domain_len = event
            .domain
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(event.domain.len());
        let domain_bytes = &event.domain[..domain_len];
        let domain = String::from_utf8_lossy(domain_bytes).to_string();

        let client_ip = if event.ip_version == 4 {
            IpAddr::from([
                event.client_ip[0],
                event.client_ip[1],
                event.client_ip[2],
                event.client_ip[3],
            ])
        } else {
            IpAddr::from(event.client_ip)
        };

        let answer_len = event
            .answer
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(event.answer.len());
        let answer = if answer_len > 0 {
            let answer_bytes = &event.answer[..answer_len];
            Some(String::from_utf8_lossy(answer_bytes).to_string())
        } else {
            None
        };

        let timestamp_ns = event.timestamp_ns.try_into().unwrap_or(i64::MAX);
        let timestamp = DateTime::from_timestamp_nanos(timestamp_ns);
        let timestamp = DateTime::<Local>::from(timestamp);

        DnsRecord {
            domain,
            src_ip: client_ip,
            query_type: event.query_type,
            answer,
            timestamp,
        }
    }
}

#[derive(Clone)]
pub struct DnsState {
    aggregator: Arc<RwLock<DnsQueryAggregator>>,
}

impl DnsState {
    pub fn new(aggregator: Arc<RwLock<DnsQueryAggregator>>) -> Self {
        Self { aggregator }
    }

    pub fn get_queries(&self, sort_by: SortBy, filter: Option<&str>) -> Vec<DnsQuery> {
        let agg = match self.aggregator.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        agg.get_queries(sort_by, filter)
    }

    pub fn stats(&self) -> (usize, u64) {
        let agg = match self.aggregator.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        (agg.total_queries(), agg.total_count())
    }
}
