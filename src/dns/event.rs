pub const MAX_DOMAIN_LEN: usize = 64;
pub const MAX_ANSWER_LEN: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct DnsQueryEvent {
    pub client_ip: [u8; 16],
    pub domain: [u8; MAX_DOMAIN_LEN],
    pub answer: [u8; MAX_ANSWER_LEN],
    pub query_type: u16,
    pub timestamp_ns: u64,
    pub ip_version: u8,
}
