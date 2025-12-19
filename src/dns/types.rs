/// DNS Record Types (RFC 1035 Section 3.2.2, RFC 3596)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    /// A record: IPv4 address (32 bits)
    A,
    /// NS record: Authoritative name server
    Ns,
    /// CNAME record: Canonical name for an alias
    Cname,
    /// SOA record: Start of authority
    Soa,
    /// PTR record: Domain name pointer
    Ptr,
    /// MX record: Mail exchange
    Mx,
    /// TXT record: Text strings
    Txt,
    /// AAAA record: IPv6 address (128 bits) - RFC 3596
    Aaaa,
    /// SRV record: Service location - RFC 2782
    Srv,
    /// HTTPS record: HTTPS binding - RFC 9460
    Https,
    /// Unknown or unsupported record type
    Unknown(u16),
}

impl DnsRecordType {
    /// Convert wire format u16 to `DnsRecordType`
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            65 => Self::Https,
            n => Self::Unknown(n),
        }
    }

    /// Get human-readable name for the record type
    pub fn name(self) -> String {
        match self {
            Self::A => "A".to_string(),
            Self::Ns => "NS".to_string(),
            Self::Cname => "CNAME".to_string(),
            Self::Soa => "SOA".to_string(),
            Self::Ptr => "PTR".to_string(),
            Self::Mx => "MX".to_string(),
            Self::Txt => "TXT".to_string(),
            Self::Aaaa => "AAAA".to_string(),
            Self::Srv => "SRV".to_string(),
            Self::Https => "HTTPS".to_string(),
            Self::Unknown(n) => format!("TYPE{n}"),
        }
    }
}

/// Helper function for backwards compatibility
pub fn type_name(qtype: u16) -> String {
    DnsRecordType::from_u16(qtype).name()
}
