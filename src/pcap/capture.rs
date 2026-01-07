use crate::dns::types::DnsRecordType;
use crate::dns::{DnsQueryEvent, MAX_ANSWER_LEN, MAX_DOMAIN_LEN};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use log::{debug, info, warn};
use pcap::{Capture, Device, Error};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const DNS_PORT: u16 = 53;

pub struct CaptureLoader;

impl CaptureLoader {
    pub fn list_interfaces() -> Result<Vec<Device>> {
        Ok(Device::list()?)
    }

    pub fn select_default_interface() -> Result<String> {
        let devices = Device::list()?;

        for device in &devices {
            if device.name == "any" {
                continue;
            }
            if !device.flags.is_loopback() && device.flags.is_up() && device.flags.is_running() {
                return Ok(device.name.clone());
            }
        }

        for device in &devices {
            if device.name != "any" && device.flags.is_up() {
                return Ok(device.name.clone());
            }
        }

        bail!("No suitable network interface found")
    }

    pub fn load(
        interface: &str,
    ) -> Result<(
        JoinHandle<()>,
        mpsc::Receiver<DnsQueryEvent>,
        CancellationToken,
    )> {
        info!("Opening capture on interface: {interface}");

        let mut cap = if interface == "any" {
            Capture::from_device("any")?
                .immediate_mode(true)
                .timeout(100)
                .open()?
        } else {
            let device = Device::list()?
                .into_iter()
                .find(|d| d.name == interface)
                .context(format!("Interface {interface} not found"))?;

            Capture::from_device(device)?
                .immediate_mode(true)
                .timeout(100)
                .open()?
        };

        cap.filter("udp port 53", true)?;

        info!("Capture started on interface: {interface}");

        let (tx, rx) = mpsc::channel(10000);
        let cancel_token = CancellationToken::new();
        let token_clone = cancel_token.clone();

        // Use Arc<AtomicBool> for faster cancellation checking
        let should_stop = Arc::new(AtomicBool::new(false));
        let should_stop_clone = should_stop.clone();

        let handle = tokio::task::spawn_blocking(move || {
            while !should_stop_clone.load(Ordering::Relaxed) {
                // First check if we should stop before trying to read
                if should_stop_clone.load(Ordering::Relaxed) {
                    break;
                }

                match cap.next_packet() {
                    Ok(packet) => {
                        // Check stop flag after getting packet too
                        if should_stop_clone.load(Ordering::Relaxed) {
                            break;
                        }

                        if let Some(event) = parse_dns_packet(packet.data)
                            && tx.blocking_send(event).is_err()
                        {
                            info!("Channel closed, stopping capture");
                            break;
                        }
                    }
                    Err(Error::TimeoutExpired) => {
                        // Timeout is expected, loop back to check stop flag
                        continue;
                    }
                    Err(e) => {
                        warn!("Error reading packet: {e}");
                        // Don't break on packet errors, just continue unless stopped
                        continue;
                    }
                }
            }
            info!("Packet capture task terminated");
        });

        // Set the stop flag when token is cancelled
        let stop_handle = should_stop.clone();
        tokio::spawn(async move {
            token_clone.cancelled().await;
            stop_handle.store(true, Ordering::Relaxed);
        });

        Ok((handle, rx, cancel_token))
    }
}

/// Parse raw packet data to extract DNS response information
///
/// Packet structure (layers):
/// 1. Ethernet Frame (14 bytes)
/// 2. IP Header (20+ bytes for IPv4, 40 bytes for IPv6)
/// 3. UDP Header (8 bytes)
/// 4. DNS Message (variable length)
///
/// References:
/// - RFC 894: Ethernet Frame Format
/// - RFC 791: Internet Protocol (IPv4)
/// - RFC 2460: Internet Protocol Version 6 (IPv6)
/// - RFC 768: User Datagram Protocol (UDP)
/// - RFC 1035: Domain Names - Implementation and Specification (DNS)
fn parse_dns_packet(data: &[u8]) -> Option<DnsQueryEvent> {
    // Ethernet Frame: minimum 14 bytes
    // [0-5]: Destination MAC (6 bytes)
    // [6-11]: Source MAC (6 bytes)
    // [12-13]: EtherType (2 bytes)
    if data.len() < 14 {
        return None;
    }

    // Extract EtherType to determine the next layer protocol
    // 0x0800 = IPv4, 0x86DD = IPv6
    let eth_type = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14; // Skip Ethernet header

    // Parse IP layer (returns: IP version, source IP, dest IP, header length)
    let (ip_version, src_ip, dst_ip, ip_header_len) = match eth_type {
        0x0800 => parse_ipv4(&data[offset..])?, // IPv4
        0x86DD => parse_ipv6(&data[offset..])?, // IPv6
        _ => return None,                       // Ignore non-IP packets
    };

    offset += ip_header_len;

    // UDP Header: 8 bytes
    // [0-1]: Source Port
    // [2-3]: Destination Port
    // [4-5]: Length
    // [6-7]: Checksum
    if data.len() < offset + 8 {
        return None;
    }

    // Extract UDP source port (responses come FROM port 53)
    let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);

    // Filter: only process DNS responses (source port = 53)
    if src_port != DNS_PORT {
        return None;
    }

    offset += 8; // Skip UDP header

    // Parse DNS message
    parse_dns_query(&data[offset..], ip_version, src_ip, dst_ip)
}

/// Parse IPv4 header (RFC 791)
///
/// IPv4 Header Format (minimum 20 bytes):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |Type of Service|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Returns: (IP version, source IP, destination IP, header length)
fn parse_ipv4(data: &[u8]) -> Option<(u8, [u8; 16], [u8; 16], usize)> {
    if data.len() < 20 {
        return None;
    }

    // Byte 9: Protocol field
    // 17 = UDP (we only care about UDP for DNS)
    if data[9] != 17 {
        return None;
    }

    // Byte 0: Version (4 bits) + IHL (4 bits)
    // IHL = Internet Header Length in 32-bit words
    // Multiply by 4 to get bytes
    let ihl = (data[0] & 0x0F) as usize * 4;

    // Extract IP addresses (4 bytes each)
    // Store in 16-byte array for consistency with IPv6
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    src_ip[..4].copy_from_slice(&data[12..16]); // Bytes 12-15: Source IP
    dst_ip[..4].copy_from_slice(&data[16..20]); // Bytes 16-19: Destination IP

    Some((4, src_ip, dst_ip, ihl))
}

/// Parse IPv6 header (RFC 2460)
///
/// IPv6 Header Format (fixed 40 bytes):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version| Traffic Class |           Flow Label                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Payload Length        |  Next Header  |   Hop Limit   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                         Source Address                        +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                      Destination Address                      +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Returns: (IP version, source IP, destination IP, header length)
fn parse_ipv6(data: &[u8]) -> Option<(u8, [u8; 16], [u8; 16], usize)> {
    if data.len() < 40 {
        return None;
    }

    // Byte 6: Next Header field
    // 17 = UDP (we only care about UDP for DNS)
    if data[6] != 17 {
        return None;
    }

    // Extract IP addresses (16 bytes each)
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    src_ip.copy_from_slice(&data[8..24]); // Bytes 8-23: Source IP
    dst_ip.copy_from_slice(&data[24..40]); // Bytes 24-39: Destination IP

    // IPv6 header is always 40 bytes (no variable length like IPv4)
    Some((6, src_ip, dst_ip, 40))
}

/// Parse DNS message (RFC 1035 Section 4.1)
///
/// DNS Message Format:
/// ```text
///     +---------------------+
///     |        Header       |  12 bytes
///     +---------------------+
///     |       Question      |  Variable (question for the name server)
///     +---------------------+
///     |        Answer       |  Variable (RRs answering the question)
///     +---------------------+
///     |      Authority      |  Variable (RRs pointing toward an authority)
///     +---------------------+
///     |      Additional     |  Variable (RRs holding additional information)
///     +---------------------+
/// ```
///
/// DNS Header Format (12 bytes):
/// ```text
///  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |  Number of questions
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |  Number of answers
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |  Number of authority RRs
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |  Number of additional RRs
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// Where:
/// - QR: 0 = Query, 1 = Response
/// - QDCOUNT: Number of entries in the question section
/// - ANCOUNT: Number of resource records in the answer section
fn parse_dns_query(
    data: &[u8],
    ip_version: u8,
    _src_ip: [u8; 16],
    dst_ip: [u8; 16],
) -> Option<DnsQueryEvent> {
    // DNS header is 12 bytes minimum
    if data.len() < 12 {
        return None;
    }

    // Parse DNS header fields
    // Bytes 2-3: Flags
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = (flags & 0x8000) != 0; // QR bit: 1 = response

    // Bytes 4-5: QDCOUNT (number of questions)
    let qd_count = u16::from_be_bytes([data[4], data[5]]);

    // Bytes 6-7: ANCOUNT (number of answers)
    let an_count = u16::from_be_bytes([data[6], data[7]]);

    // Filter: only process responses with at least one question
    if !is_response || qd_count == 0 {
        return None;
    }

    // Parse question section
    let mut offset = 12; // Skip header
    let domain = parse_domain_name(data, &mut offset)?;

    // Question section also contains QTYPE (2 bytes) and QCLASS (2 bytes)
    if offset + 4 > data.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]); // QTYPE
    offset += 4; // Skip QTYPE + QCLASS

    let mut event_domain = [0u8; MAX_DOMAIN_LEN];
    let domain_len = domain.len().min(MAX_DOMAIN_LEN);
    event_domain[..domain_len].copy_from_slice(&domain[..domain_len]);

    let mut event_answer = [0u8; MAX_ANSWER_LEN];

    if an_count > 0
        && let Some(answer) = parse_first_answer(data, offset, qtype)
    {
        let answer_len = answer.len().min(MAX_ANSWER_LEN);
        event_answer[..answer_len].copy_from_slice(&answer[..answer_len]);
        debug!(
            "DNS response: {} (type {}) -> {}",
            String::from_utf8_lossy(&domain),
            qtype,
            String::from_utf8_lossy(&answer)
        );
    }

    Some(DnsQueryEvent {
        client_ip: dst_ip,
        domain: event_domain,
        answer: event_answer,
        query_type: qtype,
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX),
        ip_version,
    })
}

/// Parse DNS domain name with compression support (RFC 1035 Section 4.1.4)
///
/// Domain Name Format:
/// Domain names are represented as a sequence of labels, where each label consists of
/// a length octet followed by that number of octets.
///
/// ```text
/// Example: "www.example.com" is encoded as:
///
///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///  | 3 | w | w | w | 7 | e | x | a | m | p | l | e |
///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///  | 3 | c | o | m | 0 |
///  +--+--+--+--+--+--+--+
///
/// Where:
/// - First byte (3) = length of "www"
/// - Next 3 bytes = "www"
/// - Next byte (7) = length of "example"
/// - Next 7 bytes = "example"
/// - Next byte (3) = length of "com"
/// - Next 3 bytes = "com"
/// - Last byte (0) = terminator
/// ```
///
/// Message Compression (RFC 1035 Section 4.1.4):
/// To reduce packet size, domain names can use pointers to previous occurrences.
///
/// ```text
/// Pointer Format:
///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///  | 1  1|                OFFSET                   |
///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// Where:
/// - First 2 bits = 11 (0xC0) indicates a pointer
/// - Remaining 14 bits = offset from start of DNS message
/// ```
///
/// Example with compression:
/// ```text
/// Query: "www.example.com"
/// Answer: "ftp.example.com"
///
/// Instead of repeating "example.com", use a pointer:
///  +--+--+--+--+--+--+--+--+--+--+
///  | 3 | f | t | p |  0xC0  | 0x04 |  <- Points to offset 4 where "example.com" starts
///  +--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// RFC Compliance:
/// - Maximum label length: 63 octets (RFC 1035 Section 2.3.4)
/// - Maximum domain name length: 253 octets (RFC 1035 Section 2.3.4)
/// - Pointer loop protection: limit to 10 jumps (prevents infinite loops)
///
/// Returns:
/// - `Bytes` containing the domain name with labels separated by dots
fn parse_domain_name(data: &[u8], offset: &mut usize) -> Option<Bytes> {
    let mut domain = Vec::new();
    let mut jumped = false; // Track if we've followed a pointer
    let mut jump_offset = 0; // Save position after pointer to resume
    let max_jumps = 10; // Prevent infinite pointer loops
    let mut jump_count = 0;

    loop {
        if *offset >= data.len() {
            return None;
        }

        // Read length byte
        let len = data[*offset] as usize;

        // Length = 0 means end of domain name
        if len == 0 {
            if !jumped {
                *offset += 1; // Move past terminator only if not jumped
            }
            break;
        }

        // Check if this is a pointer (top 2 bits = 11)
        if (len & 0xC0) == 0xC0 {
            if *offset + 1 >= data.len() {
                return None;
            }

            // Save position after pointer for first jump only
            if !jumped {
                jump_offset = *offset + 2;
                jumped = true;
            }

            // Prevent infinite loops
            jump_count += 1;
            if jump_count > max_jumps {
                return None;
            }

            // Extract pointer offset (14 bits: 6 bits from first byte + 8 bits from second)
            let pointer = ((len & 0x3F) << 8) | (data[*offset + 1] as usize);
            *offset = pointer;
            continue;
        }

        // RFC 1035 Section 2.3.4: labels must be 63 octets or less
        if len > 63 {
            return None;
        }

        *offset += 1;

        // Add dot separator between labels (but not before first label)
        if !domain.is_empty() {
            domain.push(b'.');
        }

        // Validate we have enough data for the label
        if *offset + len > data.len() {
            return None;
        }

        // Copy label bytes
        domain.extend_from_slice(&data[*offset..*offset + len]);
        *offset += len;

        // RFC 1035 Section 2.3.4: domain names limited to 253 octets
        if domain.len() > 253 {
            break;
        }
    }

    // If we followed a pointer, restore offset to position after the pointer
    if jumped {
        *offset = jump_offset;
    }

    // Convert Vec<u8> to Bytes (efficient conversion, reuses allocation)
    Some(Bytes::from(domain))
}

/// Parse DNS answer section to extract the first matching resource record (RFC 1035 Section 4.1.3)
///
/// Resource Record (RR) Format:
/// All RRs have the same top-level format:
///
/// ```text
///                                     1  1  1  1  1  1
///       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     /                                               /
///     /                      NAME                     /
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     CLASS                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TTL                      |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                   RDLENGTH                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
///     /                     RDATA                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// Where:
/// - NAME: domain name (variable length, with compression)
/// - TYPE: 2 bytes - RR type code (A=1, NS=2, CNAME=5, etc.)
/// - CLASS: 2 bytes - RR class code (IN=1 for Internet)
/// - TTL: 4 bytes - time to live in seconds
/// - RDLENGTH: 2 bytes - length of RDATA field
/// - RDATA: variable - resource data (format depends on TYPE)
/// ```
///
/// Common Record Types (RFC 1035 Section 3.2.2):
///
/// ```text
/// TYPE   Value   Meaning
/// ----   -----   -------
/// A        1     IPv4 address (4 bytes)
///               Example: 192.0.2.1 -> 0xC0 0x00 0x02 0x01
///
/// NS       2     Authoritative name server (domain name)
/// CNAME    5     Canonical name (domain name)
/// PTR     12     Domain name pointer (domain name)
/// MX      15     Mail exchange (2-byte preference + domain name)
/// TXT     16     Text strings (arbitrary text)
/// AAAA    28     IPv6 address (16 bytes) - RFC 3596
///               Example: 2001:db8::1
/// ```
///
/// CNAME Chain Handling:
/// This function skips CNAME records when looking for A/AAAA records.
/// For example, if querying for A record of "www.example.com":
/// ```text
/// Answer 1: www.example.com CNAME -> example.com  (skip this)
/// Answer 2: example.com A -> 192.0.2.1            (return this)
/// ```
///
/// RFC Compliance:
/// - Supports TYPE values defined in RFC 1035 and RFC 3596 (AAAA)
/// - Handles message compression in domain names
/// - Maximum 10 answer records scanned (prevents excessive processing)
///
/// Returns:
/// - `Bytes` containing the parsed answer data (IP address, domain name, etc.)
fn parse_first_answer(data: &[u8], mut offset: usize, qtype: u16) -> Option<Bytes> {
    if offset >= data.len() {
        return None;
    }

    // Scan up to 10 answer records to find matching type
    // (protects against malformed packets with excessive answers)
    let max_answers = 10;
    for _ in 0..max_answers {
        if offset >= data.len() {
            return None;
        }

        // Parse NAME field (domain name with possible compression)
        parse_domain_name(data, &mut offset)?;

        // Verify we have enough bytes for the fixed RR fields
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
        if offset + 10 > data.len() {
            return None;
        }

        // Extract TYPE and RDLENGTH
        let rtype_code = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rtype = DnsRecordType::from_u16(rtype_code);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10; // Skip to RDATA

        // Validate RDATA doesn't exceed packet bounds
        if offset + rdlength > data.len() {
            return None;
        }

        let rdata = &data[offset..offset + rdlength];

        // Parse RDATA based on record TYPE
        let result = match rtype {
            // TYPE A: IPv4 address - 4 bytes
            DnsRecordType::A => {
                if rdlength == 4 {
                    let formatted = format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
                    Some(Bytes::from(formatted.into_bytes()))
                } else {
                    None // Invalid A record length
                }
            }

            // TYPE AAAA: IPv6 address - 16 bytes (RFC 3596)
            DnsRecordType::Aaaa => {
                if rdlength == 16 {
                    let formatted = format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        rdata[0],
                        rdata[1],
                        rdata[2],
                        rdata[3],
                        rdata[4],
                        rdata[5],
                        rdata[6],
                        rdata[7],
                        rdata[8],
                        rdata[9],
                        rdata[10],
                        rdata[11],
                        rdata[12],
                        rdata[13],
                        rdata[14],
                        rdata[15]
                    );
                    Some(Bytes::from(formatted.into_bytes()))
                } else {
                    None // Invalid AAAA record length
                }
            }

            // TYPE CNAME or PTR: Domain name
            DnsRecordType::Cname | DnsRecordType::Ptr => {
                let mut name_offset = offset;
                parse_domain_name(data, &mut name_offset)
            }

            // TYPE TXT: Text strings
            // Optimization: zero-copy using Bytes::copy_from_slice
            DnsRecordType::Txt => Some(Bytes::copy_from_slice(rdata)),

            // TYPE MX: Mail exchange (2-byte preference + domain name)
            DnsRecordType::Mx => {
                if rdlength < 3 {
                    // Need at least 2 bytes for preference + 1 for name
                    None
                } else {
                    let mut mx_offset = offset + 2; // Skip 2-byte preference
                    parse_domain_name(data, &mut mx_offset)
                }
            }

            // Other known record type: return generic representation
            DnsRecordType::Ns | DnsRecordType::Soa | DnsRecordType::Srv | DnsRecordType::Https => {
                Some(Bytes::from(rtype.name().into_bytes()))
            }

            // Unknown TYPE: return generic representation
            DnsRecordType::Unknown(_) => Some(Bytes::from(rtype.name().into_bytes())),
        };

        offset += rdlength; // Move to next RR

        let qtype_enum = DnsRecordType::from_u16(qtype);

        // For A/AAAA queries: skip CNAME records, return only matching IP type
        // For other queries: return first matching type
        if matches!(qtype_enum, DnsRecordType::A | DnsRecordType::Aaaa) {
            if rtype == qtype_enum {
                return result; // Found matching A or AAAA record
            }
            // Continue loop to skip CNAME and find actual IP
        } else if rtype == qtype_enum {
            return result; // Found matching record type
        }
    }

    None // No matching answer found in first 10 records
}
