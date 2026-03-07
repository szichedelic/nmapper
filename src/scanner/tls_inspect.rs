use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use native_tls::TlsConnector;

use crate::models::TlsInfo;

/// Inspect the TLS certificate on the given host:port.
pub fn inspect_tls(target: IpAddr, port: u16, verbose: bool) -> Option<TlsInfo> {
    let addr = SocketAddr::new(target, port);
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok();

    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;

    let host = target.to_string();
    let tls_stream = connector.connect(&host, stream).ok()?;

    let cert = tls_stream.peer_certificate().ok()??;
    let der = cert.to_der().ok()?;

    let protocol_version = "TLS".to_string();

    let info = parse_certificate_info(&der, protocol_version);

    if verbose {
        if let Some(ref info) = info {
            eprintln!("  [+] TLS cert: {}", info.subject);
            eprintln!("     Issuer: {}", info.issuer);
            eprintln!("     Valid: {} to {}", info.not_before, info.not_after);
            if !info.sans.is_empty() {
                eprintln!("     SANs: {}", info.sans.join(", "));
            }
        }
    }

    info
}

/// Parse DER-encoded X.509 certificate to extract basic fields.
fn parse_certificate_info(der: &[u8], protocol_version: String) -> Option<TlsInfo> {
    let (_, cert_seq) = parse_asn1_sequence(der, 0)?;
    let (_, tbs) = parse_asn1_sequence(cert_seq, 0)?;

    let mut offset = 0;

    // Optional version field uses explicit tag [0] (0xA0)
    if offset < tbs.len() && (tbs[offset] & 0xE0 == 0xA0) {
        let (new_offset, _) = skip_asn1_element(tbs, offset)?;
        offset = new_offset;
    }

    let (new_offset, _) = skip_asn1_element(tbs, offset)?; // serial number
    offset = new_offset;

    let (new_offset, _) = skip_asn1_element(tbs, offset)?; // signature algorithm
    offset = new_offset;

    let (new_offset, issuer_bytes) = parse_asn1_element(tbs, offset)?;
    let issuer = parse_x509_name(issuer_bytes);
    offset = new_offset;

    let (new_offset, validity_bytes) = parse_asn1_sequence_content(tbs, offset)?;
    let (not_before, not_after) = parse_validity(validity_bytes);
    offset = new_offset;

    let (new_offset, subject_bytes) = parse_asn1_element(tbs, offset)?;
    let subject = parse_x509_name(subject_bytes);
    offset = new_offset;

    let (new_offset, _) = skip_asn1_element(tbs, offset)?; // subject public key info
    offset = new_offset;

    let mut sans = Vec::new();
    // Extensions use explicit tag [3] (0xA3); skip any optional fields between SPKI and extensions
    while offset < tbs.len() {
        if tbs[offset] == 0xA3 {
            let (_, ext_outer) = parse_asn1_element(tbs, offset)?;
            if let Some((_, ext_seq)) = parse_asn1_sequence_content(ext_outer, 0) {
                sans = extract_sans(ext_seq);
            }
            break;
        }
        let (new_offset, _) = skip_asn1_element(tbs, offset)?;
        offset = new_offset;
    }

    Some(TlsInfo {
        subject,
        issuer,
        not_before,
        not_after,
        sans,
        protocol_version,
    })
}

fn parse_asn1_sequence(data: &[u8], offset: usize) -> Option<(usize, &[u8])> {
    if offset >= data.len() || data[offset] != 0x30 {
        return None;
    }
    parse_asn1_element_content(data, offset)
}

fn parse_asn1_sequence_content(data: &[u8], offset: usize) -> Option<(usize, &[u8])> {
    parse_asn1_element_content(data, offset)
}

fn parse_asn1_element(data: &[u8], offset: usize) -> Option<(usize, &[u8])> {
    if offset >= data.len() {
        return None;
    }
    let (end, _content) = parse_asn1_element_content(data, offset)?;
    Some((end, &data[offset..end]))
}

fn parse_asn1_element_content(data: &[u8], offset: usize) -> Option<(usize, &[u8])> {
    if offset >= data.len() {
        return None;
    }
    let mut pos = offset + 1; // skip tag
    if pos >= data.len() {
        return None;
    }

    let length_byte = data[pos];
    pos += 1;

    let length: usize;
    if length_byte & 0x80 == 0 {
        length = length_byte as usize;
    } else {
        let num_bytes = (length_byte & 0x7F) as usize;
        if pos + num_bytes > data.len() || num_bytes > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[pos + i] as usize;
        }
        pos += num_bytes;
        length = len;
    }

    if pos + length > data.len() {
        return None;
    }

    Some((pos + length, &data[pos..pos + length]))
}

fn skip_asn1_element(data: &[u8], offset: usize) -> Option<(usize, ())> {
    let (end, _) = parse_asn1_element_content(data, offset)?;
    Some((end, ()))
}

fn parse_x509_name(data: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut offset = 0;

    // X.509 Name: SEQUENCE of RDN SETs, each SET containing a SEQUENCE of (OID, value)
    if offset < data.len() && data[offset] == 0x30 {
        if let Some((_, seq_content)) = parse_asn1_element_content(data, offset) {
            offset = 0;
            let data = seq_content;
            while offset < data.len() {
                if let Some((new_offset, set_content)) = parse_asn1_element_content(data, offset) {
                    if let Some(rdn) = parse_rdn(set_content) {
                        parts.push(rdn);
                    }
                    offset = new_offset;
                } else {
                    break;
                }
            }
        }
    }

    if parts.is_empty() {
        "(unknown)".to_string()
    } else {
        parts.join(", ")
    }
}

fn parse_rdn(data: &[u8]) -> Option<String> {
    let (_, seq_content) = parse_asn1_element_content(data, 0)?;

    if seq_content.is_empty() || seq_content[0] != 0x06 {
        return None;
    }
    let (value_offset, oid_content) = parse_asn1_element_content(seq_content, 0)?;

    let oid_name = match oid_content {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x0A] => "O",
        [0x55, 0x04, 0x0B] => "OU",
        _ => return None,
    };

    if value_offset >= seq_content.len() {
        return None;
    }
    let (_, value_content) = parse_asn1_element_content(seq_content, value_offset)?;
    let value = String::from_utf8_lossy(value_content);

    Some(format!("{oid_name}={value}"))
}

fn parse_validity(data: &[u8]) -> (String, String) {
    let mut offset = 0;

    let not_before = if offset < data.len() {
        if let Some((new_offset, content)) = parse_asn1_element_content(data, offset) {
            offset = new_offset;
            String::from_utf8_lossy(content).to_string()
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    let not_after = if offset < data.len() {
        if let Some((_, content)) = parse_asn1_element_content(data, offset) {
            String::from_utf8_lossy(content).to_string()
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    (not_before, not_after)
}

fn extract_sans(data: &[u8]) -> Vec<String> {
    let mut sans = Vec::new();
    let mut offset = 0;

    // SAN extension OID: 2.5.29.17 = 55 1D 11
    let san_oid: &[u8] = &[0x55, 0x1D, 0x11];

    while offset < data.len() {
        if let Some((new_offset, ext_content)) = parse_asn1_element_content(data, offset) {
            // Each extension is a SEQUENCE(OID, [critical], value)
            let mut ext_offset = 0;
            if ext_offset < ext_content.len() && ext_content[ext_offset] == 0x06 {
                if let Some((oid_end, oid)) =
                    parse_asn1_element_content(ext_content, ext_offset)
                {
                    if oid == san_oid {
                        // Skip optional critical boolean
                        ext_offset = oid_end;
                        if ext_offset < ext_content.len() && ext_content[ext_offset] == 0x01 {
                            if let Some((skip, _)) =
                                parse_asn1_element_content(ext_content, ext_offset)
                            {
                                ext_offset = skip;
                            }
                        }
                        // Value is an OCTET STRING wrapping a SEQUENCE of GeneralNames
                        if ext_offset < ext_content.len() && ext_content[ext_offset] == 0x04
                        {
                            if let Some((_, octet_content)) =
                                parse_asn1_element_content(ext_content, ext_offset)
                            {
                                if let Some((_, san_seq)) =
                                    parse_asn1_element_content(octet_content, 0)
                                {
                                    let mut san_offset = 0;
                                    while san_offset < san_seq.len() {
                                        let tag = san_seq[san_offset];
                                        if let Some((next, content)) =
                                            parse_asn1_element_content(san_seq, san_offset)
                                        {
                                            // tag 0x82 = dNSName (context-specific [2])
                                            if tag == 0x82 {
                                                sans.push(
                                                    String::from_utf8_lossy(content).to_string(),
                                                );
                                            }
                                            san_offset = next;
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            offset = new_offset;
        } else {
            break;
        }
    }

    sans
}
