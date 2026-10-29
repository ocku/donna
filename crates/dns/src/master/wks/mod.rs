mod services;

use super::MasterError;
use super::rdata::parse_bytes_number;
use services::{WKS_PROTOCOLS, WKS_SERVICES, WKS_TCP, WKS_UDP};

pub(super) fn wks_protocol(value: &[u8]) -> Result<u8, MasterError> {
    let text =
        std::str::from_utf8(value).map_err(|_| MasterError::new("WKS protocol is not text"))?;
    if let Some((_, protocol)) = WKS_PROTOCOLS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(text))
    {
        return Ok(*protocol);
    }
    u8::try_from(parse_bytes_number(value, "WKS protocol")?)
        .map_err(|_| MasterError::new("WKS protocol exceeds 255"))
}

pub(super) fn wks_service(value: &[u8], protocol: u8) -> Result<u16, MasterError> {
    let text =
        std::str::from_utf8(value).map_err(|_| MasterError::new("WKS service is not text"))?;
    if let Ok(port) = text.parse::<u16>() {
        return Ok(port);
    }
    let protocol_mask = match protocol {
        6 => WKS_TCP,
        17 => WKS_UDP,
        _ => 0,
    };
    WKS_SERVICES
        .iter()
        .find(|(name, _, protocols)| {
            protocols & protocol_mask != 0 && name.eq_ignore_ascii_case(text)
        })
        .map(|(_, port, _)| *port)
        .ok_or_else(|| {
            MasterError::new(format!(
                "unknown WKS service {text} for protocol {protocol}"
            ))
        })
}

pub(super) fn wks_bitmap(ports: &[u16]) -> Vec<u8> {
    let Some(&highest_port) = ports.iter().max() else {
        return Vec::new();
    };
    let mut bitmap = vec![0; usize::from(highest_port) / 8 + 1];
    for &port in ports {
        bitmap[usize::from(port) / 8] |= 0x80 >> (port % 8);
    }
    bitmap
}
