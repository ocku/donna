use anyhow::Result;
use base64ct::{Base64, Encoding};
use dns::{DomainName, Message, RData, ResourceRecord};
use serde_json::{Value, json};
use std::{io::Write, time::Duration};

#[derive(Clone, Copy)]
pub enum Format {
    Text,
    Json,
    Short,
}

pub fn name(name: &DomainName) -> String {
    if name.as_ref().is_empty() {
        return ".".into();
    }
    let mut text = String::new();
    for label in name.as_ref() {
        for byte in label {
            match *byte {
                b'.' | b'\\' | b'(' | b')' | b';' | b'"' | b'@' | b'$' => {
                    text.push('\\');
                    text.push(*byte as char);
                }
                33..=126 => text.push(*byte as char),
                _ => text.push_str(&format!("\\{byte:03}")),
            }
        }
        text.push('.');
    }
    text
}

fn quoted(bytes: &[u8]) -> String {
    let mut s = String::from("\"");
    for byte in bytes {
        match *byte {
            b'"' | b'\\' => {
                s.push('\\');
                s.push(*byte as char);
            }
            32..=126 => s.push(*byte as char),
            _ => s.push_str(&format!("\\{byte:03}")),
        }
    }
    s.push('"');
    s
}

fn rrtype(record: &ResourceRecord) -> String {
    match record.rtype {
        dns::RecordType::Unknown(n) => format!("TYPE{n}"),
        t => format!("{t:?}"),
    }
}

fn class(record: &ResourceRecord) -> String {
    match record.class {
        dns::ClassType::Unknown(n) => format!("CLASS{n}"),
        c => format!("{c:?}"),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn data(record: &ResourceRecord) -> String {
    match &record.rdata {
        RData::A(ip) => ip.to_string(),
        RData::AAAA(ip) => ip.to_string(),
        RData::NS(n)
        | RData::CNAME(n)
        | RData::PTR(n)
        | RData::DNAME(n)
        | RData::MD(n)
        | RData::MF(n)
        | RData::MB(n)
        | RData::MG(n)
        | RData::MR(n) => name(n),
        RData::MX {
            preference,
            exchange,
        } => format!("{preference} {}", name(exchange)),
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {}", name(target)),
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!(
            "{} {} {serial} {refresh} {retry} {expire} {minimum}",
            name(mname),
            name(rname)
        ),
        RData::TXT(parts) => parts
            .iter()
            .map(|p| quoted(p))
            .collect::<Vec<_>>()
            .join(" "),
        RData::HINFO { cpu, os } => format!("{} {}", quoted(cpu), quoted(os)),
        RData::MINFO { rmailbx, emailbx } => format!("{} {}", name(rmailbx), name(emailbx)),
        RData::CAA(c) => format!(
            "{} {} {}",
            c.flags,
            String::from_utf8_lossy(&c.tag),
            quoted(&c.value)
        ),
        RData::DS(ds) => format!(
            "{} {} {} {}",
            ds.key_tag,
            ds.algorithm,
            ds.digest_type,
            hex(&ds.digest)
        ),
        RData::Unknown(bytes) | RData::NULL(bytes) => format!("\\# {} {}", bytes.len(), hex(bytes)),
        RData::DNSKEY(key) => format!(
            "{} {} {} {}",
            key.flags,
            key.protocol,
            key.algorithm,
            Base64::encode_string(&key.public_key)
        ),
        RData::KEY(key) => format!(
            "{} {} {} {}",
            key.flags,
            key.protocol,
            key.algorithm,
            Base64::encode_string(&key.public_key)
        ),
        RData::RRSIG(sig) => format!(
            "{} {} {} {} {} {} {} {} {}",
            dns::QueryType::from(sig.type_covered),
            sig.algorithm,
            sig.labels,
            sig.original_ttl,
            sig.signature_expiration,
            sig.signature_inception,
            sig.key_tag,
            name(&sig.signer_name),
            Base64::encode_string(&sig.signature)
        ),
        RData::SIG(sig) => format!(
            "{} {} {} {} {} {} {} {} {}",
            dns::QueryType::from(sig.type_covered),
            sig.algorithm,
            sig.labels,
            sig.original_ttl,
            sig.signature_expiration,
            sig.signature_inception,
            sig.key_tag,
            name(&sig.signer_name),
            Base64::encode_string(&sig.signature)
        ),
        RData::NSEC(nsec) => format!(
            "{} {}",
            name(&nsec.next_domain_name),
            bitmap(&nsec.type_bitmap)
        ),
        RData::NSEC3(nsec) => format!(
            "{} {} {} {} {}{}",
            nsec.hash_algorithm,
            nsec.flags,
            nsec.iterations,
            salt(&nsec.salt),
            data_encoding::BASE32HEX_NOPAD.encode(&nsec.next_hashed_owner_name),
            nsec.type_bitmap
                .as_ref()
                .map(|b| format!(" {}", bitmap(b)))
                .unwrap_or_default()
        ),
        RData::NSEC3PARAM(nsec) => format!(
            "{} {} {} {}",
            nsec.hash_algorithm,
            nsec.flags,
            nsec.iterations,
            salt(&nsec.salt)
        ),
        RData::TLSA(cert) | RData::SMIMEA(cert) => format!(
            "{} {} {} {}",
            cert.certificate_usage,
            cert.selector,
            cert.matching_type,
            hex(&cert.association_data)
        ),
        RData::CSYNC(csync) => format!(
            "{} {} {}",
            csync.soa_serial,
            csync.flags,
            bitmap(&csync.type_bitmap)
        ),
        RData::WKS {
            address,
            protocol,
            bitmap,
        } => {
            let services = bitmap
                .iter()
                .enumerate()
                .flat_map(|(index, byte)| {
                    (0..u8::BITS)
                        .filter(move |bit| byte & (0x80 >> bit) != 0)
                        .map(move |bit| (index * u8::BITS as usize + bit as usize).to_string())
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!("{address} {protocol} {services}")
        }
        RData::OPT(options) => options
            .iter()
            .map(|o| format!("option{}={}", o.code, hex(&o.data)))
            .collect::<Vec<_>>()
            .join(" "),
        RData::TSIG(sig) => format!(
            "{} {} {} {} {} {} {} {} {}",
            name(&sig.algorithm),
            sig.time_signed,
            sig.fudge,
            sig.mac.len(),
            Base64::encode_string(&sig.mac),
            sig.original_id,
            sig.error.value(),
            sig.other_data.len(),
            hex(&sig.other_data)
        ),
    }
}

fn bitmap(bitmap: &dns::TypeBitmap) -> String {
    bitmap
        .codes()
        .iter()
        .map(|code| dns::QueryType::from(*code).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn salt(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "-".into()
    } else {
        hex(bytes)
    }
}

pub fn record_json(record: &ResourceRecord) -> Value {
    json!({"name":name(&record.name), "ttl":record.ttl, "class":class(record), "type":rrtype(record), "type_code":u16::from(record.rtype), "data":data(record)})
}

pub fn status(message: &Message) -> String {
    let code = message.extended_rcode();
    if code == u16::from(u8::from(message.headers.rcode)) {
        format!("{:?}", message.headers.rcode)
    } else {
        format!("RCODE{code}")
    }
}

pub fn print(message: &Message, server: &str, elapsed: Duration, format: Format) -> Result<()> {
    let mut out = std::io::stdout().lock();
    if matches!(format, Format::Json) {
        let h = &message.headers;
        let questions: Vec<_> = message
            .questions
            .iter()
            .map(|question| {
                json!({
                    "name": name(&question.qname),
                    "type": question.qtype.to_string(),
                    "class_code": question.qclass.value(),
                })
            })
            .collect();
        let value = json!({
            "server": server,
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
            "id": h.id,
            "status": status(message),
            "rcode": message.extended_rcode(),
            "flags": {
                "aa": h.aa,
                "tc": h.tc,
                "rd": h.rd,
                "ra": h.ra,
                "ad": h.ad,
                "cd": h.cd,
            },
            "questions": questions,
            "answers": message.answers.iter().map(record_json).collect::<Vec<_>>(),
            "authorities": message.authorities.iter().map(record_json).collect::<Vec<_>>(),
            "additionals": message.additionals.iter().map(record_json).collect::<Vec<_>>(),
        });
        writeln!(out, "{value}")?;
    } else if matches!(format, Format::Short) {
        for record in &message.answers {
            writeln!(out, "{}", data(record))?;
        }
    } else {
        writeln!(
            out,
            ";; status: {} ({}), id: {}; server: {server}; {:.3} ms",
            status(message),
            message.extended_rcode(),
            message.headers.id,
            elapsed.as_secs_f64() * 1000.0
        )?;
        let h = &message.headers;
        let flags = [
            ("aa", h.aa),
            ("tc", h.tc),
            ("rd", h.rd),
            ("ra", h.ra),
            ("ad", h.ad),
            ("cd", h.cd),
        ]
        .into_iter()
        .filter_map(|(n, v)| v.then_some(n))
        .collect::<Vec<_>>()
        .join(" ");
        writeln!(
            out,
            ";; flags: {flags}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
            message.questions.len(),
            message.answers.len(),
            message.authorities.len(),
            message.additionals.len()
        )?;
        for q in &message.questions {
            writeln!(out, "; {}\t{}\t{}", name(&q.qname), q.qclass, q.qtype)?;
        }
        for (title, records) in [
            ("ANSWER", &message.answers),
            ("AUTHORITY", &message.authorities),
            ("ADDITIONAL", &message.additionals),
        ] {
            if !records.is_empty() {
                writeln!(out, "\n;; {title}")?;
            }
            for r in records {
                writeln!(
                    out,
                    "{}\t{}\t{}\t{}\t{}",
                    name(&r.name),
                    r.ttl,
                    class(r),
                    rrtype(r),
                    data(r)
                )?;
            }
        }
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_escapes_binary_names_and_text() {
        let n = DomainName::from_labels(vec![b"a.b".to_vec(), vec![0, 255]]).unwrap();
        assert_eq!(name(&n), "a\\.b.\\000\\255.");
        assert_eq!(quoted(b"x\"\n"), "\"x\\\"\\010\"");
    }
}
