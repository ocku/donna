//! Checked packet access, request correlation, and implicit NS appending.
use super::*;
use crate::{ClassType, FromWire};

impl EncodedReply {
    /// Checks transaction/header correlation and exact question spelling.
    pub fn matches_request(&self, request: &Message) -> bool {
        !request.headers.qr
            && !request.headers.aa
            && !request.headers.ra
            && !request.headers.tc
            && request.headers.rcode == RCode::Ok
            && request.answers.is_empty()
            && request.authorities.is_empty()
            && match (self.request_opt_ttl, request.additionals.as_slice()) {
                (None, []) => true,
                (Some(ttl), [opt]) => {
                    opt.rtype == RecordType::OPT
                        && opt.name == crate::DomainName::root()
                        && matches!(opt.class, ClassType::Unknown(_))
                        && opt.ttl == ttl
                        && matches!(&opt.rdata,RData::OPT(options) if options.is_empty())
                }
                _ => false,
            }
            && request.headers.id == self.id
            && request.headers.opcode == OpCode::Query
            && request.headers.rd == self.rd
            && request.headers.cd == self.cd
            && request.headers.ad == self.request_ad
            && matches!(request.questions.as_slice(), [q] if q.is_wire_canonical()
                && q.qname.as_ref() == self.question.qname.as_ref()
                && q.qtype == self.question.qtype && q.qclass == self.question.qclass)
    }

    /// Returns the immutable checked packet.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Takes ownership of the checked packet.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Decodes a checked packet when a caller needs ordinary response handling.
    ///
    /// # Errors
    /// Returns a wire error if the checked packet cannot be decoded.
    pub fn into_message(self) -> Result<Message> {
        Message::from_wire(&self.bytes)
    }

    /// Appends one checked implicit NS RRSet, leaving the packet unchanged on failure.
    ///
    /// Uncompressed names preserve spelling and cannot invalidate prior offsets.
    /// A reply already carrying NS, invalid/duplicate/mixed records, or a set
    /// exceeding the request ceiling must use ordinary Message handling instead.
    pub fn append_name_servers(&mut self, records: &[ResourceRecord]) -> bool {
        if records.is_empty() {
            return true;
        }
        // Implicit referrals belong only to empty-answer replies. In
        // particular, appending NS to a positive NS answer could split the
        // same RRset across sections, which the ordinary validator rejects.
        if self.has_name_servers
            || read_u16(&self.bytes, 6) != Some(0)
            || records.len() > MAX_RECORDS
        {
            return false;
        }
        let first = &records[0];
        for (index, record) in records.iter().enumerate() {
            if record.rtype != RecordType::NS
                || !matches!(record.rdata, RData::NS(_))
                || record.class.value() != self.question.qclass.value()
                || !self.question.qname.is_descendant_of(&record.name)
                || !record.name.eq_dns(&first.name)
                || record.ttl != first.ttl
                || record.validate_for_forwarding().is_err()
                || records[..index]
                    .iter()
                    .any(|previous| previous.rdata == record.rdata)
            {
                return false;
            }
        }
        let Some(additional_length) = records.iter().try_fold(0_usize, |length, record| {
            let RData::NS(target) = &record.rdata else {
                return None;
            };
            length.checked_add(record.name.wire_len() + 10 + target.wire_len())
        }) else {
            return false;
        };
        if self
            .bytes
            .len()
            .checked_add(additional_length)
            .is_none_or(|length| length > self.maximum)
        {
            return false;
        }
        let Some(count) = read_u16(&self.bytes, 8)
            .and_then(|count| usize::from(count).checked_add(records.len()))
            .and_then(|count| u16::try_from(count).ok())
        else {
            return false;
        };
        // Reuse the selected packet's allocation. Save its final empty OPT,
        // then append through the same checked record writer, permanently
        // without compression. Earlier targets and offsets remain unchanged.
        let opt_length = usize::from(self.request_opt_ttl.is_some()) * EMPTY_OPT_OCTETS;
        let authority_end = self.bytes.len() - opt_length;
        let mut opt = [0; EMPTY_OPT_OCTETS];
        opt[..opt_length].copy_from_slice(&self.bytes[authority_end..]);
        let mut bytes = std::mem::take(&mut self.bytes);
        bytes.truncate(authority_end);
        let mut encoder = Encoder::from_uncompressed_bytes(bytes);
        let success = records
            .iter()
            .all(|record| encode_record(record, &mut encoder).is_ok());
        let mut bytes = encoder.into_bytes();
        if !success {
            bytes.truncate(authority_end);
        }
        bytes.extend_from_slice(&opt[..opt_length]);
        self.bytes = bytes;
        if !success {
            return false;
        }
        debug_assert_eq!(
            self.bytes.len(),
            authority_end + additional_length + opt_length
        );
        self.bytes[8..10].copy_from_slice(&count.to_be_bytes());
        self.has_name_servers = true;
        true
    }
}
