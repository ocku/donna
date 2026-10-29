use super::*;

/// A bounded, checked positive or composed CNAME recursive reply.
///
/// Stores one ordinary encoding with either retained or client-filtered DNSSEC
/// data. Rendering permits only request correlation fields and
/// nonincreasing TTLs, including independently admitted component RRsets.
#[derive(Debug)]
pub struct PreparedPositiveReply {
    reply: PreparedReply,
}

impl PreparedPositiveReply {
    /// Prepares a fully validated ordinary positive reply, or declines an
    /// unsupported shape so the caller can use the ordinary response path.
    ///
    /// # Errors
    /// Returns errors from the normal checked message encoder.
    pub fn from_message(message: &Message) -> Result<Option<Self>> {
        Self::from_message_inner(message, false)
    }

    /// Prepares a bounded, fully checked composed CNAME response.
    ///
    /// # Errors
    /// Returns errors from the normal checked message encoder.
    pub fn from_composed_message(message: &Message) -> Result<Option<Self>> {
        Self::from_message_inner(message, true)
    }

    fn from_message_inner(message: &Message, composed: bool) -> Result<Option<Self>> {
        let bytes = message.into_wire()?;
        let [question] = message.questions.as_slice() else {
            return Ok(None);
        };
        if bytes.len() > MAXIMUM
            || !message.headers.qr
            || !message.headers.ra
            || message.headers.aa
            || message.headers.tc
            || message.headers.cd
            || message.headers.opcode != OpCode::Query
            || message.headers.rcode != RCode::Ok
            || message.answers.is_empty()
            || message.answers.len() + message.authorities.len() > MAX_RECORDS
            || !matches!(question.qclass, QClassType::Class(_))
            || message.additionals.len() != 1
        {
            return Ok(None);
        }
        let Some(edns) = message.edns().ok().flatten() else {
            return Ok(None);
        };
        if edns.version != 0 || edns.extended_rcode != 0 || !edns.options.is_empty() {
            return Ok(None);
        }
        if !edns.dnssec_ok
            && message
                .answers
                .iter()
                .chain(&message.authorities)
                .any(|record| {
                    matches!(
                        record.rtype,
                        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                    ) && u16::from(record.rtype) != question.qtype.value()
                })
        {
            return Ok(None);
        }
        let mut direct = false;
        for record in &message.answers {
            if record.class.value() != question.qclass.value()
                || (!composed && !record.name.eq_dns(&question.qname))
            {
                return Ok(None);
            }
            if u16::from(record.rtype) == question.qtype.value() && !record.rtype.is_meta_type() {
                direct = true;
            } else if composed && !record.rtype.is_meta_type() {
                // Complete answer/CNAME coherence was checked by into_wire.
            } else if !matches!(&record.rdata, RData::RRSIG(signature)
                if record.rtype == RecordType::RRSIG
                    && (composed || signature.type_covered == question.qtype.value()))
            {
                return Ok(None);
            }
        }
        if !direct
            || (composed
                && matches!(
                    question.qtype,
                    QueryType::ANY | QueryType::AXFR | QueryType::IXFR
                ))
        {
            return Ok(None);
        }
        for record in &message.authorities {
            if record.class.value() != question.qclass.value()
                || !matches!(
                    &record.rdata,
                    RData::NSEC(_) | RData::NSEC3(_) | RData::RRSIG(_)
                )
            {
                return Ok(None);
            }
        }
        Ok(PreparedReply::from_checked_encoding(message, bytes)?.map(|reply| Self { reply }))
    }

    /// Renders the admitted entry at its current uniform TTL. Expired entries
    /// must be rejected by the caller; unsupported requests and oversized
    /// packets return `None` without modifying the prototype. A prototype with
    /// DO clear also supports classic queries by omitting its final empty OPT;
    /// no record bytes or compression targets change.
    pub fn render(
        &self,
        request: &Message,
        ttl: u32,
        maximum: usize,
        allow_authenticated_data: bool,
    ) -> Option<EncodedReply> {
        let ttls = [ttl; MAX_RECORDS];
        self.reply.render(
            request,
            &ttls[..self.reply.ttls.len()],
            maximum,
            allow_authenticated_data,
        )
    }
}

impl PreparedPositiveReply {
    /// Renders per-record TTLs in checked answer then authority order.
    /// Values must be nonincreasing and preserve complete RRset TTL equality.
    pub fn render_record_ttls(
        &self,
        request: &Message,
        ttls: &[u32],
        maximum: usize,
        allow_authenticated_data: bool,
    ) -> Option<EncodedReply> {
        self.reply
            .render(request, ttls, maximum, allow_authenticated_data)
    }
}
