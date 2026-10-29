use crate::{Edns, Headers, Message, RCode, RecordType};

impl Message {
    /// Constructs a data-free error reply correlated with this request.
    ///
    /// Copies the request ID, opcode, RD/CD bits, and canonical questions.
    /// The caller selects the RCODE and recursion-availability policy.
    /// An OPT anywhere in the request produces one minimal response OPT,
    /// including when the request has malformed or duplicate OPT records
    /// (RFC 6891 section 6.1.1). Only an unambiguous request's DO bit is copied;
    /// request options, future flags, and version are not echoed.
    ///
    /// This does not validate the request or authenticate transaction signatures.
    #[must_use]
    pub fn error_response(&self, rcode: RCode, recursion_available: bool) -> Self {
        let edns = self.edns().ok().flatten();
        let has_opt = self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
            .any(|record| record.rtype == RecordType::OPT);

        Self {
            headers: Headers {
                id: self.headers.id,
                qr: true,
                opcode: self.headers.opcode,
                rd: self.headers.rd,
                cd: self.headers.cd,
                ra: recursion_available,
                rcode,
                ..Headers::default()
            },
            questions: self
                .questions
                .iter()
                .filter(|question| question.is_wire_canonical())
                .cloned()
                .collect(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: has_opt
                .then(|| {
                    Edns {
                        dnssec_ok: edns.is_some_and(|value| value.dnssec_ok),
                        ..Edns::default()
                    }
                    .into_record()
                })
                .into_iter()
                .collect(),
        }
    }

    /// Returns a protocol error for malformed or unsupported request EDNS.
    ///
    /// Malformed OPT structure or option contents produce FORMERR. Otherwise,
    /// an unsupported version produces BADVERS with the supported version and
    /// the request's DO bit; a request's nonzero extended RCODE produces FORMERR.
    /// These replies contain one minimal OPT (RFC 6891 sections 6.1.1–6.1.3).
    ///
    /// Other header, question, authentication, and access policies are left to
    /// the caller. Returns `None` when EDNS is absent or valid.
    #[must_use]
    pub fn edns_error_response(&self, recursion_available: bool) -> Option<Self> {
        let edns = match self.edns() {
            Ok(Some(value)) => value,
            Ok(None) => return None,
            Err(_) => return Some(self.error_response(RCode::FormatError, recursion_available)),
        };

        if edns.validate_options().is_err() {
            return Some(self.error_response(RCode::FormatError, recursion_available));
        }
        if edns.version != Edns::VERSION {
            let mut response = self.error_response(RCode::Ok, recursion_available);
            response.additionals = vec![
                Edns {
                    // BADVERS is extended RCODE 16: upper bits 1, header bits 0.
                    extended_rcode: 1,
                    dnssec_ok: edns.dnssec_ok,
                    ..Edns::default()
                }
                .into_record(),
            ];
            return Some(response);
        }
        (edns.extended_rcode != 0)
            .then(|| self.error_response(RCode::FormatError, recursion_available))
    }
}
