//! Match synthesized CNAMEs to the DNAME RRset that authenticates them.
use dns::{
    ClassType, DomainName, QClassType, QueryType, Question, RData, RecordType, ResourceRecord,
};

use crate::{ResolveError, response::checked_substitution};

pub(super) struct Binding {
    pub(super) dname_owner: DomainName,
    pub(super) cname_owner: DomainName,
    pub(super) class: ClassType,
}

/// Identifies exact derived CNAMEs; the caller must validate every referenced
/// DNAME RRset and apply its authentication deadline to the derived CNAME.
pub(super) fn bindings(answers: &[ResourceRecord]) -> Result<Vec<Binding>, ResolveError> {
    let mut bindings = Vec::new();
    for cname in answers
        .iter()
        .filter(|r| r.rtype == RecordType::CNAME && matches!(r.rdata, RData::CNAME(_)))
    {
        let question = Question {
            qname: cname.name.clone(),
            qtype: QueryType::A,
            qclass: QClassType::Class(cname.class),
        };
        let selected = checked_substitution(answers, &question, &DomainName::root())
            .map_err(|_| ResolveError::DnssecBogus(dns::DnssecValidationError::InvalidRrset))?;
        if let Some((dname, _)) = selected {
            if answers.iter().any(|record| {
                record.class == cname.class
                    && record.name.eq_dns(&cname.name)
                    && match &record.rdata {
                        RData::RRSIG(sig) if record.rtype == RecordType::RRSIG => {
                            sig.type_covered == u16::from(RecordType::CNAME)
                        }
                        RData::SIG(sig) if record.rtype == RecordType::SIG => {
                            sig.type_covered == u16::from(RecordType::CNAME)
                        }
                        _ => false,
                    }
            }) {
                return Err(ResolveError::DnssecBogus(
                    dns::DnssecValidationError::InvalidRrset,
                ));
            }
            bindings.push(Binding {
                dname_owner: dname.name.clone(),
                cname_owner: cname.name.clone(),
                class: cname.class,
            });
        }
    }
    Ok(bindings)
}
