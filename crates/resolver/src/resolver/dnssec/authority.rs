//! Project authenticated negative replies to authority RRsets actually verified.
use dns::{AuthenticatedDenial, ClassType, DomainName, Message, RData, RecordType, ResourceRecord};
#[derive(Clone, Eq, PartialEq)]
pub(super) struct AuthorityKey(
    pub(super) DomainName,
    pub(super) RecordType,
    pub(super) ClassType,
);
impl AuthorityKey {
    pub(super) fn retains(&self, record: &ResourceRecord) -> bool {
        let rtype = match &record.rdata {
            RData::RRSIG(sig) if record.rtype == RecordType::RRSIG => sig.type_covered,
            _ => u16::from(record.rtype),
        };
        self.0.eq_dns(&record.name) && u16::from(self.1) == rtype && self.2 == record.class
    }
}

pub(super) fn retain_denial_keys(
    keys: &mut Vec<AuthorityKey>,
    response: &Message,
    proof: &AuthenticatedDenial,
) {
    let rtype = if response
        .authorities
        .iter()
        .any(|r| r.rtype == RecordType::NSEC3)
    {
        RecordType::NSEC3
    } else {
        RecordType::NSEC
    };
    let records: Vec<_> = response
        .authorities
        .iter()
        .filter(|r| r.rtype == rtype)
        .collect();
    for index in proof.proof_record_indices() {
        if let Some(record) = records.get(*index) {
            let key = AuthorityKey(record.name.clone(), record.rtype, record.class);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
}
