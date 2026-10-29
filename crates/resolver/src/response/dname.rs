//! Checked DNAME selection before the resolver enables recursive synthesis.
use dns::{DomainName, QClassType, Question, RData, RecordType, ResourceRecord};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DnameError {
    OutsideAuthority,
    Ambiguous,
    Overflow,
    MismatchedCname,
    MalformedCname,
}

/// Returns the matching DNAME and its derived target for a single resolution
/// step. This does not authenticate the record, prove delegation boundaries,
/// or grant permission to cache either record.
pub(crate) fn checked_substitution<'a>(
    answers: &'a [ResourceRecord],
    question: &Question,
    authority: &DomainName,
) -> Result<Option<(&'a ResourceRecord, DomainName)>, DnameError> {
    let QClassType::Class(class) = question.qclass else {
        return Ok(None);
    };
    let mut selected = None;
    for record in answers {
        if record.rtype != RecordType::DNAME {
            continue;
        }
        let RData::DNAME(target) = &record.rdata else {
            continue;
        };
        if record.class != class
            || !question.qname.is_descendant_of(&record.name)
            || question.qname.eq_dns(&record.name)
        {
            continue;
        }
        if !record.name.is_descendant_of(authority) {
            return Err(DnameError::OutsideAuthority);
        }
        let target = question
            .qname
            .dname_substitute(&record.name, target)
            .map_err(|_| DnameError::Overflow)?
            .expect("the record is a strict ancestor");
        if selected.is_some() {
            return Err(DnameError::Ambiguous);
        }
        selected = Some((record, target));
    }
    if let Some((_, target)) = &selected {
        for cname in answers.iter().filter(|record| {
            record.rtype == RecordType::CNAME
                && record.class == class
                && record.name.eq_dns(&question.qname)
        }) {
            let RData::CNAME(value) = &cname.rdata else {
                return Err(DnameError::MalformedCname);
            };
            if !value.eq_dns(target) {
                return Err(DnameError::MismatchedCname);
            }
        }
    }
    Ok(selected)
}

/// Constructs or checks a single derived CNAME without authenticating it.
/// The caller must still establish authority, validate DNSSEC and retain the
/// DNAME proof before using or caching the result.
pub(crate) fn prepare_substitution(
    answers: &mut Vec<ResourceRecord>,
    question: &Question,
    authority: &DomainName,
) -> Result<bool, DnameError> {
    let Some((dname, target)) = checked_substitution(answers, question, authority)? else {
        return Ok(false);
    };
    let class = dname.class;
    let ttl = dname.ttl;
    let mut found = false;
    for record in answers.iter_mut().filter(|record| {
        record.rtype == RecordType::CNAME
            && record.class == class
            && record.name.eq_dns(&question.qname)
    }) {
        record.ttl = record.ttl.min(ttl);
        found = true;
    }
    if !found {
        answers.push(ResourceRecord {
            name: question.qname.clone(),
            rtype: RecordType::CNAME,
            class,
            ttl,
            rdata: RData::CNAME(target),
        });
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{ClassType, QueryType, RData, RecordType};
    fn name(s: &str) -> DomainName {
        DomainName::from_dotted(s).unwrap()
    }
    fn dname(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: name(owner),
            rtype: RecordType::DNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::DNAME(name(target)),
        }
    }
    fn question(s: &str) -> Question {
        Question {
            qname: name(s),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }
    }
    #[test]
    fn checks_substitution_authority_and_cname_binding() {
        let q = question("WwW.Old.Example");
        let record = dname("old.example", "New.Other");
        let actual = checked_substitution(std::slice::from_ref(&record), &q, &name("example"))
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(
            actual.as_ref(),
            &[b"WwW".to_vec(), b"New".to_vec(), b"Other".to_vec()]
        );
        assert_eq!(
            checked_substitution(std::slice::from_ref(&record), &q, &name("old.example"))
                .unwrap()
                .unwrap()
                .1,
            actual
        );
        assert!(matches!(
            checked_substitution(std::slice::from_ref(&record), &q, &name("sub.old.example")),
            Err(DnameError::OutsideAuthority)
        ));
        let wrong = ResourceRecord {
            name: q.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::CNAME(name("wrong.other")),
        };
        assert!(matches!(
            checked_substitution(&[record.clone(), wrong], &q, &name("example")),
            Err(DnameError::MismatchedCname)
        ));
        assert!(matches!(
            checked_substitution(&[record.clone(), record], &q, &name("example")),
            Err(DnameError::Ambiguous)
        ));
    }
    #[test]
    fn exact_owner_and_label_lookalikes_do_not_redirect() {
        let r = dname("old.example", "new.example");
        for q in [question("old.example"), question("notold.example")] {
            assert!(matches!(
                checked_substitution(std::slice::from_ref(&r), &q, &name("example")),
                Ok(None)
            ));
        }
    }

    #[test]
    fn prepares_missing_or_received_cname_without_extending_ttl() {
        let question = question("www.old.example");
        let record = dname("old.example", "new.other");
        let mut answers = vec![record.clone()];
        assert!(prepare_substitution(&mut answers, &question, &name("example")).unwrap());
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[1].ttl, 60);
        assert!(
            matches!(&answers[1].rdata, RData::CNAME(target) if target.eq_dns(&name("www.new.other")))
        );
        for (incoming, expected) in [(0, 0), (20, 20), (90, 60)] {
            answers[1].ttl = incoming;
            assert!(prepare_substitution(&mut answers, &question, &name("example")).unwrap());
            assert_eq!(answers.len(), 2);
            assert_eq!(answers[1].ttl, expected);
        }
        answers[1].rdata = RData::CNAME(name("wrong.other"));
        assert_eq!(
            prepare_substitution(&mut answers, &question, &name("example")),
            Err(DnameError::MismatchedCname)
        );
        assert!(
            matches!(&answers[1].rdata, RData::CNAME(target) if target.eq_dns(&name("wrong.other")))
        );
        answers[1].rdata = RData::A(std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(
            prepare_substitution(&mut answers, &question, &name("example")),
            Err(DnameError::MalformedCname)
        );
    }
}
