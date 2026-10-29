use super::*;

#[tokio::test]
async fn signature_only_answers_never_set_ad_even_when_cached() {
    for qtype in [QueryType::RRSIG, QueryType::ANY] {
        let (mut transport, anchor, mut question) = signed_fixture(true);
        question.qtype = qtype;
        transport
            .answer
            .answers
            .retain(|record| record.rtype == RecordType::RRSIG);
        let resolver = resolver(transport, anchor);
        for _ in 0..2 {
            let response = resolver.resolve(question.clone()).await.unwrap();
            assert!(!response.answers.is_empty());
            assert!(
                !response.headers.ad,
                "{qtype:?} signature-only answer is unauthenticated"
            );
        }
    }
}

#[tokio::test]
async fn requested_orphan_signatures_never_set_ad_even_when_cached() {
    for qtype in [QueryType::RRSIG, QueryType::ANY] {
        let (mut transport, anchor, mut question) = signed_fixture(false);
        question.qtype = qtype;
        let mut forged = transport.answer.answers[1].clone();
        let RData::RRSIG(signature) = &mut forged.rdata else {
            unreachable!()
        };
        signature.type_covered = u16::from(RecordType::MX);
        transport.answer.answers.push(forged);
        let requests = Arc::clone(&transport.requests);
        let resolver = resolver(transport, anchor);
        for _ in 0..2 {
            let response = resolver.resolve(question.clone()).await.unwrap();
            assert!(!response.answers.is_empty());
            assert!(
                !response.headers.ad,
                "{qtype:?} contains an orphan signature"
            );
        }
        assert_eq!(requests.lock().unwrap().len(), 2, "second answer is cached");
    }
}

#[tokio::test]
async fn orphan_signatures_do_not_bypass_answer_validation() {
    for qtype in [QueryType::RRSIG, QueryType::ANY] {
        let (mut transport, anchor, mut question) = signed_fixture(true);
        question.qtype = qtype;
        let mut orphan = transport.answer.answers[1].clone();
        let RData::RRSIG(signature) = &mut orphan.rdata else {
            unreachable!()
        };
        signature.type_covered = u16::from(RecordType::MX);
        transport.answer.answers.push(orphan);
        assert!(matches!(
            resolver(transport, anchor).resolve(question).await,
            Err(ResolveError::DnssecBogus(_))
        ));
    }
}

#[tokio::test]
async fn negative_rrsig_answers_validate_soa_and_denial_signatures() {
    for covered in [RecordType::SOA, RecordType::NSEC] {
        let (mut transport, anchor, mut question) = negative_fixture();
        question.qtype = QueryType::RRSIG;
        for record in &mut transport.answer.authorities {
            if let RData::RRSIG(signature) = &mut record.rdata
                && signature.type_covered == u16::from(covered)
            {
                signature.signature[0] ^= 1;
            }
        }
        assert!(matches!(
            resolver(transport, anchor).resolve(question).await,
            Err(ResolveError::DnssecBogus(_))
        ));
    }
}

#[tokio::test]
async fn signed_negative_rrsig_answers_are_authenticated_even_when_cached() {
    let (transport, anchor, mut question) = negative_fixture();
    question.qtype = QueryType::RRSIG;
    let resolver = resolver(transport, anchor);
    for _ in 0..2 {
        let response = resolver.resolve(question.clone()).await.unwrap();
        assert_eq!(response.headers.rcode, RCode::NameError);
        assert!(response.headers.ad);
    }
}

#[tokio::test]
async fn signatures_cached_from_secure_any_do_not_authenticate_rrsig_queries() {
    let (transport, anchor, mut question) = signed_fixture(false);
    let requests = Arc::clone(&transport.requests);
    question.qtype = QueryType::ANY;
    let resolver = resolver(transport, anchor);
    assert!(resolver.resolve(question.clone()).await.unwrap().headers.ad);
    question.qtype = QueryType::RRSIG;
    let response = resolver.resolve(question).await.unwrap();
    assert!(!response.answers.is_empty());
    assert!(!response.headers.ad);
    assert_eq!(requests.lock().unwrap().len(), 2, "RRSIG answer is cached");
}
