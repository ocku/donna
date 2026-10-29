use super::*;

#[tokio::test]
async fn delayed_rollover_retry_does_not_restart_answer_ttl() {
    let (transport, anchor, question) = signed_fixture(false);
    let zone = anchor.name.clone();
    let controlled = Controlled::new(transport, false);
    let resolver = Arc::new(resolver(controlled.clone(), anchor.clone()));
    resolver
        .authenticate_zone(&zone, ClassType::IN, super::super::super::unix_time())
        .await
        .unwrap();
    let new = signing_key(0x7777_6666_5555_4444);
    let now = super::super::super::unix_time();
    let reply = {
        let mut state = controlled.state.lock().unwrap();
        let key = ResourceRecord {
            rdata: RData::DNSKEY(new.dnskey().clone()),
            ..anchor
        };
        let keys = vec![state.dnskey.answers[0].clone(), key];
        let signature = signing_key(0xfeed_face_cafe_beef)
            .sign_rrset(&keys, &zone, now.wrapping_sub(60), now.wrapping_add(3600))
            .unwrap();
        let mut sig = state.dnskey.answers[1].clone();
        sig.rdata = RData::RRSIG(signature);
        state.dnskey.answers = keys;
        state.dnskey.answers.push(sig);
        state.answer.answers[0].ttl = 1;
        let signature = new
            .sign_rrset(
                &state.answer.answers[..1],
                &zone,
                now.wrapping_sub(60),
                now.wrapping_add(3600),
            )
            .unwrap();
        state.answer.answers[1].ttl = 1;
        state.answer.answers[1].rdata = RData::RRSIG(signature);
        state.answer.clone()
    };
    controlled.block.store(true, Ordering::SeqCst);
    let task = {
        let resolver = Arc::clone(&resolver);
        let question = question.clone();
        tokio::spawn(async move {
            let mut reply = reply;
            let status = resolver
                .validate_dnssec_response(&question, &mut reply)
                .await;
            (status, reply)
        })
    };
    controlled.entered.notified().await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    controlled.release.notify_one();
    let (status, response) = task.await.unwrap();
    assert_eq!(status.unwrap(), dns::DnssecSecurityStatus::Secure);
    assert!(response.answers.iter().all(|record| record.ttl == 0));
}
