use super::super::tests::record;
use super::*;

#[test]
fn probe_tie_break_and_registration_timers_follow_rfc_sequence() {
    assert_eq!(
        probe_tie_break(&[record(2)], &[record(1)]).unwrap(),
        ProbeTieBreak::Win
    );
    let start = Instant::now();
    let mut registration = MdnsRegistration::new(start, Duration::from_millis(100));
    assert_eq!(registration.poll(start), None);
    assert_eq!(
        registration.poll(start + Duration::from_millis(100)),
        Some(MdnsRegistrationAction::Probe)
    );
    assert_eq!(
        registration.poll(start + Duration::from_millis(350)),
        Some(MdnsRegistrationAction::Probe)
    );
    assert_eq!(
        registration.poll(start + Duration::from_millis(600)),
        Some(MdnsRegistrationAction::Probe)
    );
    assert_eq!(registration.poll(start + Duration::from_millis(600)), None);
    assert_eq!(
        registration.poll(start + Duration::from_millis(850)),
        Some(MdnsRegistrationAction::Announce)
    );
    assert_eq!(
        registration.poll(start + Duration::from_millis(1_850)),
        Some(MdnsRegistrationAction::Announce)
    );
    assert_eq!(registration.state(), MdnsRegistrationState::Established);
    assert_eq!(
        registration.response_conflict(start + Duration::from_secs(2)),
        Some(MdnsRegistrationAction::Probe)
    );
    assert_eq!(registration.state(), MdnsRegistrationState::Probing);
    assert_eq!(
        registration.response_conflict(start + Duration::from_secs(3)),
        Some(MdnsRegistrationAction::Relinquish)
    );
}

#[test]
fn losing_a_simultaneous_probe_waits_one_second_then_retries() {
    let start = Instant::now();
    let mut registration = MdnsRegistration::new(start, Duration::ZERO);
    assert_eq!(
        registration.poll(start),
        Some(MdnsRegistrationAction::Probe)
    );
    assert_eq!(
        registration.conflict(ProbeTieBreak::Lose, start),
        Some(MdnsRegistrationAction::Backoff)
    );
    assert_eq!(registration.state(), MdnsRegistrationState::BackingOff);
    assert_eq!(registration.poll(start + Duration::from_millis(999)), None);
    assert_eq!(
        registration.poll(start + Duration::from_secs(1)),
        Some(MdnsRegistrationAction::Probe)
    );
    assert_eq!(registration.state(), MdnsRegistrationState::Probing);
}

#[test]
fn response_before_first_probe_is_ignored_but_owner_wins_after_probe() {
    let now = Instant::now();
    let mut registration = MdnsRegistration::new(now, Duration::from_millis(100));
    assert_eq!(registration.response_conflict(now), None);
    assert_eq!(registration.state(), MdnsRegistrationState::Probing);
    assert_eq!(
        registration.poll(now + Duration::from_millis(100)),
        Some(MdnsRegistrationAction::Probe)
    );
    assert_eq!(
        registration.response_conflict(now + Duration::from_millis(101)),
        Some(MdnsRegistrationAction::Relinquish)
    );
    assert_eq!(registration.state(), MdnsRegistrationState::Conflicted);
    assert_eq!(registration.poll(now + Duration::from_secs(1)), None);
}

#[test]
fn response_during_post_probe_wait_relinquishes() {
    let now = Instant::now();
    let mut registration = MdnsRegistration::new(now, Duration::ZERO);
    for delay in [0, 250, 500] {
        registration.poll(now + Duration::from_millis(delay));
    }
    assert_eq!(
        registration.response_conflict(now + Duration::from_millis(600)),
        Some(MdnsRegistrationAction::Relinquish)
    );
}

#[test]
fn established_names_defend_queries_without_lexical_tie_breaking() {
    let now = Instant::now();
    let mut registration = MdnsRegistration::new(now, Duration::ZERO);
    for delay in [0, 250, 500, 750, 1750] {
        registration.poll(now + Duration::from_millis(delay));
    }
    for outcome in [ProbeTieBreak::Win, ProbeTieBreak::Lose, ProbeTieBreak::Lose] {
        assert_eq!(
            registration.probe(outcome, now + Duration::from_secs(2)),
            Some(MdnsRegistrationAction::Defend)
        );
        assert_eq!(registration.state(), MdnsRegistrationState::Established);
    }
    assert_eq!(
        registration.probe(ProbeTieBreak::Equal, now + Duration::from_secs(2)),
        None
    );
    assert_eq!(registration.state(), MdnsRegistrationState::Established);
}

#[test]
fn identical_or_winning_proposals_do_not_interrupt_probing() {
    let now = Instant::now();
    let mut registration = MdnsRegistration::new(now, Duration::ZERO);
    registration.poll(now);
    for outcome in [ProbeTieBreak::Equal, ProbeTieBreak::Win] {
        assert_eq!(registration.probe(outcome, now), None);
        assert_eq!(registration.state(), MdnsRegistrationState::Probing);
    }
}

#[test]
fn conflicting_response_while_announcing_restarts_all_three_probes() {
    let now = Instant::now();
    let mut registration = MdnsRegistration::new(now, Duration::ZERO);
    for delay in [0, 250, 500, 750] {
        registration.poll(now + Duration::from_millis(delay));
    }
    assert_eq!(registration.state(), MdnsRegistrationState::Announcing);
    let restart = now + Duration::from_secs(1);
    assert_eq!(
        registration.response_conflict(restart),
        Some(MdnsRegistrationAction::Probe)
    );
    for delay in [250, 500] {
        assert_eq!(
            registration.poll(restart + Duration::from_millis(delay)),
            Some(MdnsRegistrationAction::Probe)
        );
    }
    assert_eq!(
        registration.poll(restart + Duration::from_millis(749)),
        None
    );
    assert_eq!(
        registration.poll(restart + Duration::from_millis(750)),
        Some(MdnsRegistrationAction::Announce)
    );
}
