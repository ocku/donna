use super::*;
use std::sync::{Arc, mpsc};

#[test]
fn insertion_expiring_while_lock_is_held_cannot_replace_live_entry() {
    let cache = Arc::new(PositiveCache::new(1));
    let request = question(1);
    let mut live = request.clone();
    live.headers.qr = true;
    live.headers.aa = true;
    live.answers.push(ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    });
    assert!(cache.insert(&request, &live, Duration::from_secs(60)));
    let mut stale = live.clone();
    stale.answers[0].rdata = RData::A(Ipv4Addr::new(192, 0, 2, 2));
    let observed_at = Instant::now();
    let deadline = observed_at + Duration::from_secs(1);
    let guard = cache.entries.lock().unwrap();
    let (started, ready) = mpsc::channel();
    let task = {
        let cache = Arc::clone(&cache);
        let request = request.clone();
        std::thread::spawn(move || {
            started.send(()).unwrap();
            cache.insert_at(
                &request,
                &stale,
                Duration::from_secs(60),
                observed_at,
                Some(deadline),
            )
        })
    };
    ready.recv().unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    drop(guard);
    assert!(!task.join().unwrap());
    let hit = cache.get(&request).expect("live entry remains");
    assert!(matches!(hit.answers[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 1)));
}
