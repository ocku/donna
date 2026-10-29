use super::*;
use std::sync::{Arc, mpsc};

#[test]
fn insertion_expiring_while_lock_is_held_cannot_replace_live_negative() {
    let cache = Arc::new(NegativeCache::new(1));
    let query = question(QueryType::A);
    let live = negative(RCode::NameError, 60, 60);
    assert!(cache.insert(&query, &live, true, Duration::from_secs(60)));
    let stale = negative(RCode::Ok, 60, 60);
    let observed_at = Instant::now();
    let deadline = observed_at + Duration::from_secs(1);
    let guard = cache.entries.lock().unwrap();
    let (started, ready) = mpsc::channel();
    let task = {
        let cache = Arc::clone(&cache);
        let query = query.clone();
        std::thread::spawn(move || {
            started.send(()).unwrap();
            cache.insert_at(
                &query,
                &stale,
                true,
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
    assert_eq!(
        cache
            .get(&query)
            .expect("live negative remains")
            .headers
            .rcode,
        RCode::NameError
    );
}
