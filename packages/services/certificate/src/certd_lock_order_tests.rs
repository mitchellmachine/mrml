use super::*;
use std::time::{Duration, Instant};

#[test]
fn candidate_publication_does_not_hold_key_while_waiting_for_durable_reader() {
    let keys = Mutex::new(Vec::<CertificateP256SigningKey>::new());
    let durable = Mutex::new(());
    std::thread::scope(|scope| {
        // Match the real paths: staging has finished key use; an active
        // identity reader holds durable state before checking key availability.
        let staging_key = keys.lock().unwrap();
        let (ready, started) = std::sync::mpsc::channel();
        let reader_keys = &keys;
        let reader_durable = &durable;
        let reader = scope.spawn(move || {
            let _durable = reader_durable.lock().unwrap();
            ready.send(()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                if reader_keys.try_lock().is_ok() {
                    return true;
                }
                if Instant::now() >= deadline {
                    // Release the durable guard so the red regression remains
                    // bounded and reports failure instead of deadlocking tests.
                    return false;
                }
                std::thread::yield_now();
            }
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        publish_after_certificate_validation(staging_key, || {
            let _durable = durable.lock().unwrap();
            Ok(())
        })
        .unwrap();
        assert!(
            reader.join().unwrap(),
            "key/durable lock inversion blocked active reader"
        );
    });
}
