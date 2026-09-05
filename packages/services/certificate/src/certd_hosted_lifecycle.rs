//! Bounded hosted-daemon shutdown and resilient channel acceptance.
use mrml_certificate::{UnixCertdChannelError, UnixCertdListener, UnixCertdSession};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(super) static STOPPING: AtomicBool = AtomicBool::new(false);

pub(super) struct StopOnWorkerExit;

impl Drop for StopOnWorkerExit {
    fn drop(&mut self) {
        // Also runs on unwind, so one worker cannot strand its scoped sibling.
        STOPPING.store(true, Ordering::Release);
    }
}

pub(super) fn install_termination_handlers() -> Result<(), &'static str> {
    let handler = termination_handler as *const () as usize;
    // SAFETY: Linux hosted entrypoint installs a C ABI handler before spawning
    // workers. The handler only stores to a lock-free AtomicBool; it allocates
    // nothing and calls no non-signal-safe functions. This follows Gitd's
    // existing hosted termination mechanism.
    if unsafe { signal(2, handler) } == usize::MAX || unsafe { signal(15, handler) } == usize::MAX {
        return Err("cannot install certd termination handlers");
    }
    Ok(())
}

extern "C" fn termination_handler(number: i32) {
    if matches!(number, 2 | 15) {
        STOPPING.store(true, Ordering::Release);
    }
}

unsafe extern "C" {
    fn signal(number: i32, handler: usize) -> usize;
}

pub(super) fn next_session(
    listener: &UnixCertdListener,
    stopping: &AtomicBool,
) -> Result<Option<UnixCertdSession>, &'static str> {
    while !stopping.load(Ordering::Acquire) {
        match listener.try_accept() {
            Ok(session) => return Ok(Some(session)),
            Err(UnixCertdChannelError::WouldBlock) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(UnixCertdChannelError::UnauthorizedPeer | UnixCertdChannelError::IoFailed) => {
                // A refused peer or per-connection setup failure does not own
                // the listener's lifetime. Bound retry work even under flood.
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(_) => {
                stopping.store(true, Ordering::Release);
                return Err("certd listener failed");
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::Instant;

    #[test]
    fn signal_child() {
        let Some(marker) = std::env::var_os("MRML_CERTD_SIGNAL_TEST_MARKER") else {
            return;
        };
        install_termination_handlers().unwrap();
        std::fs::write(marker, b"ready").unwrap();
        let start = Instant::now();
        while !STOPPING.load(Ordering::Acquire) {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn real_sigterm_is_observed_without_waiting_for_a_connection() {
        let root = std::env::temp_dir().join(format!("mrml-certd-signal-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let marker = root.join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "-Z",
                "unstable-options",
                "--force-run-in-process",
                "--exact",
                "certd_hosted_lifecycle::tests::signal_child",
            ])
            .env("MRML_CERTD_SIGNAL_TEST_MARKER", &marker)
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !marker.exists() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("signal child did not initialize");
        }
        assert!(
            Command::new("/bin/kill")
                .args(["-TERM", &child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let signalled = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if signalled.elapsed() >= Duration::from_secs(2) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("signal shutdown exceeded two seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
        std::fs::remove_dir_all(root).unwrap();
    }
}
