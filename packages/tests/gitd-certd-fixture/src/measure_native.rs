//! Test-only Linux accounting wrapper; executes only the native Git client.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[repr(C)]
#[derive(Default)]
struct Timeval {
    seconds: i64,
    microseconds: i64,
}
#[repr(C)]
#[derive(Default)]
struct Usage {
    user: Timeval,
    system: Timeval,
    counters: [i64; 14],
}
unsafe extern "C" {
    fn getrusage(who: i32, usage: *mut Usage) -> i32;
}
struct ReapOnExit(Child);
impl Drop for ReapOnExit {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn network_bytes() -> Result<(u64, u64), ()> {
    let contents = fs::read_to_string("/proc/self/net/dev").map_err(|_| ())?;
    if contents.len() > 16384 {
        return Err(());
    }
    let mut totals = (0u64, 0u64);
    for line in contents.lines().skip(2) {
        let (name, values) = line.split_once(':').ok_or(())?;
        if name.trim() == "lo" {
            continue;
        }
        let fields: Vec<&str> = values.split_whitespace().collect();
        if fields.len() != 16 {
            return Err(());
        }
        totals.0 = totals
            .0
            .checked_add(fields[0].parse::<u64>().map_err(|_| ())?)
            .ok_or(())?;
        totals.1 = totals
            .1
            .checked_add(fields[8].parse::<u64>().map_err(|_| ())?)
            .ok_or(())?;
    }
    Ok(totals)
}

fn final_child_io(pid: u32, output: &str, result: &mut fs::File) -> Result<String, ()> {
    match fs::read_to_string(format!("/proc/{pid}/io")) {
        Ok(io) => return Ok(io),
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied
                && std::env::var("MRML_ACCOUNTING_HOST_OBSERVER").as_deref() == Ok("1") => {}
        Err(error) => {
            eprintln!("accounting final child I/O: {error}");
            return Err(());
        }
    }
    // Some hardened hosts deny even a parent's read of its zombie child's I/O.
    // Do not grant ptrace/DAC capabilities to the client. The existing host
    // measurement operator reads the exact retained child, checks its namespace
    // PID and parent, and atomically publishes only numeric accounting data.
    // This public test observation conveys no Git or daemon authority.
    writeln!(result, "observer_state=zombie\nchild_namespace_pid={pid}").map_err(|_| ())?;
    result.sync_all().map_err(|_| ())?;
    let path = format!("{output}.host-io");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match OpenOptions::new().read(true).open(&path) {
            Ok(file) => {
                use std::io::Read;
                let mut bytes = Vec::new();
                file.take(4097).read_to_end(&mut bytes).map_err(|_| ())?;
                if bytes.len() > 4096 {
                    return Err(());
                }
                let text = String::from_utf8(bytes).map_err(|_| ())?;
                let (identity, io) = text.split_once('\n').ok_or(())?;
                if identity != format!("child_namespace_pid={pid}") {
                    return Err(());
                }
                return Ok(io.to_owned());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }
        if Instant::now() >= deadline {
            eprintln!("accounting host observer did not capture retained child I/O");
            return Err(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn run(args: &[String]) -> Result<(), ()> {
    let [_, output, command, rest @ ..] = args else {
        return Err(());
    };
    if command != "/usr/bin/mrml-git" || !output.starts_with("/work/") {
        return Err(());
    }
    let mut result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|_| ())?;
    let network_before = network_bytes()?;
    let start = Instant::now();
    let mut child = ReapOnExit(
        Command::new(command)
            .args(rest)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|_| ())?,
    );
    let pid = child.0.id();
    let last_io;
    let elapsed;
    let network_after;
    let mut samples = 0u64;
    // Read final task I/O while the exited child is still a zombie, before wait
    // releases its /proc entry. No secret contents or arguments are recorded.
    let status = loop {
        samples += 1;
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
            eprintln!("accounting child status: {error}");
        })?;
        let state = stat
            .rsplit_once(") ")
            .ok_or(())?
            .1
            .as_bytes()
            .first()
            .copied()
            .ok_or(())?;
        if state == b'Z' {
            // Exclude observer coordination from transfer elapsed/network data.
            elapsed = start.elapsed();
            network_after = network_bytes()?;
            last_io = final_child_io(pid, output, &mut result)?;
            if last_io.len() > 4096 {
                return Err(());
            }
            break child.0.wait().map_err(|_| ())?;
        }
        if start.elapsed() > Duration::from_secs(1800) {
            return Err(());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut usage = Usage::default();
    // SAFETY: Linux x86-64 getrusage(RUSAGE_CHILDREN), fixed ABI storage retained for the
    // call. Only this wrapper's one reaped child contributes; no host authority.
    if unsafe { getrusage(-1, &mut usage) } != 0 {
        eprintln!("accounting getrusage: {}", std::io::Error::last_os_error());
        return Err(());
    }
    for prefix in [
        "rchar:",
        "wchar:",
        "syscr:",
        "syscw:",
        "read_bytes:",
        "write_bytes:",
    ] {
        if !last_io.lines().any(|line| line.starts_with(prefix)) {
            eprintln!("accounting missing I/O counter: {prefix}");
            return Err(());
        }
    }
    writeln!(
        result,
        "network_received_bytes={}\nnetwork_sent_bytes={}",
        network_after.0.checked_sub(network_before.0).ok_or(())?,
        network_after.1.checked_sub(network_before.1).ok_or(())?
    )
    .map_err(|_| ())?;
    writeln!(result, "format=mrml-native-transfer-accounting-v1\nelapsed_microseconds={}\nuser_cpu_microseconds={}\nsystem_cpu_microseconds={}\npeak_rss_kib={}\nexit_status={}\nsamples={}",
        elapsed.as_micros(),
        usage.user.seconds * 1_000_000 + usage.user.microseconds,
        usage.system.seconds * 1_000_000 + usage.system.microseconds,
        usage.counters[0], status.code().unwrap_or(-1), samples).map_err(|_| ())?;
    for line in last_io.lines() {
        if [
            "rchar:",
            "wchar:",
            "syscr:",
            "syscw:",
            "read_bytes:",
            "write_bytes:",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix))
        {
            writeln!(result, "{line}").map_err(|_| ())?;
        }
    }
    result.sync_all().map_err(|_| ())?;
    if !status.success() {
        return Err(());
    }
    println!("native transfer accounting saved");
    Ok(())
}
