//! Unprivileged client for the installed Linux USB writer.
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::Sha3_512;

const PKEXEC: &str = "/usr/bin/pkexec";
const HELPER: &str = "/usr/lib/mrml/mrml-usb-writer";
const ROOT_FALLBACK: &str = "run mrml usb autoburn as root instead";

pub(crate) struct Writer;

impl Writer {
    pub(crate) fn locate() -> io::Result<Self> {
        for path in [PKEXEC, HELPER] {
            trusted_executable(Path::new(path))
                .map_err(|error| io::Error::other(format!("{path}: {error}; {ROOT_FALLBACK}")))?;
        }
        Ok(Self)
    }

    pub(crate) fn write(&self, target: [u8; 64], image: &[u8]) -> io::Result<()> {
        Self::locate()?;
        let mut child = Command::new(PKEXEC)
            .args(["--disable-internal-agent", HELPER])
            .current_dir("/")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|error| {
                io::Error::other(format!("could not start pkexec: {error}; {ROOT_FALLBACK}"))
            })?;
        let digest = Sha3_512::digest(image);
        let sent = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing USB writer input"))
            .and_then(|mut pipe| {
                pipe.write_all(&target)?;
                pipe.write_all(&digest)?;
                pipe.write_all(image)
            });
        match child.wait()?.code() {
            Some(0) => sent,
            Some(126) => Err(io::Error::other("polkit authorization canceled")),
            Some(127) => Err(io::Error::other(format!(
                "polkit authorization unavailable or denied; {ROOT_FALLBACK}"
            ))),
            _ => Err(io::Error::other(
                "privileged USB writer did not complete; see its diagnostic",
            )),
        }
    }
}

fn trusted_executable(path: &Path) -> io::Result<()> {
    for entry in path.ancestors() {
        let meta = fs::symlink_metadata(entry)?;
        if meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || (entry == path && (!meta.is_file() || meta.mode() & 0o111 == 0))
            || (entry != path && !meta.is_dir())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "expected a root-owned executable under non-writable, non-symlink directories",
            ));
        }
    }
    Ok(())
}
