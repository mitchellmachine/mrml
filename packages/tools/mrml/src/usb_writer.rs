//! Installed Linux privilege boundary: no build, child process, or caller-supplied paths.
use std::io::{self, Read as _};
use std::process::ExitCode;

#[path = "../../../libraries/crypto/src/sha3.rs"]
#[allow(dead_code)]
mod sha3;
use sha3::Sha3_512;
#[path = "usb_linux.rs"]
#[allow(dead_code)]
mod host;
#[allow(dead_code)]
mod usb_image;
#[allow(dead_code)] // The shared manual mode is only used by the frontend.
mod usb_transfer;

use usb_image::BYTES;
use usb_transfer::{WriteMode, require_only_usb, transfer};
type Disk = usb_transfer::Disk<host::Identity>;

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("mrml-usb-writer: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> io::Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(io::Error::other(
            "the USB writer does not accept command-line arguments",
        ));
    }
    if !host::privileged() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the USB writer must run as root",
        ));
    }
    let mut input = io::stdin().lock();
    let mut target = [0; 64];
    input.read_exact(&mut target)?;
    let disk = matching_target(&target)?;
    let image = read_image(input)?;
    if matching_target(&target)? != disk {
        return Err(io::Error::other("the USB device changed; no bytes written"));
    }
    host::write_image(&disk, &image, WriteMode::Auto { erase: false })?;
    println!(
        "Verified {} bytes on {}. Safely eject the drive.",
        image.len(),
        disk.path.display()
    );
    Ok(())
}

fn matching_target(target: &[u8; 64]) -> io::Result<Disk> {
    let connected = host::usb_storage()?;
    let [path] = connected.as_slice() else {
        return Err(io::Error::other(
            "expected exactly one USB storage drive; no bytes written",
        ));
    };
    host::disks(false)?
        .into_iter()
        .find(|disk| disk.path == *path && host::fingerprint(disk) == *target)
        .ok_or_else(|| io::Error::other("USB does not match the selected device; no bytes written"))
}

fn read_image(mut input: impl io::Read) -> io::Result<Vec<u8>> {
    let mut digest = [0; 64];
    input.read_exact(&mut digest)?;
    let mut image = Vec::with_capacity(BYTES + 1);
    input.take((BYTES + 1) as u64).read_to_end(&mut image)?;
    usb_image::check_image(&image)?;
    if Sha3_512::digest(&image) != digest {
        return Err(io::Error::other(
            "USB image digest mismatch; no bytes written",
        ));
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_or_non_diagnostic_requests_cannot_supply_an_image() {
        assert!(read_image(&[0u8; 63][..]).is_err());
        assert!(read_image(&[0u8; 65][..]).is_err());
        assert!(read_image(io::repeat(0).take((BYTES + 65) as u64)).is_err());
    }
}
