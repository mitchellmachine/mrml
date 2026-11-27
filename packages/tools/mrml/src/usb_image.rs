//! Minimal portable EFI System Partition authoring for the USB diagnostic.
use std::io::{self, Read as _};
use std::path::Path;

pub(super) const SECTOR: usize = 512;
const PARTITION: usize = 2048;
const VOLUME: usize = 128 * 1024;
const RESERVED: usize = 32;
const FAT: usize = (VOLUME - RESERVED + 2).div_ceil(130);
const DATA: usize = RESERVED + FAT * 2;
const END: u32 = 0x0fff_ffff;
// Matches the UEFI loader's reserved diagnostic slot (not a boot artifact).
const REPORT_BYTES: usize = 16 * 1024;
const REPORT_HEADER: &[u8] =
    b"MRML BOOT LOG V1\r\nNo boot report has been recorded.\r\nEND MRML BOOT LOG\r\n";
const LABEL: &[u8; 11] = b"MRMLBOOT   ";
pub(super) const BYTES: usize = (PARTITION + VOLUME) * SECTOR;

const BOOT: &[(&str, &[u8; 11])] = &[("BOOTX64.EFI", b"BOOTX64 EFI")];
const MRML: &[(&str, &[u8; 11])] = &[
    ("BOOTLOADER.PACKAGE", b"LOADER~1PAK"),
    ("KERNEL.PACKAGE", b"KERNEL~1PAK"),
    ("CONFIGURATION.PACKAGE", b"CONFIG~1PAK"),
    ("SYSTEM.RELEASE", b"SYSTEM~1REL"),
    ("SERVICE.SIGNED", b"SERVIC~1SIG"),
];

fn put16(output: &mut [u8], at: usize, value: u16) {
    output[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(output: &mut [u8], at: usize, value: u32) {
    output[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn partition_table() -> [u8; SECTOR] {
    let mut first = [0; SECTOR];
    first[440..444].copy_from_slice(b"MRMU");
    first[447..450].copy_from_slice(&[0xfe, 0xff, 0xff]);
    first[450] = 0xef; // MBR EFI System Partition; no legacy boot program.
    first[451..454].copy_from_slice(&[0xfe, 0xff, 0xff]);
    put32(&mut first, 454, PARTITION as u32);
    put32(&mut first, 458, VOLUME as u32);
    first[510..].copy_from_slice(&[0x55, 0xaa]);
    first
}

fn volume_boot() -> [u8; SECTOR] {
    let mut boot = [0; SECTOR];
    boot[..11].copy_from_slice(b"\xeb\x58\x90MRML USB");
    put16(&mut boot, 11, SECTOR as u16);
    boot[13] = 1;
    put16(&mut boot, 14, RESERVED as u16);
    boot[16] = 2;
    boot[21] = 0xf8;
    put16(&mut boot, 24, 63);
    put16(&mut boot, 26, 255);
    put32(&mut boot, 28, PARTITION as u32);
    put32(&mut boot, 32, VOLUME as u32);
    put32(&mut boot, 36, FAT as u32);
    put32(&mut boot, 44, 2);
    put16(&mut boot, 48, 1);
    put16(&mut boot, 50, 6);
    boot[64] = 0x80;
    boot[66] = 0x29;
    boot[67..71].copy_from_slice(b"MRMU");
    boot[71..82].copy_from_slice(LABEL);
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[90..94].copy_from_slice(&[0xfa, 0xf4, 0xeb, 0xfd]);
    boot[510..].copy_from_slice(&[0x55, 0xaa]);
    boot
}

fn short(alias: &[u8; 11], attributes: u8, cluster: u32, bytes: u32) -> [u8; 32] {
    let mut entry = [0; 32];
    entry[..11].copy_from_slice(alias);
    entry[11] = attributes;
    for at in [16, 18, 24] {
        put16(&mut entry, at, (46 << 9) | (1 << 5) | 1);
    }
    put16(&mut entry, 20, (cluster >> 16) as u16);
    put16(&mut entry, 26, cluster as u16);
    put32(&mut entry, 28, bytes);
    entry
}

fn append_file(dir: &mut Vec<u8>, name: &str, alias: &[u8; 11], cluster: u32, bytes: u32) {
    if name != "BOOTX64.EFI" {
        let mut units: Vec<u16> = name.encode_utf16().collect();
        units.push(0);
        let count = units.len().div_ceil(13);
        units.resize(count * 13, u16::MAX);
        let checksum = alias
            .iter()
            .fold(0u8, |v, &b| v.rotate_right(1).wrapping_add(b));
        for index in (0..count).rev() {
            let mut record = [0; 32];
            record[0] = (index as u8 + 1) | if index + 1 == count { 0x40 } else { 0 };
            record[11] = 0x0f;
            record[13] = checksum;
            for (at, &unit) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                .into_iter()
                .zip(&units[index * 13..][..13])
            {
                put16(&mut record, at, unit);
            }
            dir.extend(record);
        }
    }
    dir.extend(short(alias, 0x20, cluster, bytes));
}

struct Writer {
    image: Vec<u8>,
    table: Vec<u8>,
    next: usize,
}

impl Writer {
    fn allocate(&mut self, count: usize) -> io::Result<u32> {
        let end = self
            .next
            .checked_add(count)
            .ok_or_else(|| io::Error::other("cluster overflow"))?;
        if count == 0 || end > VOLUME - DATA + 2 {
            return Err(io::Error::other("boot artifacts do not fit the ESP"));
        }
        let first = self.next;
        for cluster in first..end {
            let next = if cluster + 1 == end {
                END
            } else {
                cluster as u32 + 1
            };
            put32(&mut self.table, cluster * 4, next);
        }
        self.next = end;
        Ok(first as u32)
    }

    fn write(&mut self, cluster: u32, data: &[u8]) {
        let at = (PARTITION + DATA + cluster as usize - 2) * SECTOR;
        self.image[at..at + data.len()].copy_from_slice(data);
    }

    fn finish(mut self) -> Vec<u8> {
        self.image[..SECTOR].copy_from_slice(&partition_table());
        for sector in [0, 6] {
            let at = (PARTITION + sector) * SECTOR;
            self.image[at..at + SECTOR].copy_from_slice(&volume_boot());
            let info = &mut self.image[at + SECTOR..at + 2 * SECTOR];
            put32(info, 0, 0x4161_5252);
            put32(info, 484, 0x6141_7272);
            let remaining = VOLUME - DATA + 2 - self.next;
            put32(info, 488, remaining as u32);
            put32(
                info,
                492,
                if remaining == 0 {
                    u32::MAX
                } else {
                    self.next as u32
                },
            );
            put32(info, 508, 0xaa55_0000);
        }
        for offset in [RESERVED, RESERVED + FAT] {
            let at = (PARTITION + offset) * SECTOR;
            self.image[at..at + FAT * SECTOR].copy_from_slice(&self.table);
        }
        self.image
    }
}

fn serialize(files: [&[u8]; 6]) -> io::Result<Vec<u8>> {
    let mut writer = Writer {
        image: vec![0; BYTES],
        table: vec![0; FAT * SECTOR],
        next: 2,
    };
    put32(&mut writer.table, 0, 0x0fff_fff8);
    put32(&mut writer.table, 4, END);
    let root = writer.allocate(1)?;
    let efi = writer.allocate(1)?;
    let boot = writer.allocate(1)?;
    let mrml = writer.allocate(2)?;

    let mut dirs = [Vec::new(), Vec::new()];
    for (buffer, cluster) in dirs.iter_mut().zip([boot, mrml]) {
        buffer.extend(short(b".          ", 0x10, cluster, 0));
        buffer.extend(short(b"..         ", 0x10, efi, 0));
    }
    for (((name, alias), payload), container) in
        BOOT.iter().chain(MRML).zip(files).zip([0, 1, 1, 1, 1, 1])
    {
        let cluster = writer.allocate(payload.len().div_ceil(SECTOR))?;
        writer.write(cluster, payload);
        append_file(
            &mut dirs[container],
            name,
            alias,
            cluster,
            payload.len() as u32,
        );
    }
    if dirs[0].len() >= SECTOR || dirs[1].len() >= 2 * SECTOR {
        return Err(io::Error::other("ESP directory overflow"));
    }

    let report_cluster = writer.allocate(REPORT_BYTES / SECTOR)?;
    let mut report = [b' '; REPORT_BYTES];
    report[..REPORT_HEADER.len()].copy_from_slice(REPORT_HEADER);
    writer.write(report_cluster, &report);

    let mut entries = Vec::new();
    entries.extend(short(LABEL, 0x08, 0, 0));
    entries.extend(short(b"EFI        ", 0x10, efi, 0));
    entries.extend(short(
        b"MRMLBOOTTXT",
        0x20,
        report_cluster,
        REPORT_BYTES as u32,
    ));
    writer.write(root, &entries);
    entries.clear();
    entries.extend(short(b".          ", 0x10, efi, 0));
    entries.extend(short(b"..         ", 0x10, 0, 0));
    entries.extend(short(b"BOOT       ", 0x10, boot, 0));
    entries.extend(short(b"MRML       ", 0x10, mrml, 0));
    writer.write(efi, &entries);
    writer.write(boot, &dirs[0]);
    writer.write(mrml, &dirs[1]);
    Ok(writer.finish())
}

pub(super) fn read_regular(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(io::Error::other("expected a regular file"));
    }
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(io::Error::other(
            "regular file is empty or outside the size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(io::Error::other("file changed while reading"));
    }
    Ok(bytes)
}

pub(super) fn compose(paths: [&Path; 6]) -> io::Result<Vec<u8>> {
    let mut slots: [Vec<u8>; 6] = std::array::from_fn(|_| Vec::new());
    let mut remaining = (VOLUME - DATA - 5) * SECTOR - REPORT_BYTES;
    for (slot, path) in slots.iter_mut().zip(paths) {
        *slot = read_regular(path, remaining)?;
        remaining -= slot.len().div_ceil(SECTOR) * SECTOR;
    }
    serialize(slots.each_ref().map(Vec::as_slice))
}

pub(super) fn check_image(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() != BYTES
        || bytes[..SECTOR] != partition_table()
        || bytes[PARTITION * SECTOR..(PARTITION + 1) * SECTOR] != volume_boot()
    {
        return Err(io::Error::other("not an MRML diagnostic USB image"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_layout_and_independent_copies() {
        let mut image = serialize([
            b"efi", b"loader", b"kernel", b"config", b"release", b"service",
        ])
        .unwrap();
        check_image(&image).unwrap();
        let first = (PARTITION + RESERVED) * SECTOR;
        let second = first + FAT * SECTOR;
        assert_eq!(&image[first..second], &image[second..second + FAT * SECTOR]);
        assert_eq!(
            &image[first + 5 * 4..first + 7 * 4],
            &[6, 0, 0, 0, 255, 255, 255, 15]
        );
        let root = (PARTITION + DATA) * SECTOR;
        let entry = &image[root + 64..root + 96];
        assert_eq!(&entry[..11], b"MRMLBOOTTXT");
        assert_eq!(
            u32::from_le_bytes(entry[28..32].try_into().unwrap()),
            REPORT_BYTES as u32
        );
        let report_cluster = u16::from_le_bytes(entry[26..28].try_into().unwrap()) as usize;
        let report_offset = root + (report_cluster - 2) * SECTOR;
        assert_eq!(
            &image[report_offset..][..REPORT_HEADER.len()],
            REPORT_HEADER
        );
        image[450] = 0xef ^ 1;
        assert!(check_image(&image).is_err());
        assert!(serialize([b""; 6]).is_err());
    }
}
