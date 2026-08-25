use crate::generation::SystemPackage;

pub const COMPONENT_PAGE_BYTES: u64 = 4096;
const MAX_IMAGE_SECTIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionPermissions {
    read: bool,
    write: bool,
    execute: bool,
}

impl SectionPermissions {
    pub const fn new(read: bool, write: bool, execute: bool) -> Result<Self, LoaderError> {
        if write && execute {
            return Err(LoaderError::WritableExecutable);
        }
        if !read && !write && !execute {
            return Err(LoaderError::EmptyPermissions);
        }
        Ok(Self {
            read,
            write,
            execute,
        })
    }

    pub const fn writable(self) -> bool {
        self.write
    }

    pub const fn executable(self) -> bool {
        self.execute
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageSection {
    offset: u64,
    length: u64,
    permissions: SectionPermissions,
}

impl ImageSection {
    pub fn pages(
        offset: u64,
        length: u64,
        permissions: SectionPermissions,
    ) -> Result<Self, LoaderError> {
        if length == 0
            || !offset.is_multiple_of(COMPONENT_PAGE_BYTES)
            || !length.is_multiple_of(COMPONENT_PAGE_BYTES)
        {
            return Err(LoaderError::InvalidSectionGeometry);
        }
        offset
            .checked_add(length)
            .ok_or(LoaderError::SectionOverflow)?;
        Ok(Self {
            offset,
            length,
            permissions,
        })
    }

    pub const fn offset(self) -> u64 {
        self.offset
    }

    pub const fn length(self) -> u64 {
        self.length
    }

    pub const fn permissions(self) -> SectionPermissions {
        self.permissions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableLoadPlan {
    package: SystemPackage,
    image_length: u64,
    entry_offset: u64,
    sections: Vec<ImageSection>,
}

impl ImmutableLoadPlan {
    pub fn admit(
        package: SystemPackage,
        image_length: u64,
        entry_offset: u64,
        sections: Vec<ImageSection>,
    ) -> Result<Self, LoaderError> {
        if image_length == 0 || !image_length.is_multiple_of(COMPONENT_PAGE_BYTES) {
            return Err(LoaderError::InvalidImageLength);
        }
        if sections.is_empty() || sections.len() > MAX_IMAGE_SECTIONS {
            return Err(LoaderError::SectionCount);
        }
        let mut entry_is_executable = false;
        let mut previous_end = 0;
        for section in &sections {
            let end = section
                .offset
                .checked_add(section.length)
                .ok_or(LoaderError::SectionOverflow)?;
            if section.offset < previous_end || end > image_length {
                return Err(LoaderError::OverlappingOrOutsideImage);
            }
            if section.permissions.write && section.permissions.execute {
                return Err(LoaderError::WritableExecutable);
            }
            if section.permissions.execute && (section.offset..end).contains(&entry_offset) {
                entry_is_executable = true;
            }
            previous_end = end;
        }
        if !entry_is_executable {
            return Err(LoaderError::EntryNotExecutable);
        }
        Ok(Self {
            package,
            image_length,
            entry_offset,
            sections,
        })
    }

    pub fn package(&self) -> &SystemPackage {
        &self.package
    }

    pub const fn image_length(&self) -> u64 {
        self.image_length
    }

    pub const fn entry_offset(&self) -> u64 {
        self.entry_offset
    }

    pub fn sections(&self) -> &[ImageSection] {
        &self.sections
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderError {
    WritableExecutable,
    EmptyPermissions,
    InvalidSectionGeometry,
    SectionOverflow,
    InvalidImageLength,
    SectionCount,
    OverlappingOrOutsideImage,
    EntryNotExecutable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package() -> SystemPackage {
        SystemPackage::new("org.mrml.zstd".into(), 14, [0x2e; 64]).unwrap()
    }

    #[test]
    fn admits_exact_immutable_wx_plan() {
        let rx = SectionPermissions::new(true, false, true).unwrap();
        let rw = SectionPermissions::new(true, true, false).unwrap();
        let plan = ImmutableLoadPlan::admit(
            package(),
            3 * COMPONENT_PAGE_BYTES,
            64,
            vec![
                ImageSection::pages(0, COMPONENT_PAGE_BYTES, rx).unwrap(),
                ImageSection::pages(COMPONENT_PAGE_BYTES, 2 * COMPONENT_PAGE_BYTES, rw).unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(plan.package().package_id(), "org.mrml.zstd");
        assert_eq!(plan.image_length(), 3 * COMPONENT_PAGE_BYTES);
        assert_eq!(plan.entry_offset(), 64);
        assert!(plan.sections()[0].permissions().executable());
        assert!(plan.sections()[1].permissions().writable());
    }

    #[test]
    fn rejects_writable_code_overlap_and_nonexecutable_entry() {
        assert_eq!(
            SectionPermissions::new(true, true, true),
            Err(LoaderError::WritableExecutable)
        );
        let rx = SectionPermissions::new(true, false, true).unwrap();
        let rw = SectionPermissions::new(true, true, false).unwrap();
        let first = ImageSection::pages(0, 2 * COMPONENT_PAGE_BYTES, rx).unwrap();
        let overlap = ImageSection::pages(COMPONENT_PAGE_BYTES, COMPONENT_PAGE_BYTES, rw).unwrap();
        assert_eq!(
            ImmutableLoadPlan::admit(
                package(),
                3 * COMPONENT_PAGE_BYTES,
                64,
                vec![first, overlap]
            ),
            Err(LoaderError::OverlappingOrOutsideImage)
        );
        assert_eq!(
            ImmutableLoadPlan::admit(
                package(),
                COMPONENT_PAGE_BYTES,
                64,
                vec![ImageSection::pages(0, COMPONENT_PAGE_BYTES, rw).unwrap()]
            ),
            Err(LoaderError::EntryNotExecutable)
        );
    }

    #[test]
    fn rejects_unaligned_overflowing_and_outside_sections() {
        let rx = SectionPermissions::new(true, false, true).unwrap();
        assert_eq!(
            ImageSection::pages(1, COMPONENT_PAGE_BYTES, rx),
            Err(LoaderError::InvalidSectionGeometry)
        );
        assert_eq!(
            ImageSection::pages(u64::MAX - 4095, COMPONENT_PAGE_BYTES, rx),
            Err(LoaderError::SectionOverflow)
        );
        assert_eq!(
            ImmutableLoadPlan::admit(
                package(),
                COMPONENT_PAGE_BYTES,
                0,
                vec![ImageSection::pages(0, 2 * COMPONENT_PAGE_BYTES, rx).unwrap()]
            ),
            Err(LoaderError::OverlappingOrOutsideImage)
        );
    }
}
