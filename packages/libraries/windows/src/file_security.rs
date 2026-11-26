use super::{CreateFileW, DynamicLibrary, NativeFile};
use core::ffi::{CStr, c_void};
use core::ptr::{NonNull, null_mut};

unsafe extern "system" {
    fn LockFileEx(
        file: *mut c_void,
        flags: u32,
        reserved: u32,
        count_low: u32,
        count_high: u32,
        overlapped: *mut FileLockOverlapped,
    ) -> i32;
    fn LoadLibraryExA(name: *const i8, file: *mut c_void, flags: u32) -> *mut c_void;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[repr(C)]
struct FileLockOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut c_void,
}

pub(super) fn lock_exclusive(file: &NativeFile) -> bool {
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
    let mut request = FileLockOverlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: core::ptr::null_mut(),
    };
    // SAFETY: file owns a synchronous handle and request is live for the call.
    let result = unsafe {
        LockFileEx(
            file.raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut request,
        )
    };
    result != 0
}

pub(super) fn open_owner_mode(path: &[u16]) -> Option<NativeFile> {
    let name = path.strip_suffix(&[0])?;
    if name.is_empty() || name.contains(&0) {
        return None;
    }
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const FILE_SHARE_ALL: u32 = 7;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    // SAFETY: path is a live, NUL-terminated UTF-16 slice.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_ALL,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            core::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return None;
    }
    let file = NativeFile(handle, core::cell::Cell::new(false));
    NativeFile::handle_is_regular_file(handle).then_some(file)
}

struct LocalSid(NonNull<c_void>);

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: this SID is owned and was allocated by ConvertStringSidToSidA.
        unsafe { LocalFree(self.0.as_ptr()) };
    }
}

/// Maps rwx to the Win32 generic file access masks, not ACL administration.
fn access_mask(bits: u32) -> u32 {
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    const FILE_GENERIC_EXECUTE: u32 = 0x0012_00a0;
    let mut mask = 0;
    if bits & 4 != 0 {
        mask |= FILE_GENERIC_READ;
    }
    if bits & 2 != 0 {
        mask |= FILE_GENERIC_WRITE;
    }
    if bits & 1 != 0 {
        mask |= FILE_GENERIC_EXECUTE;
    }
    mask
}

pub(super) fn set_owner_mode(
    file: &NativeFile,
    owner: &CStr,
    group: &CStr,
    mode: u32,
) -> Option<()> {
    let owner_bits = (mode >> 6) & 7;
    let group_bits = (mode >> 3) & 7;
    let other_bits = mode & 7;
    // An allow-only DACL safely represents nested permission sets. Windows
    // group membership can overlap, so never silently widen an unsupported mode.
    if mode & !0o777 != 0
        || group_bits & !owner_bits != 0
        || other_bits & !group_bits != 0
        || owner.to_bytes().len() > 192
        || group.to_bytes().len() > 192
        || !owner.to_bytes().starts_with(b"S-1-")
        || !group.to_bytes().starts_with(b"S-1-")
    {
        return None;
    }

    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
    // SAFETY: a fixed system DLL is loaded with no search of the working directory.
    let library = DynamicLibrary(unsafe {
        LoadLibraryExA(
            c"advapi32.dll".as_ptr(),
            null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    });
    if library.0.is_null() {
        // Do not pass a failed load to the library's Drop implementation.
        core::mem::forget(library);
        return None;
    }

    type ConvertSid = unsafe extern "system" fn(*const i8, *mut *mut c_void) -> i32;
    type EqualSid = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
    type InitializeAcl = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;
    type AddAce = unsafe extern "system" fn(*mut c_void, u32, u32, *mut c_void) -> i32;
    type SetSecurityInfo = unsafe extern "system" fn(
        *mut c_void,
        u32,
        u32,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
    ) -> u32;

    macro_rules! bind {
        ($name:literal, $abi:ty) => {{
            // SAFETY: each name is paired with its documented ABI in system advapi32.
            unsafe { core::mem::transmute::<*mut c_void, $abi>(library.symbol($name)?) }
        }};
    }
    let convert_sid = bind!(c"ConvertStringSidToSidA", ConvertSid);
    let equal_sid = bind!(c"EqualSid", EqualSid);
    let initialize_acl = bind!(c"InitializeAcl", InitializeAcl);
    let add_ace = bind!(c"AddAccessAllowedAce", AddAce);
    let set_security_info = bind!(c"SetSecurityInfo", SetSecurityInfo);
    let sid = |value: &CStr| {
        let mut pointer = null_mut();
        // SAFETY: value is NUL-terminated and the API returns an owned allocation.
        if unsafe { convert_sid(value.as_ptr(), &mut pointer) } == 0 {
            return None;
        }
        NonNull::new(pointer).map(LocalSid)
    };
    let owner = sid(owner)?;
    let group = sid(group)?;
    let world = sid(c"S-1-1-0")?;
    let owner = &owner;
    let group = &group;
    let world = &world;
    let matches = |a: &LocalSid, b: &LocalSid| {
        // SAFETY: both pointers refer to live, validated SIDs.
        unsafe { equal_sid(a.0.as_ptr(), b.0.as_ptr()) != 0 }
    };
    if matches(owner, world) || matches(group, world) || matches(owner, group) {
        return None;
    }

    const ACL_REVISION: u32 = 2;
    // DWORD-aligned: ACL header plus three ACEs with maximum-sized SIDs.
    let mut acl_buffer = [0u32; 60];
    let acl = acl_buffer.as_mut_ptr().cast();
    // SAFETY: acl names a live, aligned buffer of the exact declared size.
    if unsafe { initialize_acl(acl, size_of_val(&acl_buffer) as u32, ACL_REVISION) } == 0 {
        return None;
    }
    for (principal, bits) in [
        (owner, owner_bits),
        (group, group_bits),
        (world, other_bits),
    ] {
        // SAFETY: the ACL is initialized and principal is a live Windows SID.
        if bits != 0
            && unsafe { add_ace(acl, ACL_REVISION, access_mask(bits), principal.0.as_ptr()) } == 0
        {
            return None;
        }
    }

    const SE_FILE_OBJECT: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 1;
    const GROUP_SECURITY_INFORMATION: u32 = 2;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    // SAFETY: the handle, SIDs and non-null DACL remain live. Windows checks
    // the handle's WRITE_DAC/WRITE_OWNER rights and SID assignment authority.
    (unsafe {
        set_security_info(
            file.raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner.0.as_ptr(),
            group.0.as_ptr(),
            acl,
            null_mut(),
        )
    } == 0)
        .then_some(())
}
