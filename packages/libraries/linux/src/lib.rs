#![no_std]

#[cfg(unix)]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(unix)]
use core::ffi::c_void;
#[cfg(unix)]
use core::ffi::{CStr, c_int, c_long};
#[cfg(unix)]
use core::ptr::NonNull;

#[repr(C)]
#[cfg(unix)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

// Linux x86-64 exposes pthread_attr_t as a 56-byte opaque object aligned to
// eight bytes. Keep the platform ABI detail here rather than in runtime code.
#[repr(C, align(8))]
#[cfg(unix)]
struct PthreadAttr([u8; 56]);

#[repr(C)]
#[cfg(unix)]
struct Stat {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    pad: i32,
    special_device: u64,
    size: i64,
    block_size: i64,
    blocks: i64,
    access_time: i64,
    access_nanoseconds: i64,
    modification_time: i64,
    modification_nanoseconds: i64,
    change_time: i64,
    change_nanoseconds: i64,
    reserved: [i64; 3],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalTime {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub weekday: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
}

#[repr(C)]
#[cfg(unix)]
struct Tm {
    second: c_int,
    minute: c_int,
    hour: c_int,
    day: c_int,
    month: c_int,
    year: c_int,
    weekday: c_int,
    year_day: c_int,
    daylight: c_int,
    utc_offset: c_long,
    zone: *const i8,
}

#[cfg(unix)]
#[link(name = "c")]
unsafe extern "C" {
    fn localtime_r(clock: *const c_long, result: *mut Tm) -> *mut Tm;
    fn posix_memalign(memory: *mut *mut c_void, alignment: usize, bytes: usize) -> c_int;
    fn free(memory: *mut c_void);
    fn nanosleep(request: *const Timespec, remaining: *mut Timespec) -> c_int;
    fn clock_gettime(clock: c_int, time: *mut Timespec) -> c_int;
    fn dlopen(name: *const i8, flags: c_int) -> *mut c_void;
    fn dlsym(module: *mut c_void, name: *const i8) -> *mut c_void;
    fn dlclose(module: *mut c_void) -> c_int;
    fn mmap(
        address: *mut c_void,
        len: usize,
        protection: c_int,
        flags: c_int,
        file: c_int,
        offset: isize,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, len: usize) -> c_int;
    fn _exit(status: c_int) -> !;
    fn isatty(file: c_int) -> c_int;
    fn getenv(name: *const i8) -> *mut i8;
    fn getpid() -> c_int;
    fn open(path: *const i8, flags: c_int, ...) -> c_int;
    fn read(file: c_int, buffer: *mut c_void, count: usize) -> isize;
    fn write(file: c_int, buffer: *const c_void, count: usize) -> isize;
    fn lseek(file: c_int, offset: isize, whence: c_int) -> isize;
    fn close(file: c_int) -> c_int;
    fn fsync(file: c_int) -> c_int;
    fn fstat(file: c_int, status: *mut Stat) -> c_int;
    fn geteuid() -> u32;
    fn mkdir(path: *const i8, mode: u32) -> c_int;
    fn unlink(path: *const i8) -> c_int;
    fn rmdir(path: *const i8) -> c_int;
    fn pipe(files: *mut c_int) -> c_int;
    fn fork() -> c_int;
    fn dup2(old: c_int, new: c_int) -> c_int;
    fn execvp(program: *const i8, arguments: *const *const i8) -> c_int;
    fn chdir(path: *const i8) -> c_int;
    fn waitpid(process: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn kill(process: c_int, signal: c_int) -> c_int;
    fn fcntl(file: c_int, command: c_int, ...) -> c_int;
    fn rename(existing: *const i8, replacement: *const i8) -> c_int;
    fn opendir(path: *const i8) -> *mut c_void;
    fn fdopendir(file: c_int) -> *mut c_void;
    fn dirfd(directory: *mut c_void) -> c_int;
    fn readdir(directory: *mut c_void) -> *mut Dirent;
    fn closedir(directory: *mut c_void) -> c_int;
    fn realpath(path: *const i8, resolved: *mut i8) -> *mut i8;
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn bind(socket: c_int, address: *const SockAddr, length: u32) -> c_int;
    fn listen(socket: c_int, backlog: c_int) -> c_int;
    fn accept(socket: c_int, address: *mut SockAddr, length: *mut u32) -> c_int;
    fn connect(socket: c_int, address: *const SockAddr, length: u32) -> c_int;
    fn getsockname(socket: c_int, address: *mut SockAddr, length: *mut u32) -> c_int;
    fn recvfrom(
        socket: c_int,
        buffer: *mut c_void,
        length: usize,
        flags: c_int,
        address: *mut SockAddr,
        address_length: *mut u32,
    ) -> isize;
    fn sendto(
        socket: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const SockAddr,
        address_length: u32,
    ) -> isize;
    fn setsockopt(
        socket: c_int,
        level: c_int,
        name: c_int,
        value: *const c_void,
        length: u32,
    ) -> c_int;
    fn getsockopt(
        socket: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        length: *mut u32,
    ) -> c_int;
    fn pthread_create(
        thread: *mut usize,
        attributes: *const PthreadAttr,
        start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        argument: *mut c_void,
    ) -> c_int;
    fn pthread_join(thread: usize, result: *mut *mut c_void) -> c_int;
    fn pthread_attr_init(attributes: *mut PthreadAttr) -> c_int;
    fn pthread_attr_setdetachstate(attributes: *mut PthreadAttr, state: c_int) -> c_int;
    fn pthread_attr_destroy(attributes: *mut PthreadAttr) -> c_int;
    fn sysconf(name: c_int) -> c_long;
    fn sched_yield() -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn getrandom(buffer: *mut c_void, length: usize, flags: u32) -> isize;
    fn getaddrinfo(
        node: *const i8,
        service: *const i8,
        hints: *const AddrInfo,
        result: *mut *mut AddrInfo,
    ) -> c_int;
    fn freeaddrinfo(result: *mut AddrInfo);
}

#[cfg(unix)]
pub fn fill_random(mut output: &mut [u8]) -> bool {
    while !output.is_empty() {
        let read = unsafe { getrandom(output.as_mut_ptr().cast(), output.len(), 0) };
        if read <= 0 {
            output.fill(0);
            return false;
        }
        output = &mut output[read as usize..];
    }
    true
}

#[repr(C)]
#[cfg(unix)]
struct SockAddr {
    family: u16,
    port: [u8; 2],
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[cfg(unix)]
struct AddrInfo {
    flags: c_int,
    family: c_int,
    socket_type: c_int,
    protocol: c_int,
    address_length: u32,
    address: *mut SockAddr,
    canonical_name: *mut i8,
    next: *mut AddrInfo,
}

#[cfg(unix)]
pub fn resolve_ipv4(host: &[u8]) -> Option<[u8; 4]> {
    if host.last().copied() != Some(0) {
        return None;
    }
    let hints = AddrInfo {
        flags: 0,
        family: 2,
        socket_type: 1,
        protocol: 6,
        address_length: 0,
        address: core::ptr::null_mut(),
        canonical_name: core::ptr::null_mut(),
        next: core::ptr::null_mut(),
    };
    let mut result = core::ptr::null_mut();
    if unsafe { getaddrinfo(host.as_ptr().cast(), core::ptr::null(), &hints, &mut result) } != 0
        || result.is_null()
    {
        return None;
    }
    let address = unsafe { (*result).address.as_ref() }.map(|value| value.address);
    unsafe { freeaddrinfo(result) };
    address
}

#[repr(C)]
#[cfg(unix)]
struct TimeVal {
    seconds: isize,
    microseconds: isize,
}

#[repr(C)]
#[cfg(unix)]
struct Dirent {
    inode: u64,
    offset: i64,
    record_length: u16,
    kind: u8,
    name: [i8; 256],
}

#[cfg(unix)]
pub fn processor_count() -> usize {
    const SC_NPROCESSORS_ONLN: c_int = 84;
    unsafe { sysconf(SC_NPROCESSORS_ONLN) }.max(1) as usize
}

#[cfg(unix)]
pub fn process_id() -> u32 {
    (unsafe { getpid() }) as u32
}

#[cfg(unix)]
pub fn unix_time_seconds() -> Option<u64> {
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    (unsafe { clock_gettime(0, &mut value) } == 0 && value.seconds >= 0)
        .then_some(value.seconds as u64)
}

#[cfg(unix)]
fn socket_address(ip: [u8; 4], port: u16) -> SockAddr {
    SockAddr {
        family: 2,
        port: port.to_be_bytes(),
        address: ip,
        zero: [0; 8],
    }
}

#[cfg(unix)]
pub struct NativeTcpListener(c_int);

#[cfg(unix)]
impl NativeTcpListener {
    pub fn bind(ip: [u8; 4], port: u16) -> Option<Self> {
        let handle = unsafe { socket(2, 1, 0) };
        if handle < 0 {
            return None;
        }
        let address = socket_address(ip, port);
        if unsafe { bind(handle, &address, core::mem::size_of::<SockAddr>() as u32) } != 0
            || unsafe { listen(handle, 128) } != 0
        {
            let _ = unsafe { close(handle) };
            return None;
        }
        Some(Self(handle))
    }

    pub fn local_port(&self) -> Option<u16> {
        let mut address = socket_address([0; 4], 0);
        let mut length = core::mem::size_of::<SockAddr>() as u32;
        (unsafe { getsockname(self.0, &mut address, &mut length) } == 0)
            .then(|| u16::from_be_bytes(address.port))
    }

    pub fn accept(&self) -> Option<NativeTcpStream> {
        let handle = unsafe { accept(self.0, core::ptr::null_mut(), core::ptr::null_mut()) };
        (handle >= 0).then_some(NativeTcpStream(handle))
    }
}

#[cfg(unix)]
impl Drop for NativeTcpListener {
    fn drop(&mut self) {
        let _ = unsafe { close(self.0) };
    }
}

#[cfg(unix)]
pub struct NativeUdpSocket(c_int);

#[cfg(unix)]
unsafe impl Send for NativeUdpSocket {}

#[cfg(unix)]
impl NativeUdpSocket {
    pub fn bind(ip: [u8; 4], port: u16) -> Option<Self> {
        let handle = unsafe { socket(2, 2, 17) };
        if handle < 0 {
            return None;
        }
        let address = socket_address(ip, port);
        if unsafe { bind(handle, &address, core::mem::size_of::<SockAddr>() as u32) } != 0 {
            let _ = unsafe { close(handle) };
            return None;
        }
        Some(Self(handle))
    }

    pub fn local_port(&self) -> Option<u16> {
        let mut address = socket_address([0; 4], 0);
        let mut length = core::mem::size_of::<SockAddr>() as u32;
        (unsafe { getsockname(self.0, &mut address, &mut length) } == 0)
            .then(|| u16::from_be_bytes(address.port))
    }

    pub fn receive_from(&self, buffer: &mut [u8]) -> Option<(usize, [u8; 4], u16)> {
        let mut address = socket_address([0; 4], 0);
        let mut length = core::mem::size_of::<SockAddr>() as u32;
        let amount = unsafe {
            recvfrom(
                self.0,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                &mut address,
                &mut length,
            )
        };
        (amount >= 0 && length as usize >= core::mem::size_of::<SockAddr>()).then(|| {
            (
                amount as usize,
                address.address,
                u16::from_be_bytes(address.port),
            )
        })
    }

    pub fn send_to(&self, buffer: &[u8], ip: [u8; 4], port: u16) -> Option<usize> {
        let address = socket_address(ip, port);
        let amount = unsafe {
            sendto(
                self.0,
                buffer.as_ptr().cast(),
                buffer.len(),
                0,
                &address,
                core::mem::size_of::<SockAddr>() as u32,
            )
        };
        (amount >= 0).then_some(amount as usize)
    }

    pub fn set_timeout_millis(&self, read_timeout: bool, milliseconds: u64) -> bool {
        let value = TimeVal {
            seconds: (milliseconds / 1000) as isize,
            microseconds: ((milliseconds % 1000) * 1000) as isize,
        };
        let option = if read_timeout { 20 } else { 21 };
        (unsafe {
            setsockopt(
                self.0,
                1,
                option,
                (&value as *const TimeVal).cast(),
                core::mem::size_of::<TimeVal>() as u32,
            )
        }) == 0
    }
}

#[cfg(unix)]
impl Drop for NativeUdpSocket {
    fn drop(&mut self) {
        let _ = unsafe { close(self.0) };
    }
}

#[cfg(unix)]
pub struct NativeTcpStream(c_int);

#[cfg(unix)]
unsafe impl Send for NativeTcpStream {}

#[cfg(unix)]
impl NativeTcpStream {
    pub fn connect(ip: [u8; 4], port: u16) -> Option<Self> {
        let handle = unsafe { socket(2, 1, 0) };
        if handle < 0 {
            return None;
        }
        let address = socket_address(ip, port);
        if unsafe { connect(handle, &address, core::mem::size_of::<SockAddr>() as u32) } != 0 {
            let _ = unsafe { close(handle) };
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> Option<usize> {
        let amount = unsafe { read(self.0, buffer.as_mut_ptr().cast(), buffer.len()) };
        (amount >= 0).then_some(amount as usize)
    }

    pub fn write(&mut self, buffer: &[u8]) -> Option<usize> {
        let amount = unsafe { write(self.0, buffer.as_ptr().cast(), buffer.len()) };
        (amount >= 0).then_some(amount as usize)
    }

    pub fn set_timeout_millis(&self, read_timeout: bool, milliseconds: u64) -> bool {
        let value = TimeVal {
            seconds: (milliseconds / 1000) as isize,
            microseconds: ((milliseconds % 1000) * 1000) as isize,
        };
        let option = if read_timeout { 20 } else { 21 };
        (unsafe {
            setsockopt(
                self.0,
                1,
                option,
                (&value as *const TimeVal).cast(),
                core::mem::size_of::<TimeVal>() as u32,
            )
        }) == 0
    }
}

#[cfg(unix)]
impl Drop for NativeTcpStream {
    fn drop(&mut self) {
        let _ = unsafe { close(self.0) };
    }
}

#[repr(C)]
#[cfg(unix)]
struct SockAddrUnix {
    family: u16,
    path: [u8; 108],
}

#[repr(C)]
#[cfg(unix)]
struct PeerCredentials {
    pid: c_int,
    uid: u32,
    gid: u32,
}

/// Linux AF_UNIX client used by no-std capability transports.
#[cfg(unix)]
pub struct NativeUnixStream(c_int);

#[cfg(unix)]
unsafe impl Send for NativeUnixStream {}

#[cfg(unix)]
impl NativeUnixStream {
    pub fn connect_path(path: &[u8]) -> Option<Self> {
        if path.is_empty() || path.len() > 107 || path.contains(&0) {
            return None;
        }
        let handle = unsafe { socket(1, 1, 0) };
        if handle < 0 {
            return None;
        }
        let mut address = SockAddrUnix {
            family: 1,
            path: [0; 108],
        };
        address.path[..path.len()].copy_from_slice(path);
        let length = u32::try_from(2 + path.len() + 1).ok()?;
        if unsafe { connect(handle, (&address as *const SockAddrUnix).cast(), length) } != 0 {
            let _ = unsafe { close(handle) };
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn peer_credentials(&self) -> Option<(u32, u32)> {
        let mut credentials = PeerCredentials { pid: 0, uid: 0, gid: 0 };
        let mut length = core::mem::size_of::<PeerCredentials>() as u32;
        let result = unsafe {
            getsockopt(
                self.0,
                1,
                17,
                (&mut credentials as *mut PeerCredentials).cast(),
                &mut length,
            )
        };
        (result == 0 && length as usize == core::mem::size_of::<PeerCredentials>())
            .then_some((credentials.uid, credentials.gid))
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> Option<usize> {
        let amount = unsafe { read(self.0, buffer.as_mut_ptr().cast(), buffer.len()) };
        (amount >= 0).then_some(amount as usize)
    }

    pub fn write(&mut self, buffer: &[u8]) -> Option<usize> {
        let amount = unsafe { write(self.0, buffer.as_ptr().cast(), buffer.len()) };
        (amount >= 0).then_some(amount as usize)
    }

    pub fn set_timeout_millis(&self, read_timeout: bool, milliseconds: u64) -> bool {
        let value = TimeVal {
            seconds: (milliseconds / 1000) as isize,
            microseconds: ((milliseconds % 1000) * 1000) as isize,
        };
        let option = if read_timeout { 20 } else { 21 };
        (unsafe {
            setsockopt(
                self.0,
                1,
                option,
                (&value as *const TimeVal).cast(),
                core::mem::size_of::<TimeVal>() as u32,
            )
        }) == 0
    }
}

#[cfg(unix)]
impl Drop for NativeUnixStream {
    fn drop(&mut self) {
        let _ = unsafe { close(self.0) };
    }
}

#[cfg(unix)]
pub fn spawn_detached_process(
    program: &CStr,
    arguments: &[*const i8],
    current_directory: Option<&CStr>,
) -> bool {
    let process = unsafe { fork() };
    if process == 0 {
        let detached = unsafe { fork() };
        if detached < 0 {
            unsafe { _exit(125) };
        }
        if detached > 0 {
            unsafe { _exit(0) };
        }
        if let Some(directory) = current_directory {
            if unsafe { chdir(directory.as_ptr()) } != 0 {
                unsafe { _exit(126) };
            }
        }
        let _ = unsafe { execvp(program.as_ptr(), arguments.as_ptr()) };
        unsafe { _exit(127) };
    }
    if process < 0 {
        return false;
    }
    let mut status = 0;
    (unsafe { waitpid(process, &mut status, 0) }) == process && status == 0
}

#[cfg(unix)]
pub struct NativeChild {
    process: c_int,
    stdout: c_int,
    stderr: c_int,
    status: Option<i32>,
}

#[cfg(unix)]
impl NativeChild {
    pub fn spawn_silent(
        program: &CStr,
        arguments: &[*const i8],
        current_directory: Option<&CStr>,
    ) -> Option<Self> {
        const O_RDWR: c_int = 2;
        let null_file = unsafe { open(c"/dev/null".as_ptr(), O_RDWR) };
        if null_file < 0 {
            return None;
        }
        let process = unsafe { fork() };
        if process == 0 {
            let _ = unsafe { dup2(null_file, 0) };
            let _ = unsafe { dup2(null_file, 1) };
            let _ = unsafe { dup2(null_file, 2) };
            let _ = unsafe { close(null_file) };
            if let Some(directory) = current_directory {
                if unsafe { chdir(directory.as_ptr()) } != 0 {
                    unsafe { _exit(126) };
                }
            }
            let _ = unsafe { execvp(program.as_ptr(), arguments.as_ptr()) };
            unsafe { _exit(127) };
        }
        let _ = unsafe { close(null_file) };
        (process > 0).then_some(Self {
            process,
            stdout: -1,
            stderr: -1,
            status: None,
        })
    }

    pub fn spawn_captured(
        program: &CStr,
        arguments: &[*const i8],
        current_directory: Option<&CStr>,
    ) -> Option<Self> {
        let mut stdout_pipe = [-1; 2];
        let mut stderr_pipe = [-1; 2];
        if unsafe { pipe(stdout_pipe.as_mut_ptr()) } != 0
            || unsafe { pipe(stderr_pipe.as_mut_ptr()) } != 0
        {
            for file in stdout_pipe.into_iter().chain(stderr_pipe) {
                if file >= 0 {
                    let _ = unsafe { close(file) };
                }
            }
            return None;
        }
        let process = unsafe { fork() };
        if process == 0 {
            let _ = unsafe { close(stdout_pipe[0]) };
            let _ = unsafe { close(stderr_pipe[0]) };
            let _ = unsafe { dup2(stdout_pipe[1], 1) };
            let _ = unsafe { dup2(stderr_pipe[1], 2) };
            let _ = unsafe { close(stdout_pipe[1]) };
            let _ = unsafe { close(stderr_pipe[1]) };
            if let Some(directory) = current_directory {
                if unsafe { chdir(directory.as_ptr()) } != 0 {
                    unsafe { _exit(126) };
                }
            }
            let _ = unsafe { execvp(program.as_ptr(), arguments.as_ptr()) };
            unsafe { _exit(127) };
        }
        let _ = unsafe { close(stdout_pipe[1]) };
        let _ = unsafe { close(stderr_pipe[1]) };
        if process < 0 {
            let _ = unsafe { close(stdout_pipe[0]) };
            let _ = unsafe { close(stderr_pipe[0]) };
            return None;
        }
        const F_SETFL: c_int = 4;
        const O_NONBLOCK: c_int = 0o4000;
        let _ = unsafe { fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK) };
        let _ = unsafe { fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK) };
        Some(Self {
            process,
            stdout: stdout_pipe[0],
            stderr: stderr_pipe[0],
            status: None,
        })
    }

    fn read_pipe(file: c_int, buffer: &mut [u8]) -> usize {
        let read = unsafe { read(file, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read > 0 { read as usize } else { 0 }
    }

    pub fn read_stdout(&mut self, buffer: &mut [u8]) -> usize {
        Self::read_pipe(self.stdout, buffer)
    }

    pub fn read_stderr(&mut self, buffer: &mut [u8]) -> usize {
        Self::read_pipe(self.stderr, buffer)
    }

    pub fn try_wait(&mut self) -> Option<i32> {
        if let Some(status) = self.status {
            return Some(status);
        }
        let mut status = 0;
        const WNOHANG: c_int = 1;
        if unsafe { waitpid(self.process, &mut status, WNOHANG) } == self.process {
            let code = if status & 0x7f == 0 {
                (status >> 8) & 0xff
            } else {
                128 + (status & 0x7f)
            };
            self.status = Some(code);
        }
        self.status
    }

    pub fn kill(&mut self) -> bool {
        self.status.is_some() || unsafe { kill(self.process, 9) } == 0
    }

    pub fn wait(&mut self) -> Option<i32> {
        if let Some(status) = self.status {
            return Some(status);
        }
        let mut status = 0;
        if unsafe { waitpid(self.process, &mut status, 0) } != self.process {
            return None;
        }
        let code = if status & 0x7f == 0 {
            (status >> 8) & 0xff
        } else {
            128 + (status & 0x7f)
        };
        self.status = Some(code);
        Some(code)
    }
}

#[cfg(unix)]
impl Drop for NativeChild {
    fn drop(&mut self) {
        if self.stdout >= 0 {
            let _ = unsafe { close(self.stdout) };
        }
        if self.stderr >= 0 {
            let _ = unsafe { close(self.stderr) };
        }
        if self.status.is_none() {
            let mut status = 0;
            let _ = unsafe { waitpid(self.process, &mut status, 0) };
        }
    }
}

#[cfg(unix)]
pub struct NativePipedChild {
    process: c_int,
    stdin: c_int,
    stdout: c_int,
    status: Option<i32>,
}

#[cfg(unix)]
impl NativePipedChild {
    pub fn spawn(
        program: &CStr,
        arguments: &[*const i8],
        current_directory: Option<&CStr>,
    ) -> Option<Self> {
        let mut stdin_pipe = [-1; 2];
        let mut stdout_pipe = [-1; 2];
        if unsafe { pipe(stdin_pipe.as_mut_ptr()) } != 0
            || unsafe { pipe(stdout_pipe.as_mut_ptr()) } != 0
        {
            for file in stdin_pipe.into_iter().chain(stdout_pipe) {
                if file >= 0 {
                    let _ = unsafe { close(file) };
                }
            }
            return None;
        }
        let process = unsafe { fork() };
        if process == 0 {
            let _ = unsafe { close(stdin_pipe[1]) };
            let _ = unsafe { close(stdout_pipe[0]) };
            let _ = unsafe { dup2(stdin_pipe[0], 0) };
            let _ = unsafe { dup2(stdout_pipe[1], 1) };
            let _ = unsafe { close(stdin_pipe[0]) };
            let _ = unsafe { close(stdout_pipe[1]) };
            if let Some(directory) = current_directory {
                if unsafe { chdir(directory.as_ptr()) } != 0 {
                    unsafe { _exit(126) };
                }
            }
            let _ = unsafe { execvp(program.as_ptr(), arguments.as_ptr()) };
            unsafe { _exit(127) };
        }
        let _ = unsafe { close(stdin_pipe[0]) };
        let _ = unsafe { close(stdout_pipe[1]) };
        if process < 0 {
            let _ = unsafe { close(stdin_pipe[1]) };
            let _ = unsafe { close(stdout_pipe[0]) };
            return None;
        }
        Some(Self {
            process,
            stdin: stdin_pipe[1],
            stdout: stdout_pipe[0],
            status: None,
        })
    }

    pub fn write_stdin(&mut self, bytes: &[u8]) -> bool {
        write_descriptor(self.stdin, bytes)
    }

    pub fn read_stdout(&mut self, buffer: &mut [u8]) -> Option<usize> {
        let amount = unsafe { read(self.stdout, buffer.as_mut_ptr().cast(), buffer.len()) };
        (amount >= 0).then_some(amount as usize)
    }

    pub fn kill(&mut self) -> bool {
        self.status.is_some() || unsafe { kill(self.process, 9) } == 0
    }

    pub fn wait(&mut self) -> Option<i32> {
        if let Some(status) = self.status {
            return Some(status);
        }
        let mut status = 0;
        if unsafe { waitpid(self.process, &mut status, 0) } != self.process {
            return None;
        }
        let code = if status & 0x7f == 0 {
            (status >> 8) & 0xff
        } else {
            128 + (status & 0x7f)
        };
        self.status = Some(code);
        Some(code)
    }
}

#[cfg(unix)]
impl Drop for NativePipedChild {
    fn drop(&mut self) {
        let _ = unsafe { close(self.stdin) };
        let _ = unsafe { close(self.stdout) };
        if self.status.is_none() {
            let _ = self.kill();
            let _ = self.wait();
        }
    }
}

#[cfg(unix)]
pub fn yield_now() {
    let _ = unsafe { sched_yield() };
}

#[cfg(all(unix, target_arch = "x86_64"))]
const SYS_FUTEX: c_long = 202;
#[cfg(all(unix, target_arch = "aarch64"))]
const SYS_FUTEX: c_long = 98;

#[cfg(unix)]
pub fn wait_on_u32(address: *const u32, expected: u32) {
    const FUTEX_WAIT_PRIVATE: c_int = 128;
    let _ = unsafe {
        syscall(
            SYS_FUTEX,
            address,
            FUTEX_WAIT_PRIVATE,
            expected,
            core::ptr::null::<Timespec>(),
        )
    };
}

#[cfg(unix)]
pub fn wake_one_u32(address: *const u32) {
    const FUTEX_WAKE_PRIVATE: c_int = 129;
    let _ = unsafe { syscall(SYS_FUTEX, address, FUTEX_WAKE_PRIVATE, 1) };
}

#[cfg(unix)]
pub fn wake_all_u32(address: *const u32) {
    const FUTEX_WAKE_PRIVATE: c_int = 129;
    let _ = unsafe { syscall(SYS_FUTEX, address, FUTEX_WAKE_PRIVATE, i32::MAX) };
}

#[cfg(unix)]
pub unsafe fn spawn_detached_thread(
    context: *mut c_void,
    start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
) -> bool {
    const PTHREAD_CREATE_DETACHED: c_int = 1;
    let mut attributes = core::mem::MaybeUninit::<PthreadAttr>::uninit();
    if unsafe { pthread_attr_init(attributes.as_mut_ptr()) } != 0 {
        return false;
    }
    let attributes = unsafe { attributes.assume_init_mut() };
    if unsafe { pthread_attr_setdetachstate(attributes, PTHREAD_CREATE_DETACHED) } != 0 {
        let _ = unsafe { pthread_attr_destroy(attributes) };
        return false;
    }
    let mut thread = 0usize;
    let created = unsafe { pthread_create(&mut thread, attributes, start, context) } == 0;
    let _ = unsafe { pthread_attr_destroy(attributes) };
    created
}

#[cfg(unix)]
pub struct NativeThread(Option<usize>);

#[cfg(unix)]
unsafe impl Send for NativeThread {}

#[cfg(unix)]
impl NativeThread {
    pub fn join(mut self) -> bool {
        self.join_inner()
    }

    fn join_inner(&mut self) -> bool {
        let Some(thread) = self.0 else {
            return true;
        };
        if unsafe { pthread_join(thread, core::ptr::null_mut()) } != 0 {
            return false;
        }
        self.0 = None;
        true
    }
}

#[cfg(unix)]
impl Drop for NativeThread {
    fn drop(&mut self) {
        // An unconfirmed worker may still be using resources borrowed by its
        // closure. Fail-stop here instead of allowing those resources to drop.
        while !self.join_inner() {
            yield_now();
        }
    }
}

#[cfg(unix)]
pub unsafe fn spawn_joinable_thread(
    context: *mut c_void,
    start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
) -> Option<NativeThread> {
    let mut thread = 0usize;
    (unsafe { pthread_create(&mut thread, core::ptr::null(), start, context) } == 0)
        .then_some(NativeThread(Some(thread)))
}

#[derive(Debug)]
#[cfg(unix)]
pub struct NativeFile(c_int);

#[cfg(unix)]
impl NativeFile {
    pub fn open_read(path: &CStr) -> Option<Self> {
        let file = unsafe { open(path.as_ptr(), 0) };
        (file >= 0).then_some(Self(file))
    }

    pub fn create_write(path: &CStr) -> Option<Self> {
        const O_WRONLY: c_int = 1;
        const O_CREAT: c_int = 64;
        const O_TRUNC: c_int = 512;
        let file = unsafe { open(path.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o666) };
        (file >= 0).then_some(Self(file))
    }

    pub fn create_new_write(path: &CStr) -> Option<Self> {
        const O_WRONLY: c_int = 1;
        const O_CREAT: c_int = 64;
        const O_EXCL: c_int = 128;
        const O_NOFOLLOW: c_int = 0x2_0000;
        const O_CLOEXEC: c_int = 0x8_0000;
        let file = unsafe {
            open(
                path.as_ptr(),
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o666,
            )
        };
        let file = (file >= 0).then_some(Self(file))?;
        file.is_regular().then_some(file)
    }

    pub fn open_regular_read(path: &CStr) -> Option<Self> {
        const O_RDONLY: c_int = 0;
        const O_NOFOLLOW: c_int = 0x2_0000;
        const O_CLOEXEC: c_int = 0x8_0000;
        let file = unsafe { open(path.as_ptr(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC) };
        let file = (file >= 0).then_some(Self(file))?;
        file.is_regular().then_some(file)
    }

    pub fn create_secret(path: &CStr) -> Option<Self> {
        const O_WRONLY: c_int = 1;
        const O_CREAT: c_int = 64;
        const O_EXCL: c_int = 128;
        const O_NOFOLLOW: c_int = 0x2_0000;
        const O_CLOEXEC: c_int = 0x8_0000;
        let file = unsafe {
            open(
                path.as_ptr(),
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600,
            )
        };
        let file = (file >= 0).then_some(Self(file))?;
        if !file.is_regular() || !file.has_owner_only_permissions() {
            return None;
        }
        Some(file)
    }

    pub fn sync(&self) -> bool {
        (unsafe { fsync(self.0) }) == 0
    }

    pub fn is_regular(&self) -> bool {
        let mut status = core::mem::MaybeUninit::<Stat>::uninit();
        (unsafe { fstat(self.0, status.as_mut_ptr()) }) == 0
            && (unsafe { status.assume_init() }.mode & 0o170000) == 0o100000
    }

    pub fn has_owner_only_permissions(&self) -> bool {
        let mut status = core::mem::MaybeUninit::<Stat>::uninit();
        (unsafe { fstat(self.0, status.as_mut_ptr()) }) == 0
            && (unsafe { status.assume_init() }.mode & 0o777) == 0o600
    }

    pub fn has_private_read_permissions(&self) -> bool {
        let mut status = core::mem::MaybeUninit::<Stat>::uninit();
        if (unsafe { fstat(self.0, status.as_mut_ptr()) }) != 0 {
            return false;
        }
        matches!(unsafe { status.assume_init() }.mode & 0o777, 0o400 | 0o600)
    }

    pub fn is_owned_by_effective_user(&self) -> bool {
        let mut status = core::mem::MaybeUninit::<Stat>::uninit();
        (unsafe { fstat(self.0, status.as_mut_ptr()) }) == 0
            && unsafe { status.assume_init() }.uid == unsafe { geteuid() }
    }

    pub fn open_write(path: &CStr) -> Option<Self> {
        const O_WRONLY: c_int = 1;
        let file = unsafe { open(path.as_ptr(), O_WRONLY) };
        (file >= 0).then_some(Self(file))
    }

    pub fn read(&self, buffer: &mut [u8]) -> Option<usize> {
        let read = unsafe { read(self.0, buffer.as_mut_ptr().cast(), buffer.len()) };
        (read >= 0).then_some(read as usize)
    }

    pub fn write(&self, buffer: &[u8]) -> Option<usize> {
        let result = unsafe { write(self.0, buffer.as_ptr().cast(), buffer.len()) };
        (result >= 0).then_some(result as usize)
    }

    pub fn seek_absolute(&self, position: u64) -> bool {
        position <= isize::MAX as u64 && unsafe { lseek(self.0, position as isize, 0) } >= 0
    }

    pub fn len(&self) -> Option<u64> {
        let current = unsafe { lseek(self.0, 0, 1) };
        if current < 0 {
            return None;
        }
        let end = unsafe { lseek(self.0, 0, 2) };
        let _ = unsafe { lseek(self.0, current, 0) };
        (end >= 0).then_some(end as u64)
    }

    pub fn raw_fd(&self) -> c_int {
        self.0
    }
}

#[cfg(unix)]
impl Drop for NativeFile {
    fn drop(&mut self) {
        let _ = unsafe { close(self.0) };
    }
}

#[cfg(unix)]
pub fn stdout_is_terminal() -> bool {
    (unsafe { isatty(1) }) == 1
}

#[cfg(unix)]
fn write_descriptor(file: c_int, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        let written = unsafe { write(file, bytes.as_ptr().cast(), bytes.len()) };
        if written <= 0 {
            return false;
        }
        bytes = &bytes[written as usize..];
    }
    true
}

#[cfg(unix)]
pub fn write_stdout(bytes: &[u8]) -> bool {
    write_descriptor(1, bytes)
}

#[cfg(unix)]
pub fn write_stderr(bytes: &[u8]) -> bool {
    write_descriptor(2, bytes)
}

#[cfg(unix)]
pub fn read_stdin(buffer: &mut [u8]) -> Option<usize> {
    let result = unsafe { read(0, buffer.as_mut_ptr().cast(), buffer.len()) };
    (result >= 0).then_some(result as usize)
}

#[cfg(unix)]
pub fn environment_variable_is_set(name: &CStr) -> bool {
    !unsafe { getenv(name.as_ptr()) }.is_null()
}

#[cfg(unix)]
pub fn environment_variable_equals(name: &CStr, expected: &[u8]) -> bool {
    let value = unsafe { getenv(name.as_ptr()) };
    if value.is_null() {
        return false;
    }
    unsafe { CStr::from_ptr(value) }.to_bytes() == expected
}

#[cfg(unix)]
pub fn environment_variable_bytes(name: &CStr, value: &mut [u8]) -> Result<usize, usize> {
    let pointer = unsafe { getenv(name.as_ptr()) };
    if pointer.is_null() {
        return Err(0);
    }
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if bytes.len() > value.len() {
        return Err(bytes.len());
    }
    value[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

#[cfg(unix)]
pub fn path_is_directory(path: &CStr) -> bool {
    const O_RDONLY: c_int = 0;
    const O_DIRECTORY: c_int = 0o200000;
    let file = unsafe { open(path.as_ptr(), O_RDONLY | O_DIRECTORY) };
    if file < 0 {
        false
    } else {
        let _ = unsafe { close(file) };
        true
    }
}

#[cfg(unix)]
pub fn path_is_file(path: &CStr) -> bool {
    NativeFile::open_read(path).is_some_and(|file| file.is_regular())
}

#[cfg(unix)]
pub fn canonical_path<'a>(path: &CStr, output: &'a mut [u8; 4096]) -> Option<&'a [u8]> {
    NonNull::new(unsafe { realpath(path.as_ptr(), output.as_mut_ptr().cast()) })?;
    let length = output.iter().position(|byte| *byte == 0)?;
    Some(&output[..length])
}

#[cfg(unix)]
pub fn create_directory(path: &CStr) -> bool {
    (unsafe { mkdir(path.as_ptr(), 0o777) }) == 0 || path_is_directory(path)
}

#[cfg(unix)]
pub fn delete_file(path: &CStr) -> bool {
    (unsafe { unlink(path.as_ptr()) }) == 0
}

#[cfg(unix)]
pub fn remove_directory(path: &CStr) -> bool {
    (unsafe { rmdir(path.as_ptr()) }) == 0
}

#[cfg(unix)]
pub fn rename_file(existing: &CStr, replacement: &CStr) -> bool {
    (unsafe { rename(existing.as_ptr(), replacement.as_ptr()) }) == 0
}

#[cfg(unix)]
pub struct NativeDirectory(*mut c_void);

// SAFETY: Directory iteration requires `&mut self`; descriptor-relative opens,
// metadata, and sync do not mutate Rust-visible state. libc directory streams
// may therefore be transferred and shared under those method-level bounds.
unsafe impl Send for NativeDirectory {}
unsafe impl Sync for NativeDirectory {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFileMetadata {
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u64,
    pub device: u64,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(unix)]
impl NativeDirectory {
    pub fn open(path: &CStr) -> Option<Self> {
        NonNull::new(unsafe { opendir(path.as_ptr()) }).map(|directory| Self(directory.as_ptr()))
    }

    /// Opens a configured absolute root without following any symlink component.
    pub fn open_root(path: &CStr) -> Option<Self> {
        const SYS_OPENAT2_X86_64: c_long = 437;
        const AT_FDCWD: c_int = -100;
        const O_RDONLY: u64 = 0;
        const O_DIRECTORY: u64 = 0o200000;
        const O_NOFOLLOW: u64 = 0x2_0000;
        const O_CLOEXEC: u64 = 0x8_0000;
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        if path.to_bytes().first() != Some(&b'/') {
            return None;
        }
        let how = OpenHow {
            flags: O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        // SAFETY: the immutable C string and ABI-layout `OpenHow` remain live
        // for the syscall. `from_descriptor` owns or closes the result.
        let descriptor = unsafe {
            syscall(
                SYS_OPENAT2_X86_64,
                AT_FDCWD,
                path.as_ptr(),
                &how as *const OpenHow,
                core::mem::size_of::<OpenHow>(),
            )
        };
        if descriptor < 0 || descriptor > c_int::MAX as c_long {
            return None;
        }
        Self::from_descriptor(descriptor as c_int)
    }

    /// Resolves a relative directory beneath this retained descriptor.
    ///
    /// This is the only `openat2` syscall boundary. The fixed flags reject
    /// absolute paths, `..`, symlinks, magic links, and mount crossings before
    /// a descriptor can escape the caller's retained root.
    pub fn open_beneath(&self, path: &CStr) -> Option<Self> {
        const SYS_OPENAT2_X86_64: c_long = 437;
        const O_RDONLY: u64 = 0;
        const O_DIRECTORY: u64 = 0o200000;
        const O_NOFOLLOW: u64 = 0x2_0000;
        const O_CLOEXEC: u64 = 0x8_0000;
        const RESOLVE_NO_XDEV: u64 = 0x01;
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        const RESOLVE_BENEATH: u64 = 0x08;
        if path.to_bytes().is_empty() || path.to_bytes().first() == Some(&b'/') {
            return None;
        }
        let how = OpenHow {
            flags: O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            mode: 0,
            resolve: RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS
                | RESOLVE_BENEATH,
        };
        let parent = unsafe { dirfd(self.0) };
        if parent < 0 {
            return None;
        }
        // SAFETY: `path` and `how` remain valid for the duration of the
        // syscall, `how` has the kernel ABI layout, and no returned descriptor
        // is exposed until fdopendir assumes ownership of it.
        let descriptor = unsafe {
            syscall(
                SYS_OPENAT2_X86_64,
                parent,
                path.as_ptr(),
                &how as *const OpenHow,
                core::mem::size_of::<OpenHow>(),
            )
        };
        if descriptor < 0 || descriptor > c_int::MAX as c_long {
            return None;
        }
        Self::from_descriptor(descriptor as c_int)
    }

    fn from_descriptor(descriptor: c_int) -> Option<Self> {
        if descriptor < 0 {
            return None;
        }
        let directory = NonNull::new(unsafe { fdopendir(descriptor) });
        if directory.is_none() {
            let _ = unsafe { close(descriptor) };
        }
        directory.map(|directory| Self(directory.as_ptr()))
    }

    pub fn metadata(&self) -> Option<NativeFileMetadata> {
        let descriptor = unsafe { dirfd(self.0) };
        let mut status = core::mem::MaybeUninit::<Stat>::uninit();
        if descriptor < 0 || unsafe { fstat(descriptor, status.as_mut_ptr()) } != 0 {
            return None;
        }
        let status = unsafe { status.assume_init() };
        Some(NativeFileMetadata {
            inode: status.inode,
            mode: status.mode,
            uid: status.uid,
            gid: status.gid,
            links: status.links,
            device: status.device,
        })
    }

    pub fn next<'a>(&mut self, name: &'a mut [u8; 256]) -> Option<(&'a [u8], bool, bool)> {
        let entry = unsafe { readdir(self.0).as_ref()? };
        let len = entry.name.iter().position(|byte| *byte == 0)?;
        for (target, source) in name[..len].iter_mut().zip(&entry.name[..len]) {
            *target = *source as u8;
        }
        const DT_DIR: u8 = 4;
        const DT_LNK: u8 = 10;
        Some((&name[..len], entry.kind == DT_DIR, entry.kind == DT_LNK))
    }

    pub fn sync(&self) -> bool {
        let descriptor = unsafe { dirfd(self.0) };
        descriptor >= 0 && (unsafe { fsync(descriptor) }) == 0
    }
}

#[cfg(unix)]
impl Drop for NativeDirectory {
    fn drop(&mut self) {
        let _ = unsafe { closedir(self.0) };
    }
}

#[cfg(unix)]
pub fn exit_process(status: i32) -> ! {
    unsafe { _exit(status) }
}

#[cfg(unix)]
pub unsafe fn map_file_read_only(file: c_int, len: usize) -> Option<NonNull<u8>> {
    const PROT_READ: c_int = 1;
    const MAP_PRIVATE: c_int = 2;
    let view = unsafe { mmap(core::ptr::null_mut(), len, PROT_READ, MAP_PRIVATE, file, 0) };
    if view as isize == -1 {
        None
    } else {
        NonNull::new(view.cast())
    }
}

#[cfg(unix)]
pub unsafe fn unmap_file(address: NonNull<u8>, len: usize) -> bool {
    unsafe { munmap(address.as_ptr().cast(), len) == 0 }
}

#[derive(Debug)]
#[cfg(unix)]
pub struct DynamicLibrary(*mut c_void);

#[cfg(unix)]
unsafe impl Send for DynamicLibrary {}
#[cfg(unix)]
unsafe impl Sync for DynamicLibrary {}

#[cfg(unix)]
impl DynamicLibrary {
    pub fn open(name: &core::ffi::CStr) -> Option<Self> {
        const RTLD_NOW: c_int = 2;
        let handle = unsafe { dlopen(name.as_ptr(), RTLD_NOW) };
        (!handle.is_null()).then_some(Self(handle))
    }

    pub fn symbol(&self, name: &core::ffi::CStr) -> Option<*mut c_void> {
        let symbol = unsafe { dlsym(self.0, name.as_ptr()) };
        (!symbol.is_null()).then_some(symbol)
    }

    /// Invoke the stable CUDA driver bootstrap ABI when this is `libcuda`.
    pub fn initialize_cuda_driver(&self) -> bool {
        type Initialize = unsafe extern "C" fn(u32) -> i32;
        let Some(symbol) = self.symbol(c"cuInit") else {
            return false;
        };
        let initialize: Initialize = unsafe { core::mem::transmute(symbol) };
        unsafe { initialize(0) == 0 }
    }

    /// Query the stable NVENC bootstrap ABI when this is `libnvidia-encode`.
    pub fn nvenc_max_supported_version(&self) -> Option<u32> {
        type Query = unsafe extern "C" fn(*mut u32) -> i32;
        let symbol = self.symbol(c"NvEncodeAPIGetMaxSupportedVersion")?;
        let query: Query = unsafe { core::mem::transmute(symbol) };
        let mut version = 0;
        (unsafe { query(&mut version) } == 0).then_some(version)
    }
}

#[cfg(unix)]
impl Drop for DynamicLibrary {
    fn drop(&mut self) {
        let _ = unsafe { dlclose(self.0) };
    }
}

pub struct SystemAllocator;

#[cfg(unix)]
unsafe impl GlobalAlloc for SystemAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let alignment = layout.align().max(core::mem::size_of::<*mut c_void>());
        let mut pointer = core::ptr::null_mut();
        if unsafe { posix_memalign(&mut pointer, alignment, layout.size().max(1)) } != 0 {
            return core::ptr::null_mut();
        }
        pointer.cast()
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _: Layout) {
        unsafe { free(pointer.cast()) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(size, layout.align()) else {
            return core::ptr::null_mut();
        };
        let replacement = unsafe { self.alloc(new_layout) };
        if replacement.is_null() {
            return replacement;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(pointer, replacement, layout.size().min(size));
            self.dealloc(pointer, layout);
        }
        replacement
    }
}

#[cfg(unix)]
pub fn sleep_millis(milliseconds: u64) {
    let request = Timespec {
        seconds: (milliseconds / 1000) as c_long,
        nanoseconds: ((milliseconds % 1000) * 1_000_000) as c_long,
    };
    let _ = unsafe { nanosleep(&request, core::ptr::null_mut()) };
}

#[cfg(unix)]
pub fn monotonic_nanos() -> u64 {
    const CLOCK_MONOTONIC: c_int = 1;
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    if unsafe { clock_gettime(CLOCK_MONOTONIC, &mut value) } != 0 {
        return 0;
    }
    value.seconds as u64 * 1_000_000_000 + value.nanoseconds as u64
}

#[cfg(unix)]
pub fn unix_time_millis() -> u64 {
    const CLOCK_REALTIME: c_int = 0;
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    if unsafe { clock_gettime(CLOCK_REALTIME, &mut value) } != 0 {
        return 0;
    }
    value.seconds as u64 * 1000 + value.nanoseconds as u64 / 1_000_000
}

#[cfg(unix)]
pub fn local_time(epoch_seconds: i64) -> Option<LocalTime> {
    let seconds = epoch_seconds as c_long;
    let mut value = core::mem::MaybeUninit::<Tm>::uninit();
    // SAFETY: localtime_r initializes value or returns null.
    let result = unsafe { localtime_r(&seconds, value.as_mut_ptr()) };
    if result.is_null() {
        return None;
    }
    // SAFETY: a non-null return guarantees initialization.
    let value = unsafe { value.assume_init() };
    Some(LocalTime {
        year: (value.year + 1900) as u16,
        month: (value.month + 1) as u16,
        day: value.day as u16,
        weekday: value.weekday as u16,
        hour: value.hour as u16,
        minute: value.minute as u16,
        second: value.second as u16,
    })
}

#[cfg(not(unix))]
pub fn local_time(_: i64) -> Option<LocalTime> {
    None
}

#[cfg(not(unix))]
pub fn sleep_millis(_: u64) {}

#[cfg(not(unix))]
pub fn monotonic_nanos() -> u64 {
    0
}

#[cfg(not(unix))]
pub fn unix_time_millis() -> u64 {
    0
}

#[cfg(all(test, unix))]
mod tests {
    use core::alloc::{GlobalAlloc, Layout};

    #[test]
    fn pthread_attribute_layout_matches_linux_x86_64_abi() {
        assert_eq!(core::mem::size_of::<super::PthreadAttr>(), 56);
        assert_eq!(core::mem::align_of::<super::PthreadAttr>(), 8);
    }

    #[test]
    fn native_allocator_and_clock_work() {
        assert!(super::unix_time_millis() > 1_000_000_000_000);
        let layout = Layout::from_size_align(64, 8).unwrap();
        let pointer = unsafe { GlobalAlloc::alloc(&super::SystemAllocator, layout) };
        assert!(!pointer.is_null());
        unsafe {
            pointer.write(0x5a);
            assert_eq!(pointer.read(), 0x5a);
            GlobalAlloc::dealloc(&super::SystemAllocator, pointer, layout);
        }

        let before = super::monotonic_nanos();
        super::sleep_millis(2);
        assert!(super::monotonic_nanos() > before);
    }

    #[test]
    fn native_allocator_honors_alignment_and_preserves_reallocation() {
        for alignment in [32, 64, 256, 4096] {
            let layout = Layout::from_size_align(73, alignment).unwrap();
            let pointer = unsafe { GlobalAlloc::alloc(&super::SystemAllocator, layout) };
            assert!(!pointer.is_null());
            assert_eq!(pointer as usize % alignment, 0);
            unsafe { core::ptr::write_bytes(pointer, 0x5a, layout.size()) };
            let replacement =
                unsafe { GlobalAlloc::realloc(&super::SystemAllocator, pointer, layout, 211) };
            assert!(!replacement.is_null());
            assert_eq!(replacement as usize % alignment, 0);
            assert!(
                unsafe { core::slice::from_raw_parts(replacement, 73) }
                    .iter()
                    .all(|byte| *byte == 0x5a)
            );
            let replacement_layout = Layout::from_size_align(211, alignment).unwrap();
            unsafe {
                GlobalAlloc::dealloc(&super::SystemAllocator, replacement, replacement_layout)
            };
        }

        let zero = Layout::from_size_align(0, 4096).unwrap();
        let pointer = unsafe { GlobalAlloc::alloc(&super::SystemAllocator, zero) };
        assert!(!pointer.is_null());
        assert_eq!(pointer as usize % 4096, 0);
        unsafe { GlobalAlloc::dealloc(&super::SystemAllocator, pointer, zero) };
    }

    #[test]
    fn reads_process_environment_without_allocation() {
        assert!(super::environment_variable_is_set(c"PATH"));
        let _ = super::stdout_is_terminal();
    }

    #[test]
    fn loads_native_library_symbols() {
        let library = super::DynamicLibrary::open(c"libc.so.6").unwrap();
        assert!(library.symbol(c"getpid").is_some());
        assert!(library.symbol(c"definitely_missing_symbol").is_none());
    }

    #[test]
    fn maps_native_file_descriptor_read_only() {
        let path = c"mrml-linux-map-test.bin";
        let file = super::NativeFile::create_write(path).unwrap();
        assert_eq!(file.write(b"native mapping"), Some(14));
        drop(file);
        let file = super::NativeFile::open_read(path).unwrap();
        let mapping = unsafe { super::map_file_read_only(file.raw_fd(), 14) }.unwrap();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(mapping.as_ptr(), 14) },
            b"native mapping"
        );
        assert!(unsafe { super::unmap_file(mapping, 14) });
        drop(file);
        assert!(super::delete_file(path));
    }

    #[test]
    fn creates_owner_only_regular_secret_file() {
        let path = c"/tmp/mrml-linux-secret-test.bin";
        let _ = super::delete_file(path);
        let file = super::NativeFile::create_secret(path).unwrap();
        assert!(file.is_regular());
        assert!(file.has_owner_only_permissions());
        assert!(file.sync());
        drop(file);
        assert!(super::delete_file(path));
    }
}
