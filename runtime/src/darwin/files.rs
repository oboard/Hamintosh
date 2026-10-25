//! BSD file metadata calls resolve through the same guest-owned descriptor
//! table as open/close. Paths are composed from registered virtual paths and
//! the native layer confines their canonical targets to the extracted sysroot.
use super::{Process, TrapFrame};

const STAT64_SIZE: usize = 144;
const MAX_PATH: usize = 1024;
const AT_FDCWD: i32 = -2;
const EFAULT: u32 = 14;
const EINVAL: u32 = 22;
const ENOENT: u32 = 2;
const EBADF: u32 = 9;
const ENAMETOOLONG: u32 = 63;

fn read_path(process: &Process, address: u64, path: &mut [u8; MAX_PATH]) -> Result<usize, u32> {
    let read = process.copy_in.ok_or(EFAULT)?;
    for index in 0..MAX_PATH {
        if unsafe {
            read(
                process.host_context,
                address.wrapping_add(index as u64),
                path.as_mut_ptr().add(index),
                1,
            )
        } != 0
        {
            return Err(EFAULT);
        }
        if path[index] == 0 {
            return if index == 0 { Err(ENOENT) } else { Ok(index) };
        }
    }
    Err(ENAMETOOLONG)
}

fn rooted_relative_path(
    process: &Process,
    descriptor: u32,
    path: &[u8],
) -> Result<([u8; MAX_PATH], usize), u32> {
    let mut parent = [0u8; MAX_PATH];
    let parent_size = process.files.path(descriptor, &mut parent).ok_or(EBADF)?;
    let mut slash = parent_size - 1;
    if slash == 0 || parent[slash - 1] != b'/' {
        parent[slash] = b'/';
        slash += 1;
    }
    let size = slash
        .checked_add(path.len())
        .filter(|size| *size < MAX_PATH)
        .ok_or(ENAMETOOLONG)?;
    parent[slash..size].copy_from_slice(path);
    Ok((parent, size))
}

fn fstatat_path(
    process: &Process,
    descriptor: i32,
    path: &[u8],
) -> Result<([u8; MAX_PATH], usize), u32> {
    if path.first() == Some(&b'/') {
        let mut rooted = [0u8; MAX_PATH];
        rooted[..path.len()].copy_from_slice(path);
        return Ok((rooted, path.len()));
    }
    if descriptor == AT_FDCWD {
        let size = path
            .len()
            .checked_add(1)
            .filter(|size| *size < MAX_PATH)
            .ok_or(ENAMETOOLONG)?;
        let mut rooted = [0u8; MAX_PATH];
        rooted[0] = b'/';
        rooted[1..size].copy_from_slice(path);
        return Ok((rooted, size));
    }
    if descriptor < 0 {
        return Err(EBADF);
    }
    rooted_relative_path(process, descriptor as u32, path)
}

pub(super) fn stat(process: &Process, frame: &TrapFrame, number: i32) -> Option<u32> {
    let callback = process.file_stat?;
    let copy_out = process.copy_out?;
    let (parent, path, flags, output) = match number {
        338 => {
            let mut path = [0u8; MAX_PATH];
            let size = match read_path(process, frame.arguments[0], &mut path) {
                Ok(size) => size,
                Err(error) => return Some(error),
            };
            (-1, Some((path, size)), 0, frame.arguments[1])
        }
        339 => {
            let guest = match u32::try_from(frame.arguments[0]) {
                Ok(guest) => guest,
                Err(_) => return Some(EBADF),
            };
            let parent = match process.files.host(guest) {
                Some(parent) => parent,
                None => return Some(EBADF),
            };
            (parent, None, 0, frame.arguments[1])
        }
        470 => {
            let flags = frame.arguments[3];
            if flags != 0 {
                return Some(EINVAL);
            }
            let mut path = [0u8; MAX_PATH];
            let size = match read_path(process, frame.arguments[1], &mut path) {
                Ok(size) => size,
                Err(error) => return Some(error),
            };
            match fstatat_path(process, frame.arguments[0] as i32, &path[..size]) {
                Ok((path, size)) => (-1, Some((path, size)), flags as u32, frame.arguments[2]),
                Err(error) => return Some(error),
            }
        }
        _ => return None,
    };
    let mut bytes = [0u8; STAT64_SIZE];
    let (path_pointer, path_length) = path
        .as_ref()
        .map_or((std::ptr::null(), 0), |(path, size)| (path.as_ptr(), *size));
    let error = unsafe {
        callback(
            process.host_context,
            parent,
            path_pointer,
            path_length,
            flags,
            bytes.as_mut_ptr(),
            bytes.len(),
        )
    };
    if error != 0 {
        return Some(error);
    }
    let error = unsafe { copy_out(process.host_context, output, bytes.as_ptr(), bytes.len()) };
    Some(if error == 0 { 0 } else { EFAULT })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Host {
        path: [u8; 64],
        path_size: usize,
        expected: [u8; 64],
        expected_size: usize,
        output: [u8; STAT64_SIZE],
        parent: AtomicU32,
        flags: AtomicU32,
        calls: AtomicU32,
        error: u32,
    }

    impl Default for Host {
        fn default() -> Self {
            Self {
                path: [0; 64],
                path_size: 0,
                expected: [0; 64],
                expected_size: 0,
                output: [0; STAT64_SIZE],
                parent: AtomicU32::new(0),
                flags: AtomicU32::new(0),
                calls: AtomicU32::new(0),
                error: 0,
            }
        }
    }

    unsafe extern "C" fn read(
        context: *const c_void,
        address: u64,
        out: *mut u8,
        size: usize,
    ) -> u32 {
        let host = &*(context as *const Host);
        let index = address.wrapping_sub(0x100) as usize;
        if size != 1 || index > host.path_size {
            return EFAULT;
        }
        *out = host.path[index];
        0
    }

    unsafe extern "C" fn write(
        context: *const c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        if address != 0x300 || size != STAT64_SIZE {
            return EFAULT;
        }
        let host = &mut *(context as *mut Host);
        std::ptr::copy_nonoverlapping(data, host.output.as_mut_ptr(), size);
        0
    }

    unsafe extern "C" fn get_stat(
        context: *const c_void,
        parent: i32,
        path: *const u8,
        path_size: usize,
        flags: u32,
        output: *mut u8,
        output_size: usize,
    ) -> u32 {
        let host = &mut *(context as *mut Host);
        host.calls.fetch_add(1, Ordering::Relaxed);
        host.parent.store(parent as u32, Ordering::Relaxed);
        host.flags.store(flags, Ordering::Relaxed);
        if host.error != 0 {
            return host.error;
        }
        if output_size != STAT64_SIZE {
            return EFAULT;
        }
        if !path.is_null() {
            let path = std::slice::from_raw_parts(path, path_size);
            assert_eq!(path, &host.expected[..host.expected_size]);
        }
        std::ptr::write_bytes(output, 0x5a, output_size);
        0
    }

    fn process(host: &mut Host) -> Process {
        let mut process = Process::new(1, 0, 2);
        process.host_context = (host as *mut Host).cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        process.file_stat = Some(get_stat);
        process
    }

    fn host(path: &[u8]) -> Host {
        let mut host = Host::default();
        host.path[..path.len()].copy_from_slice(path);
        host.path_size = path.len();
        host.expected[..path.len()].copy_from_slice(path);
        host.expected_size = path.len();
        host
    }

    fn frame(number: i32, arguments: [u64; 8]) -> TrapFrame {
        TrapFrame {
            number: number.into(),
            arguments,
            nzcv: 0xf000_0000,
            ..Default::default()
        }
    }

    #[test]
    fn stat64_reads_the_virtual_path_and_copies_darwin_bytes() {
        let mut host = host(b"/usr/lib/dyld");
        let process = process(&mut host);
        let mut frame = frame(338, [0x100, 0x300, 0, 0, 0, 0, 0, 0]);
        assert_eq!(stat(&process, &frame, 338), Some(0));
        assert_eq!(host.calls.load(Ordering::Relaxed), 1);
        assert_eq!(host.parent.load(Ordering::Relaxed), u32::MAX);
        assert_eq!(host.flags.load(Ordering::Relaxed), 0);
        assert!(host.output.iter().all(|byte| *byte == 0x5a));
        frame.arguments[1] = 0x301;
        assert_eq!(stat(&process, &frame, 338), Some(EFAULT));
    }

    #[test]
    fn fstatat_combines_only_registered_guest_paths_and_rejects_flags() {
        let mut host = host(b"libSystem.B.dylib");
        let expected = b"/usr/lib/libSystem.B.dylib";
        host.expected[..expected.len()].copy_from_slice(expected);
        host.expected_size = expected.len();
        let process = process(&mut host);
        assert_eq!(process.files.insert_path(33, b"/usr/lib"), Some(3));
        let mut frame = frame(470, [3, 0x100, 0x300, 0, 0, 0, 0, 0]);
        assert_eq!(stat(&process, &frame, 470), Some(0));
        assert_eq!(host.parent.load(Ordering::Relaxed), u32::MAX);
        frame = self::frame(470, [3, 0x100, 0x300, 0x20, 0, 0, 0, 0]);
        assert_eq!(stat(&process, &frame, 470), Some(EINVAL));
        frame = self::frame(470, [9, 0x100, 0x300, 0, 0, 0, 0, 0]);
        assert_eq!(stat(&process, &frame, 470), Some(EBADF));
    }

    #[test]
    fn fstat_uses_the_host_descriptor_and_errors_do_not_touch_guest_output() {
        let mut host = host(b"/unused");
        host.output.fill(0xa5);
        let process = process(&mut host);
        assert_eq!(process.files.insert_path(33, b"/usr/lib/dyld"), Some(3));
        let frame = frame(339, [3, 0x300, 0, 0, 0, 0, 0, 0]);
        assert_eq!(stat(&process, &frame, 339), Some(0));
        assert_eq!(host.parent.load(Ordering::Relaxed), 33);
        assert!(host.output.iter().all(|byte| *byte == 0x5a));
        host.output.fill(0xa5);
        host.error = 13;
        assert_eq!(stat(&process, &frame, 339), Some(13));
        assert!(host.output.iter().all(|byte| *byte == 0xa5));
    }
}
