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
        // Confined native lookup rejects symlinks; regular bundle metadata
        // has identical stat64/lstat64 layout without following host links.
        338 | 340 => {
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

// Partial reads are legal BSD results. Bound trap-stack use without allocating
// or touching host descriptor numbers supplied directly by a guest.
pub(super) fn read(process: &Process, frame: &TrapFrame) -> Option<Result<u64, u32>> {
    let callback = process.file_read?;
    let copy_out = process.copy_out?;
    let guest = match u32::try_from(frame.arguments[0]) {
        Ok(guest) => guest,
        Err(_) => return Some(Err(EBADF)),
    };
    let Some(host) = process.files.host(guest) else {
        return Some(Err(EBADF));
    };
    let length = frame.arguments[2];
    if length > i64::MAX as u64 {
        return Some(Err(EINVAL));
    }
    if length != 0 && frame.arguments[1] == 0 {
        return Some(Err(EFAULT));
    }
    let offset = if matches!(frame.number as i32, 153 | 414) {
        if frame.arguments[3] > i64::MAX as u64 {
            return Some(Err(EINVAL));
        }
        frame.arguments[3] as i64
    } else {
        -1
    };
    let mut bytes = [0u8; 4096];
    let size = length.min(bytes.len() as u64) as usize;
    let mut count = 0usize;
    let error = unsafe {
        callback(
            process.host_context,
            host,
            bytes.as_mut_ptr(),
            size,
            offset,
            &mut count,
        )
    };
    if error != 0 {
        return Some(Err(error));
    }
    if count > size {
        return Some(Err(5));
    }
    if count != 0
        && unsafe {
            copy_out(
                process.host_context,
                frame.arguments[1],
                bytes.as_ptr(),
                count,
            )
        } != 0
    {
        return Some(Err(EFAULT));
    }
    Some(Ok(count as u64))
}

pub(super) fn seek(process: &Process, frame: &TrapFrame) -> Option<Result<u64, u32>> {
    let callback = process.file_seek?;
    let guest = match u32::try_from(frame.arguments[0]) {
        Ok(guest) => guest,
        Err(_) => return Some(Err(EBADF)),
    };
    let Some(host) = process.files.host(guest) else {
        return Some(Err(EBADF));
    };
    if frame.arguments[2] > 2 {
        return Some(Err(EINVAL));
    }
    let mut position = 0i64;
    let error = unsafe {
        callback(
            process.host_context,
            host,
            frame.arguments[1] as i64,
            frame.arguments[2] as u32,
            &mut position,
        )
    };
    if error != 0 {
        return Some(Err(error));
    }
    if position < 0 {
        return Some(Err(EINVAL));
    }
    Some(Ok(position as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn nocancel_open_close_and_path_queries_share_descriptor_ownership() {
        unsafe extern "C" fn open(
            context: *const c_void,
            _: i32,
            path: *const u8,
            size: usize,
            _: u32,
            _: u32,
            descriptor: *mut i32,
        ) -> u32 {
            let host = &mut *(context as *mut Host);
            assert_eq!(std::slice::from_raw_parts(path, size), b"/x");
            host.calls.fetch_add(1, Ordering::Relaxed);
            *descriptor = 91;
            0
        }
        unsafe extern "C" fn close(_: *const c_void, descriptor: i32) -> u32 {
            assert_eq!(descriptor, 91);
            0
        }
        unsafe extern "C" fn put(
            context: *const c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            if address != 0x300 || size != 3 {
                return 14;
            }
            let host = &mut *(context as *mut Host);
            std::ptr::copy_nonoverlapping(data, host.output.as_mut_ptr(), size);
            0
        }
        let mut host = Host {
            path_size: 2,
            ..Default::default()
        };
        host.path[..2].copy_from_slice(b"/x");
        let mut process = process(&mut host);
        process.open = Some(open);
        process.close = Some(close);
        process.copy_out = Some(put);
        for number in [5, 398, 463, 464] {
            let arguments = if matches!(number, 463 | 464) {
                [(-2i64) as u64, 0x100, 0, 0, 0, 0, 0, 0]
            } else {
                [0x100, 0, 0, 0, 0, 0, 0, 0]
            };
            let mut frame = TrapFrame {
                number,
                arguments,
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!((frame.number, frame.result[0]), (number, 3));
            for number in [92, 406] {
                let mut frame = TrapFrame {
                    number,
                    arguments: [3, 50, 0x300, 0, 0, 0, 0, 0],
                    ..Default::default()
                };
                assert!(process.dispatch(&mut frame));
                assert_eq!(frame.result[0], 0);
                assert_eq!(&host.output[..3], b"/x\0");
            }
            let mut frame = TrapFrame {
                number: 399,
                arguments: [3, 0, 0, 0, 0, 0, 0, 0],
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], 0);
            assert!(process.files.host(3).is_none());
        }
        assert_eq!(host.calls.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn file_io_uses_guest_handles_and_preserves_position_for_pread() {
        struct IoHost {
            output: [u8; 32],
            position: i64,
            calls: usize,
            error: u32,
        }
        unsafe extern "C" fn get(
            context: *const c_void,
            fd: i32,
            output: *mut u8,
            size: usize,
            offset: i64,
            count: *mut usize,
        ) -> u32 {
            assert_eq!(fd, 91);
            let host = &mut *(context as *mut IoHost);
            host.calls += 1;
            if host.error != 0 {
                return host.error;
            }
            let position = if offset == -1 { host.position } else { offset } as usize;
            let data = b"abcdef";
            let size = size.min(data.len().saturating_sub(position));
            if size != 0 {
                std::ptr::copy_nonoverlapping(data.as_ptr().add(position), output, size);
            }
            *count = size;
            if offset == -1 {
                host.position += size as i64;
            }
            0
        }
        unsafe extern "C" fn seek(
            context: *const c_void,
            fd: i32,
            offset: i64,
            whence: u32,
            output: *mut i64,
        ) -> u32 {
            assert_eq!(fd, 91);
            let host = &mut *(context as *mut IoHost);
            host.calls += 1;
            let position = match whence {
                0 => offset,
                1 => host.position + offset,
                2 => 6 + offset,
                _ => return 22,
            };
            if position < 0 {
                return 22;
            }
            host.position = position;
            *output = position;
            0
        }
        unsafe extern "C" fn put(
            context: *const c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            if address != 0x300 || size > 32 {
                return 14;
            }
            let host = &mut *(context as *mut IoHost);
            std::ptr::copy_nonoverlapping(data, host.output.as_mut_ptr(), size);
            0
        }
        let mut host = IoHost {
            output: [0; 32],
            position: 0,
            calls: 0,
            error: 0,
        };
        let mut process = Process::new(1, 0, 2);
        process.host_context = (&mut host as *mut IoHost).cast();
        process.file_read = Some(get);
        process.file_seek = Some(seek);
        process.copy_out = Some(put);
        assert_eq!(process.files.insert(91), Some(3));
        for number in [3, 396] {
            host.position = 0;
            let mut frame = TrapFrame {
                number,
                arguments: [3, 0x300, 3, 0, 0, 0, 0, 0],
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!((frame.result[0], frame.nzcv & super::super::CARRY), (3, 0));
            assert_eq!(&host.output[..3], b"abc");
            assert_eq!(host.position, 3);
        }
        for number in [153, 414] {
            let mut frame = TrapFrame {
                number,
                arguments: [3, 0x300, 2, 1, 0, 0, 0, 0],
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], 2);
            assert_eq!(&host.output[..2], b"bc");
            assert_eq!(host.position, 3);
        }
        let mut frame = TrapFrame {
            number: 199,
            arguments: [3, (-1i64) as u64, 2, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 5);
        let mut frame = TrapFrame {
            number: 3,
            arguments: [3, 0x300, 32, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 1);
        assert_eq!(host.output[0], b'f');
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        let calls = host.calls;
        for (number, arguments, error) in [
            (3, [91, 0x300, 1, 0, 0, 0, 0, 0], 9),
            (3, [3, 0, 1, 0, 0, 0, 0, 0], 14),
            (153, [3, 0x300, 1, u64::MAX, 0, 0, 0, 0], 22),
            (199, [3, 0, 3, 0, 0, 0, 0, 0], 22),
        ] {
            let mut frame = TrapFrame {
                number,
                arguments,
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], error);
            assert_ne!(frame.nzcv & super::super::CARRY, 0);
        }
        assert_eq!(host.calls, calls);
        host.error = 5;
        let original = host.output;
        let mut frame = TrapFrame {
            number: 3,
            arguments: [3, 0x300, 1, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 5);
        assert_eq!(host.output, original);
    }

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
        frame.number = 340;
        assert!(process.dispatch(&mut frame));
        assert_eq!((frame.result[0], frame.nzcv & super::super::CARRY), (0, 0));
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
