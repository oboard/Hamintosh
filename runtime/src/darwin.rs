//! Minimal process identity and Darwin ARM64 syscall ABI.
//!
//! Called on the synchronous trap path without allocation, locks or panic.
//! Native callbacks supply validated VM operations and the host random source.
//! Mach self ports identify real objects in this process model; IPC is separate.
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
mod ipc;
mod signals;
mod sysctl;

pub type VmProtect = unsafe extern "C" fn(*const c_void, u64, u64, u32, u32) -> u32;
pub type GetEntropy = unsafe extern "C" fn(*const c_void, u64, u64) -> u32;
pub type CopyOut = unsafe extern "C" fn(*const c_void, u64, *const u8, usize) -> u32;
pub type CopyIn = unsafe extern "C" fn(*const c_void, u64, *mut u8, usize) -> u32;
pub type Clock = unsafe extern "C" fn(*const c_void, u32, *mut u64) -> u32;
pub type Console = unsafe extern "C" fn(*const c_void, u32, *const u8, usize);
pub type VmMap = unsafe extern "C" fn(*const c_void, *mut u64, u64, u64, u32, u32) -> u32;
pub type VmDeallocate = unsafe extern "C" fn(*const c_void, u64, u64) -> u32;
pub type Open =
    unsafe extern "C" fn(*const c_void, i32, *const u8, usize, u32, u32, *mut i32) -> u32;
pub type Close = unsafe extern "C" fn(*const c_void, i32) -> u32;
pub type Duplicate = unsafe extern "C" fn(*const c_void, i32, *mut i32) -> u32;
pub type ResolveFileId = unsafe extern "C" fn(*const c_void, u64, u64, *mut u8, *mut usize) -> u32;

const CARRY: u64 = 1 << 29;
const DARWIN_ENOSYS: u64 = 78;
const KERN_NOT_SUPPORTED: u64 = 46;

#[repr(C)]
#[derive(Default)]
pub struct TrapFrame {
    pub number: i64,
    pub arguments: [u64; 8],
    pub result: [u64; 2],
    pub nzcv: u64,
}

pub struct Process {
    pid: u32,
    parent_pid: u32,
    thread_id: u64,
    tsd_base: AtomicU64,
    signal_mask: AtomicU32,
    identity_ports: [(i32, u32); 3],
    ports: crate::mach::Space,
    clock_port: AtomicU32,
    semaphore_port: AtomicU32,
    vm_protect: Option<VmProtect>,
    get_entropy: Option<GetEntropy>,
    copy_out: Option<CopyOut>,
    copy_in: Option<CopyIn>,
    shared_region_base: u64,
    clock: Option<Clock>,
    console: Option<Console>,
    vm_map: Option<VmMap>,
    vm_deallocate: Option<VmDeallocate>,
    open: Option<Open>,
    close: Option<Close>,
    duplicate: Option<Duplicate>,
    resolve_file_id: Option<ResolveFileId>,
    files: crate::vfs::Files,
    host_context: *const c_void,
    pub handled: AtomicU64,
    pub unsupported: AtomicU64,
    pub last_unsupported: AtomicI32,
}

impl Process {
    pub fn new(pid: u32, parent_pid: u32, thread_id: u64) -> Self {
        Self {
            pid,
            parent_pid,
            thread_id,
            tsd_base: AtomicU64::new(0),
            signal_mask: AtomicU32::new(0),
            // Per-process Mach name space: index in the high bits, generation 3.
            // These rights refer to this task, its bootstrap thread and its host.
            identity_ports: [(-28, 0x103), (-27, 0x203), (-29, 0x303)],
            ports: crate::mach::Space::default(),
            clock_port: AtomicU32::new(0),
            semaphore_port: AtomicU32::new(0),
            vm_protect: None,
            get_entropy: None,
            copy_out: None,
            copy_in: None,
            shared_region_base: 0,
            clock: None,
            console: None,
            vm_map: None,
            vm_deallocate: None,
            open: None,
            close: None,
            duplicate: None,
            resolve_file_id: None,
            files: crate::vfs::Files::default(),
            host_context: std::ptr::null(),
            handled: AtomicU64::new(0),
            unsupported: AtomicU64::new(0),
            last_unsupported: AtomicI32::new(0),
        }
    }

    fn map_guest(
        &self,
        guest_address: u64,
        size: u64,
        mask: u64,
        flags: u32,
        protection: u32,
    ) -> Option<u64> {
        let map = self.vm_map?;
        let copy_in = self.copy_in?;
        let copy_out = self.copy_out?;
        let mut address = 0u64;
        let error = unsafe {
            copy_in(
                self.host_context,
                guest_address,
                (&mut address as *mut u64).cast::<u8>(),
                size_of::<u64>(),
            )
        };
        if error != 0 {
            return Some(error as u64);
        }
        let error = unsafe {
            map(
                self.host_context,
                &mut address,
                size,
                mask,
                flags,
                protection,
            )
        };
        if error != 0 {
            return Some(error as u64);
        }
        let error = unsafe {
            copy_out(
                self.host_context,
                guest_address,
                (&address as *const u64).cast::<u8>(),
                size_of::<u64>(),
            )
        };
        Some(error as u64)
    }

    pub fn dispatch(&self, frame: &mut TrapFrame) -> bool {
        let number = frame.number as i32;
        if number == 4 {
            if let (Some(read), Some(console)) = (self.copy_in, self.console) {
                let fd = frame.arguments[0] as u32;
                let length = frame.arguments[2] as usize;
                if matches!(fd, 1 | 2) && length <= 8192 {
                    let mut bytes = [0u8; 8192];
                    if unsafe {
                        read(
                            self.host_context,
                            frame.arguments[1],
                            bytes.as_mut_ptr(),
                            length,
                        )
                    } == 0
                    {
                        unsafe { console(self.host_context, fd, bytes.as_ptr(), length) };
                        frame.result = [length as u64, 0];
                        frame.nzcv &= !CARRY;
                        self.handled.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                }
            }
        }
        if number == -47 {
            if let Some(result) = ipc::message2(self, frame) {
                frame.result = [result as u64, 0];
                frame.nzcv &= !CARRY;
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if number == -24 && frame.arguments[0] == 0x103 {
            if let (Some(read), Some(write)) = (self.copy_in, self.copy_out) {
                let mut options = [0u8; 24];
                let error = unsafe {
                    read(
                        self.host_context,
                        frame.arguments[1],
                        options.as_mut_ptr(),
                        options.len(),
                    )
                };
                if error != 0 {
                    frame.result = [1, 0]; // KERN_INVALID_ADDRESS
                    frame.nzcv &= !CARRY;
                    self.handled.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                let flags = u32::from_le_bytes(options[..4].try_into().unwrap());
                // Unsupported attributes remain explicit stop points. Never
                // create an unguarded port when a guard was requested.
                if matches!(flags, 0 | 0x10 | 0x1000)
                    && frame.arguments[2] == 0
                    && options[8..].iter().all(|b| *b == 0)
                {
                    let error = match self.ports.construct(flags) {
                        Ok(name) => {
                            let bytes = name.to_le_bytes();
                            if unsafe {
                                write(
                                    self.host_context,
                                    frame.arguments[3],
                                    bytes.as_ptr(),
                                    bytes.len(),
                                )
                            } != 0
                            {
                                self.ports.discard_unpublished(name);
                                1
                            } else {
                                0
                            }
                        }
                        Err(error) => error,
                    };
                    frame.result = [error as u64, 0];
                    frame.nzcv &= !CARRY;
                    self.handled.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }
        if number == 427 {
            if let (Some(resolve), Some(read), Some(write)) =
                (self.resolve_file_id, self.copy_in, self.copy_out)
            {
                let mut fsid = [0u8; 8];
                let mut path = [0u8; 1024];
                let mut size = path.len();
                let mut error = unsafe {
                    read(
                        self.host_context,
                        frame.arguments[2],
                        fsid.as_mut_ptr(),
                        fsid.len(),
                    )
                };
                if error == 0 {
                    error = unsafe {
                        resolve(
                            self.host_context,
                            u64::from_le_bytes(fsid),
                            frame.arguments[3],
                            path.as_mut_ptr(),
                            &mut size,
                        )
                    };
                }
                if error == 0 {
                    if size > path.len() || size as u64 > frame.arguments[1] {
                        error = 34; // Darwin ERANGE
                    } else {
                        error = unsafe {
                            write(self.host_context, frame.arguments[0], path.as_ptr(), size)
                        };
                    }
                }
                frame.result = [
                    if error == 0 {
                        size as u64
                    } else {
                        error as u64
                    },
                    0,
                ];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if number == 41 {
            if let (Some(duplicate), Some(close)) = (self.duplicate, self.close) {
                let mut path = [0u8; 1024];
                let mut result = 0;
                let mut error = 9;
                if let (Some(host), Some(size)) = (
                    self.files.host(frame.arguments[0] as u32),
                    self.files.path(frame.arguments[0] as u32, &mut path),
                ) {
                    let mut cloned = -1;
                    error = unsafe { duplicate(self.host_context, host, &mut cloned) };
                    if error == 0 {
                        if let Some(guest) = self.files.insert_path(cloned, &path[..size - 1]) {
                            result = guest as u64;
                        } else {
                            if cloned >= 0 {
                                unsafe {
                                    close(self.host_context, cloned);
                                }
                            }
                            error = 24;
                        }
                    }
                }
                frame.result = [if error == 0 { result } else { error as u64 }, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if number == 48 {
            if let Some(error) = signals::mask(self, frame) {
                frame.result = [error as u64, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if number == 202 {
            if let Some(error) = sysctl::query(self, frame) {
                frame.result = [error as u64, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        // This compatibility kernel has no XNU MAC policy modules. XNU's own
        // CONFIG_MACF-disabled syscall table specifies ENOSYS for this entry.
        // Host file access and signed executable mappings keep their host rules.
        if number == 381 {
            frame.result = [DARWIN_ENOSYS, 0];
            frame.nzcv |= CARRY;
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if number == 92 && frame.arguments[1] == 50 {
            if let Some(write) = self.copy_out {
                let mut path = [0u8; 1024];
                let error = self
                    .files
                    .path(frame.arguments[0] as u32, &mut path)
                    .map_or(9, |len| unsafe {
                        write(self.host_context, frame.arguments[2], path.as_ptr(), len)
                    });
                frame.result = [error as u64, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if let (Some(open), Some(close)) = (self.open, self.close) {
            if number == 5 || number == 463 {
                let mut path = [0u8; 1024];
                let mut length = None;
                let address = frame.arguments[if number == 5 { 0 } else { 1 }];
                if let Some(read) = self.copy_in {
                    for i in 0..path.len() {
                        if unsafe {
                            read(
                                self.host_context,
                                address.wrapping_add(i as u64),
                                path.as_mut_ptr().add(i),
                                1,
                            )
                        } != 0
                        {
                            frame.result = [14, 0];
                            frame.nzcv |= CARRY;
                            self.handled.fetch_add(1, Ordering::Relaxed);
                            return true;
                        }
                        if path[i] == 0 {
                            length = Some(i);
                            break;
                        }
                    }
                }
                let mut parent = -1;
                if number == 463 && length.is_some() && path[0] != b'/' {
                    let dir = frame.arguments[0] as u32 as i32;
                    let mut combined = [0u8; 1024];
                    let prefix = if dir == -2 {
                        combined[0] = b'/';
                        1
                    } else {
                        let Some(fd) = self.files.host(dir as u32) else {
                            frame.result = [9, 0];
                            frame.nzcv |= CARRY;
                            self.handled.fetch_add(1, Ordering::Relaxed);
                            return true;
                        };
                        parent = fd;
                        let Some(size) = self.files.path(dir as u32, &mut combined) else {
                            frame.result = [9, 0];
                            frame.nzcv |= CARRY;
                            self.handled.fetch_add(1, Ordering::Relaxed);
                            return true;
                        };
                        let mut size = size - 1;
                        if size == 0 || combined[size - 1] != b'/' {
                            combined[size] = b'/';
                            size += 1;
                        }
                        size
                    };
                    let count = length.unwrap_or(0);
                    if count == 0 {
                        frame.result = [2, 0];
                        frame.nzcv |= CARRY;
                        self.handled.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                    if prefix + count >= path.len() {
                        frame.result = [63, 0];
                        frame.nzcv |= CARRY;
                        self.handled.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                    combined[prefix..prefix + count].copy_from_slice(&path[..count]);
                    path = combined;
                    length = Some(prefix + count);
                }
                let mut host = -1;
                let mut error = if let Some(length) = length {
                    unsafe {
                        open(
                            self.host_context,
                            parent,
                            path.as_ptr(),
                            length,
                            frame.arguments[if number == 5 { 1 } else { 2 }] as u32,
                            frame.arguments[if number == 5 { 2 } else { 3 }] as u32,
                            &mut host,
                        )
                    }
                } else {
                    63
                };
                let mut result = 0;
                if error == 0 {
                    if let Some(guest) = self.files.insert_path(host, &path[..length.unwrap_or(0)])
                    {
                        result = guest as u64;
                    } else {
                        if host >= 0 {
                            unsafe {
                                close(self.host_context, host);
                            }
                        }
                        error = if host < 0 { 5 } else { 24 };
                    }
                }
                frame.result = [if error == 0 { result } else { error as u64 }, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            if number == 6 {
                let error = self
                    .files
                    .take(frame.arguments[0] as u32)
                    .map_or(9, |host| unsafe { close(self.host_context, host) });
                frame.result = [error as u64, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if matches!(number, -3 | -4) {
            if let Some(clock) = self.clock {
                let mut value = 0;
                if unsafe { clock(self.host_context, (number == -4) as u32, &mut value) } == 0 {
                    frame.result = [value, frame.arguments[1]];
                    self.handled.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
        }
        if number == 294 && self.shared_region_base != 0 {
            if let Some(copy_out) = self.copy_out {
                let bytes = self.shared_region_base.to_le_bytes();
                let error = unsafe {
                    copy_out(
                        self.host_context,
                        frame.arguments[0],
                        bytes.as_ptr(),
                        bytes.len(),
                    )
                };
                frame.result = [error as u64, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if number == 500 {
            if let Some(get_entropy) = self.get_entropy {
                let error = unsafe {
                    get_entropy(self.host_context, frame.arguments[0], frame.arguments[1])
                };
                frame.result = [error as u64, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        // This ARM64 host does not provide cross-architecture translation.
        // Namespace zero follows XNU's documented ENOTSUP result, including
        // BSD carry semantics, rather than pretending a translator exists.
        if number == 38 && frame.arguments[0] == 0 {
            frame.result = [45, 0];
            frame.nzcv |= CARRY;
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if number == i32::MIN && matches!(frame.arguments[3], 2 | 3) {
            if frame.arguments[3] == 2 {
                self.tsd_base.store(frame.arguments[0], Ordering::Release);
                frame.result = [frame.arguments[0], frame.arguments[1]];
            } else {
                frame.result = [self.tsd_base.load(Ordering::Acquire), frame.arguments[1]];
            }
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        frame.result = [0, 0];
        let result = match number {
            20 => Some(self.pid as u64),
            39 => Some(self.parent_pid as u64),
            372 => Some(self.thread_id),
            -26 => Some(self.ports.construct(0x1000).unwrap_or(0) as u64),
            -12 if frame.arguments[0] == 0x103 => self.vm_deallocate.map(|deallocate| unsafe {
                deallocate(self.host_context, frame.arguments[1], frame.arguments[2]) as u64
            }),
            -15 if frame.arguments[0] == 0x103 => self.map_guest(
                frame.arguments[1],
                frame.arguments[2],
                frame.arguments[3],
                frame.arguments[4] as u32,
                frame.arguments[5] as u32,
            ),
            -10 if frame.arguments[0] == 0x103 => self.map_guest(
                frame.arguments[1],
                frame.arguments[2],
                0x3fff,
                frame.arguments[3] as u32,
                3,
            ),
            -19 if frame.arguments[0] == 0x103 && frame.arguments[2] == 0 => Some(
                self.ports
                    .modify_send_refs(frame.arguments[1] as u32, frame.arguments[3] as u32 as i32)
                    as u64,
            ),
            -18 if frame.arguments[0] == 0x103 => {
                Some(self.ports.deallocate(frame.arguments[1] as u32) as u64)
            }
            -14 if frame.arguments[0] == 0x103 => self.vm_protect.map(|protect| unsafe {
                protect(
                    self.host_context,
                    frame.arguments[1],
                    frame.arguments[2],
                    frame.arguments[3] as u32,
                    frame.arguments[4] as u32,
                ) as u64
            }),
            n => self
                .identity_ports
                .iter()
                .find(|(trap, _)| *trap == n)
                .and_then(|(_, port)| self.ports.acquire_send(*port).then_some(*port as u64)),
        };
        if let Some(result) = result {
            frame.result[0] = result;
            frame.nzcv &= !CARRY;
            self.handled.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.unsupported.fetch_add(1, Ordering::Relaxed);
            self.last_unsupported.store(number, Ordering::Relaxed);
            // Mach returns a kern_return_t; BSD uses a positive errno and carry.
            if number < 0 {
                frame.result[0] = KERN_NOT_SUPPORTED;
                frame.nzcv &= !CARRY;
            } else {
                frame.result[0] = DARWIN_ENOSYS;
                frame.nzcv |= CARRY;
            }
            false
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(close) = self.close {
            self.files.drain(|fd| unsafe {
                close(self.host_context, fd);
            });
        }
    }
}

#[no_mangle]
pub extern "C" fn hm_process_create(pid: u32, parent_pid: u32, thread_id: u64) -> *mut Process {
    Box::into_raw(Box::new(Process::new(pid, parent_pid, thread_id)))
}

/// # Safety
/// `process` is a live process context for the current guest thread.
#[no_mangle]
pub unsafe extern "C" fn hm_process_tsd_base(process: *const Process) -> u64 {
    process
        .as_ref()
        .map_or(0, |p| p.tsd_base.load(Ordering::Acquire))
}

/// # Safety
/// Configure only before guest execution. Callback/context remain valid for
/// this process and use only signal-safe host operations on the trap path.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_vm_protect(
    process: *mut Process,
    callback: Option<VmProtect>,
    context: *const c_void,
) {
    if let Some(process) = process.as_mut() {
        process.vm_protect = callback;
        process.host_context = context;
    }
}

/// # Safety
/// Configure before guest execution with the same live context as VM protection.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_getentropy(
    process: *mut Process,
    callback: Option<GetEntropy>,
) {
    if let Some(process) = process.as_mut() {
        process.get_entropy = callback;
    }
}

/// # Safety
/// Configure before guest execution with a live cache reservation and a
/// callback that checks every write against guest memory and current protections.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_memory(
    process: *mut Process,
    read: Option<CopyIn>,
    callback: Option<CopyOut>,
    cache_base: u64,
) {
    if let Some(process) = process.as_mut() {
        process.copy_out = callback;
        process.copy_in = read;
        process.shared_region_base = cache_base;
    }
}

/// # Safety
/// Configure before guest execution. Console callback copies bounded bytes
/// into diagnostics storage and does not retain the input pointer.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_console(process: *mut Process, callback: Option<Console>) {
    if let Some(process) = process.as_mut() {
        process.console = callback;
    }
}

/// # Safety
/// Configure before guest execution. Clock callback is live and signal safe.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_clock(process: *mut Process, callback: Option<Clock>) {
    if let Some(process) = process.as_mut() {
        process.clock = callback;
    }
}

/// # Safety
/// Configure before guest execution. Callback validates guest pointers and
/// owns every mapping it creates until this guest attempt is discarded.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_vm_map(process: *mut Process, callback: Option<VmMap>) {
    if let Some(process) = process.as_mut() {
        process.vm_map = callback;
    }
}

/// # Safety
/// Configure before guest execution. Callback frees only guest-owned mappings.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_vm_deallocate(
    process: *mut Process,
    callback: Option<VmDeallocate>,
) {
    if let Some(process) = process.as_mut() {
        process.vm_deallocate = callback;
    }
}

/// # Safety
/// Configure before guest execution. Both callbacks remain live until process
/// destruction, which closes every remaining guest-owned host descriptor.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_files(
    process: *mut Process,
    open: Option<Open>,
    close: Option<Close>,
    duplicate: Option<Duplicate>,
) {
    if let Some(process) = process.as_mut() {
        process.open = open;
        process.close = close;
        process.duplicate = duplicate;
    }
}

/// # Safety
/// Configure before guest execution; callback returns only registered guest paths.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_resolve_file_id(
    process: *mut Process,
    callback: Option<ResolveFileId>,
) {
    if let Some(process) = process.as_mut() {
        process.resolve_file_id = callback;
    }
}

/// # Safety
/// `process` is null or an owned pointer from hm_process_create, unused by other calls.
#[no_mangle]
pub unsafe extern "C" fn hm_process_destroy(process: *mut Process) {
    if !process.is_null() {
        drop(Box::from_raw(process));
    }
}

/// # Safety
/// `process` is live for the call and `frame` points to an exclusively writable TrapFrame.
#[no_mangle]
pub unsafe extern "C" fn hm_darwin_dispatch(process: *const Process, frame: *mut TrapFrame) -> i32 {
    let (Some(process), Some(frame)) = (process.as_ref(), frame.as_mut()) else {
        return -1;
    };
    if process.dispatch(frame) {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_construction_copies_names_and_rolls_back_bad_output_memory() {
        unsafe extern "C" fn read(
            context: *const c_void,
            address: u64,
            out: *mut u8,
            size: usize,
        ) -> u32 {
            if address != 0 || size != 24 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(context.cast::<u8>(), out, size);
            0
        }
        unsafe extern "C" fn write(
            context: *const c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            if address != 32 || size != 4 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(data, (context as *mut u8).add(32), size);
            0
        }
        let mut memory = [0u8; 64];
        memory[..4].copy_from_slice(&0x10u32.to_le_bytes());
        let mut process = Process::new(1, 0, 2);
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let mut frame = TrapFrame {
            number: -24,
            arguments: [0x103, 0, 0, 999, 0, 0, 0, 0],
            nzcv: 0xf0000000,
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 1);
        assert_eq!(frame.nzcv, 0xd0000000);
        frame.arguments[3] = 32;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        let name = u32::from_le_bytes(memory[32..36].try_into().unwrap());
        assert_eq!(name, 0x403); // failed copyout did not consume a slot
        assert!(process.ports.has_receive(name));
        assert_eq!(process.ports.modify_send_refs(name, -1), 0);
        memory[..4].copy_from_slice(&1u32.to_le_bytes());
        assert!(!process.dispatch(&mut frame)); // guards are not silently ignored
        assert_eq!(frame.result[0], 46);
    }

    #[test]
    fn file_id_lookup_checks_identity_buffer_size_and_guest_memory() {
        unsafe extern "C" fn read(
            _: *const c_void,
            address: u64,
            out: *mut u8,
            size: usize,
        ) -> u32 {
            if address != 0x100 || size != 8 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(42u64.to_le_bytes().as_ptr(), out, size);
            0
        }
        unsafe extern "C" fn write(
            context: *const c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            if address != 0x200 || size > 32 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(data, context as *mut u8, size);
            0
        }
        unsafe extern "C" fn resolve(
            _: *const c_void,
            device: u64,
            inode: u64,
            path: *mut u8,
            size: *mut usize,
        ) -> u32 {
            if device != 42 || inode != 7 {
                return 2;
            }
            let value = b"/cache\0";
            assert!(*size >= value.len());
            std::ptr::copy_nonoverlapping(value.as_ptr(), path, value.len());
            *size = value.len();
            0
        }
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0xaau8; 32];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        process.resolve_file_id = Some(resolve);
        let mut frame = TrapFrame {
            number: 427,
            arguments: [0x200, 6, 0x100, 7, 0, 0, 0, 0],
            nzcv: 0xf0000000,
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 34);
        assert_eq!(memory, [0xaa; 32]);
        frame.arguments[1] = 32;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 7);
        assert_eq!(frame.nzcv, 0xd0000000);
        assert_eq!(&memory[..7], b"/cache\0");
        for (index, value, error) in [(3, 9, 2), (2, 0, 14), (0, 0, 14)] {
            let saved = frame.arguments[index];
            frame.arguments[index] = value;
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], error);
            assert_ne!(frame.nzcv & CARRY, 0);
            frame.arguments[index] = saved;
        }
    }

    #[test]
    fn fast_clock_preserves_64_bits_flags_and_w16_trap_encoding() {
        unsafe extern "C" fn clock(_: *const c_void, continuous: u32, out: *mut u64) -> u32 {
            *out = 0x1_23456789 + continuous as u64;
            0
        }
        let mut process = Process::new(1, 0, 2);
        process.clock = Some(clock);
        let mut frame = TrapFrame {
            number: 0xffff_fffd,
            nzcv: 0xf0000000,
            arguments: [0, 17, 0, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0x1_23456789, 17]);
        assert_eq!(frame.nzcv, 0xf0000000);
        frame.number = -4;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0x1_2345678a);
        frame.number = 38;
        frame.nzcv = 0;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 45);
        assert_ne!(frame.nzcv & CARRY, 0);
        assert_eq!(process.unsupported.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn platform_tsd_storage_is_isolated_and_preserves_flags() {
        let process = Process::new(100, 10, 101);
        let other = Process::new(200, 10, 201);
        let mut frame = TrapFrame {
            number: 0x80000000,
            arguments: [0x12345000, 9, 0, 2, 0, 0, 0, 0],
            nzcv: 0xf0000000,
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0x12345000, 9]);
        assert_eq!(frame.nzcv, 0xf0000000);
        frame.arguments[3] = 3;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0x12345000);
        assert!(other.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
    }

    #[test]
    fn arm64_time_traps_return_absolute_and_continuous_clocks() {
        unsafe extern "C" fn clock(_: *const c_void, continuous: u32, out: *mut u64) -> u32 {
            *out = if continuous == 0 { 11 } else { 22 };
            0
        }
        let mut process = Process::new(1, 0, 2);
        process.clock = Some(clock);
        for (number, expected) in [(-3, 11), (-4, 22)] {
            let mut frame = TrapFrame {
                number,
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], expected);
        }
    }

    #[test]
    fn direct_vm_map_copies_the_host_result_to_guest_memory() {
        unsafe extern "C" fn map(
            _: *const c_void,
            address: *mut u64,
            size: u64,
            mask: u64,
            flags: u32,
            protection: u32,
        ) -> u32 {
            if size != 0x4000 || mask != 0x3fff || flags != 1 || protection != 3 {
                return 4;
            }
            if *address != 0x6000_0000 {
                return 1;
            }
            *address = 0x7000_0000;
            0
        }
        unsafe extern "C" fn copy_out(
            context: *const c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            let memory = &mut *(context as *mut [u8; 32]);
            memory[address as usize..address as usize + size]
                .copy_from_slice(std::slice::from_raw_parts(data, size));
            0
        }
        unsafe extern "C" fn copy_in(
            context: *const c_void,
            address: u64,
            out: *mut u8,
            size: usize,
        ) -> u32 {
            let memory = &*(context as *const [u8; 32]);
            std::ptr::copy_nonoverlapping(memory.as_ptr().add(address as usize), out, size);
            0
        }

        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 32];
        memory[8..16].copy_from_slice(&0x6000_0000u64.to_le_bytes());
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(copy_in);
        process.copy_out = Some(copy_out);
        process.vm_map = Some(map);
        let mut frame = TrapFrame {
            number: -10,
            arguments: [0x103, 8, 0x4000, 1, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert_eq!(
            u64::from_le_bytes(memory[8..16].try_into().unwrap()),
            0x7000_0000
        );
    }

    #[test]
    fn bootstrap_thread_id_and_reply_port_are_process_resources() {
        let process = Process::new(100, 10, 0x1_0000_0020);
        let mut frame = TrapFrame {
            number: 372,
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0x1_0000_0020);
        frame.number = -26;
        assert!(process.dispatch(&mut frame));
        let first = frame.result[0];
        assert!(process.ports.has_receive(first as u32));
        assert!(process.dispatch(&mut frame));
        assert_ne!(first, frame.result[0]);
    }

    #[test]
    fn unix_success_clears_only_carry_and_preserves_arguments() {
        let process = Process::new(1729, 10, 1730);
        let mut frame = TrapFrame {
            number: 20,
            arguments: [0xfeed; 8],
            nzcv: 0xf000_0000,
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [1729, 0]);
        assert_eq!(frame.nzcv, 0xd000_0000);
        assert_eq!(frame.arguments, [0xfeed; 8]);
        frame.number = 39;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 10);
    }

    #[test]
    fn unix_and_mach_failures_use_distinct_return_conventions() {
        let process = Process::new(1, 0, 2);
        let mut frame = TrapFrame {
            number: 0x7fff,
            ..Default::default()
        };
        assert!(!process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 78);
        assert_ne!(frame.nzcv & CARRY, 0);
        frame.number = -0x7fff;
        assert!(!process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 46);
        assert_eq!(frame.nzcv & CARRY, 0);
        assert_eq!(process.unsupported.load(Ordering::Relaxed), 2);
        assert_eq!(process.last_unsupported.load(Ordering::Relaxed), -0x7fff);
    }

    #[test]
    fn mach_port_deallocate_releases_only_a_published_send_right() {
        let process = Process::new(1, 0, 2);
        assert!(process.ports.acquire_send(0x303));
        let mut frame = TrapFrame {
            number: -18,
            arguments: [0x103, 0x303, 0, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert!(!process.ports.has_send(0x303));
        assert!(process.ports.acquire_send(0x303));
        assert!(process.ports.has_send(0x303));
        assert_eq!(process.ports.deallocate(0x303), 0);
        frame.arguments[1] = 0x304;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 15);
    }

    #[test]
    fn mach_identity_ports_are_stable_and_distinct_in_each_process() {
        let process = Process::new(1, 0, 2);
        for (number, port) in [(-28, 0x103), (-27, 0x203), (-29, 0x303)] {
            let mut frame = TrapFrame {
                number,
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], port);
        }
        assert_eq!(process.handled.load(Ordering::Relaxed), 3);
    }
}
