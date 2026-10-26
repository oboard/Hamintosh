//! Minimal process identity and Darwin ARM64 syscall ABI.
//!
//! Called on the synchronous trap path without allocation, locks or panic.
//! Native callbacks supply validated VM operations and the host random source.
//! Mach self ports identify real objects in this process model; IPC is separate.
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
mod activity;
mod csops;
mod display;
mod files;
mod ipc;
mod kevent;
mod memory;
mod ports;
mod proc_info;
mod restartable;
mod sandbox;
mod semwait;
mod signals;
mod sysctl;
mod time;
mod xpc;

pub type VmProtect = unsafe extern "C" fn(*const c_void, u64, u64, u32, u32) -> u32;
pub type GetEntropy = unsafe extern "C" fn(*const c_void, u64, u64) -> u32;
pub type CopyOut = unsafe extern "C" fn(*const c_void, u64, *const u8, usize) -> u32;
pub type CopyIn = unsafe extern "C" fn(*const c_void, u64, *mut u8, usize) -> u32;
// Clock kind: 0 = monotonic, 1 = continuous, 2 = Unix calendar time.
// Values use nanoseconds in the guest's 1:1 mach timebase.
pub type Clock = unsafe extern "C" fn(*const c_void, u32, *mut u64) -> u32;
pub type Console = unsafe extern "C" fn(*const c_void, u32, *const u8, usize);
pub type VmMap = unsafe extern "C" fn(*const c_void, *mut u64, u64, u64, u32, u32) -> u32;
pub type MapFile = unsafe extern "C" fn(*const c_void, *mut u64, u64, u32, i32, u64) -> u32;
pub type VmDeallocate = unsafe extern "C" fn(*const c_void, u64, u64) -> u32;
pub type Open =
    unsafe extern "C" fn(*const c_void, i32, *const u8, usize, u32, u32, *mut i32) -> u32;
pub type Close = unsafe extern "C" fn(*const c_void, i32) -> u32;
pub type Duplicate = unsafe extern "C" fn(*const c_void, i32, *mut i32) -> u32;
pub type FileStat =
    unsafe extern "C" fn(*const c_void, i32, *const u8, usize, u32, *mut u8, usize) -> u32;
pub type CodeSignatureBlob = unsafe extern "C" fn(*const c_void, u32, u64, u64) -> u32;
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
    bootstrap_port: AtomicU32,
    debug_control_port: AtomicU32,
    io_main_port: AtomicU32,
    io_registry_port: AtomicU32,
    io_display_service_port: AtomicU32,
    special_reply_port: AtomicU32,
    clock_port: AtomicU32,
    semaphore_port: AtomicU32,
    xpc: xpc::State,
    restartable: restartable::Ranges,
    workqueue: kevent::State,
    vm_protect: Option<VmProtect>,
    get_entropy: Option<GetEntropy>,
    copy_out: Option<CopyOut>,
    copy_in: Option<CopyIn>,
    shared_region_base: u64,
    display_width: u32,
    display_height: u32,
    display_scale: f32,
    display_native_scale: f32,
    clock: Option<Clock>,
    console: Option<Console>,
    vm_map: Option<VmMap>,
    map_file: Option<MapFile>,
    vm_deallocate: Option<VmDeallocate>,
    open: Option<Open>,
    close: Option<Close>,
    duplicate: Option<Duplicate>,
    file_stat: Option<FileStat>,
    code_signature_blob: Option<CodeSignatureBlob>,
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
            bootstrap_port: AtomicU32::new(0),
            debug_control_port: AtomicU32::new(0),
            io_main_port: AtomicU32::new(0),
            io_registry_port: AtomicU32::new(0),
            io_display_service_port: AtomicU32::new(0),
            special_reply_port: AtomicU32::new(0),
            clock_port: AtomicU32::new(0),
            semaphore_port: AtomicU32::new(0),
            xpc: xpc::State::default(),
            restartable: restartable::Ranges::default(),
            workqueue: kevent::State::default(),
            vm_protect: None,
            get_entropy: None,
            copy_out: None,
            copy_in: None,
            shared_region_base: 0,
            // Current MRT-AL10 fallback: 1272x2860 at density 3.5. Native
            // replaces these values when the display-manager API is present.
            display_width: 1272,
            display_height: 2860,
            display_scale: 3.5,
            display_native_scale: 3.5,
            clock: None,
            console: None,
            vm_map: None,
            map_file: None,
            vm_deallocate: None,
            open: None,
            close: None,
            duplicate: None,
            file_stat: None,
            code_signature_blob: None,
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
        if number == -70 && frame.arguments[0] == 0x303 {
            // XNU mach_kernelrpc.c: host_create_mach_voucher_trap. The runtime
            // exposes a process-owned voucher port. Recipe bytes are validated
            // and retained only for this call; QoS recipe semantics are not yet
            // interpreted by this compatibility kernel.
            let size = frame.arguments[2] as i32;
            if !(0..=5120).contains(&size) {
                frame.result = [4, 0]; // KERN_INVALID_ARGUMENT
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            if frame.arguments[3] == 0 {
                frame.result = [1, 0];
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            if let Some(read) = self.copy_in {
                let mut recipes = [0u8; 5120];
                if size > 0
                    && unsafe {
                        read(
                            self.host_context,
                            frame.arguments[1],
                            recipes.as_mut_ptr(),
                            size as usize,
                        )
                    } != 0
                {
                    frame.result = [1, 0];
                    self.handled.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
            }
            let name = self.ports.construct(0x10).unwrap_or(0);
            let error = if name == 0 {
                12 // KERN_RESOURCE_SHORTAGE
            } else if let Some(write) = self.copy_out {
                if unsafe {
                    write(
                        self.host_context,
                        frame.arguments[3],
                        name.to_le_bytes().as_ptr(),
                        size_of::<u32>(),
                    )
                } == 0
                {
                    0
                } else {
                    self.ports.discard_unpublished(name);
                    1
                }
            } else {
                self.ports.discard_unpublished(name);
                1
            };
            frame.result = [error, 0];
            frame.nzcv &= !CARRY;
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if number == -50 {
            // XNU ipc_tt.c: unbind the thread's previous special reply port,
            // then allocate a new receive right with one send user ref.
            let previous = self.special_reply_port.swap(0, Ordering::AcqRel);
            if previous != 0 {
                self.ports.discard_unpublished(previous);
            }
            let name = self.ports.construct(0x10).unwrap_or(0);
            self.special_reply_port.store(name, Ordering::Release);
            frame.result = [name as u64, 0];
            frame.nzcv &= !CARRY;
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
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
                // libxpc requests receive + send with context-guard and strict
                // name requirements (0x31). Port names already carry a
                // generation and are never silently replaced; retain the
                // context guard for future guarded-exception semantics.
                const MPO_OPTIONS_MASK: u32 = 0x23ff;
                const MPO_PORT_TYPE_MASK: u32 = 0x1c00;
                const MPO_CONNECTION_PORT: u32 = 0x0800;
                const MPO_REPLY_PORT: u32 = 0x1000;
                const MPO_CONTEXT_AS_GUARD: u32 = 0x01;
                const MPO_INSERT_SEND_RIGHT: u32 = 0x10;
                let port_type = flags & MPO_PORT_TYPE_MASK;
                let valid = flags & !(MPO_OPTIONS_MASK | MPO_PORT_TYPE_MASK) == 0
                    && matches!(port_type, 0 | MPO_CONNECTION_PORT | MPO_REPLY_PORT);
                let guard = flags & MPO_CONTEXT_AS_GUARD != 0;
                let connection = port_type == MPO_CONNECTION_PORT;
                let base_flags = if port_type == MPO_REPLY_PORT {
                    MPO_REPLY_PORT
                } else if flags & MPO_INSERT_SEND_RIGHT != 0 {
                    MPO_INSERT_SEND_RIGHT
                } else {
                    0
                };
                if valid
                    && (!guard || frame.arguments[2] != 0)
                    && (connection || options[8..].iter().all(|b| *b == 0))
                {
                    let error = match self.ports.construct(base_flags) {
                        Ok(name) if guard && !self.ports.set_guard(name, frame.arguments[2]) => {
                            self.ports.discard_unpublished(name);
                            4
                        }
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
        if number == 336 {
            if let Some(error) = proc_info::query(self, frame) {
                frame.result = [error as u64, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                    frame.result = [56, 0];
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
        if number == 169 {
            if let Some(error) = csops::csops(self, frame) {
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
        if matches!(number, 338 | 339 | 470) {
            if let Some(error) = files::stat(self, frame, number) {
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
        if number == 116 {
            if let Some(error) = time::gettimeofday(self, frame) {
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
        if matches!(number, 334 | 423) {
            if let Some(error) = semwait::semwait(frame) {
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
        if number == 74 {
            if let Some(error) = memory::protect(self, frame) {
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
        if number == 197 {
            if let Some(result) = memory::mmap(self, frame) {
                match result {
                    Ok(address) => {
                        frame.result = [address, 0];
                        frame.nzcv &= !CARRY;
                    }
                    Err(error) => {
                        frame.result = [error as u64, 0];
                        frame.nzcv |= CARRY;
                    }
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if number == 73 {
            if let Some(error) = memory::unmap(self, frame) {
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
        // HarmonyOS has no XNU MAC policy module. Emulate only the container
        // discovery operations that Apple's libsystem needs during dyld
        // initialization; every other sandbox operation keeps ENOSYS.
        if number == 381 {
            if let Some(error) = sandbox::sandbox_ms(self, frame) {
                frame.result = [error as u64, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
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
        if number == -89 {
            if let Some(copy_out) = self.copy_out {
                let mut value = [0u8; 8];
                value[..4].copy_from_slice(&1u32.to_le_bytes());
                value[4..].copy_from_slice(&1u32.to_le_bytes());
                let error = unsafe {
                    copy_out(
                        self.host_context,
                        frame.arguments[0],
                        value.as_ptr(),
                        value.len(),
                    )
                };
                frame.result = [error as u64, 0];
                frame.nzcv &= !CARRY;
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
        if number == 374 {
            if let Some(result) = kevent::qos(self, frame) {
                match result {
                    Ok(count) => {
                        frame.result = [count, 0];
                        frame.nzcv &= !CARRY;
                    }
                    Err(error) => {
                        frame.result = [error as u64, 0];
                        frame.nzcv |= CARRY;
                    }
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if number == 375 {
            if let Some(result) = kevent::id(self, frame) {
                match result {
                    Ok(count) => {
                        frame.result = [count, 0];
                        frame.nzcv &= !CARRY;
                    }
                    Err(error) => {
                        frame.result = [error as u64, 0];
                        frame.nzcv |= CARRY;
                    }
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        if number == 368 {
            // WQOPS_SETUP_DISPATCH: libdispatch supplies the offsets it uses
            // for queue serial numbers and labels. The compatibility runtime
            // does not expose those host structures, but accepting the
            // validated configuration prevents libdispatch's setup retry loop.
            const WQOPS_SETUP_DISPATCH: u64 = 0x400;
            if frame.arguments[0] != WQOPS_SETUP_DISPATCH {
                frame.result = [45, 0]; // ENOTSUP
                frame.nzcv |= CARRY;
            } else if let Some(read) = self.copy_in {
                let size = frame.arguments[2].min(24) as usize;
                let mut config = [0u8; 24];
                let error = if size == 0 {
                    22 // EINVAL
                } else if unsafe {
                    read(
                        self.host_context,
                        frame.arguments[1],
                        config.as_mut_ptr(),
                        size,
                    )
                } != 0
                {
                    14 // EFAULT
                } else {
                    let version = u32::from_le_bytes(config[..4].try_into().unwrap());
                    let flags = u32::from_le_bytes(config[4..8].try_into().unwrap());
                    if version < 1 || flags != 0 {
                        45 // ENOTSUP
                    } else {
                        0
                    }
                };
                frame.result = [error, 0];
                if error == 0 {
                    frame.nzcv &= !CARRY;
                } else {
                    frame.nzcv |= CARRY;
                }
            } else {
                frame.result = [14, 0];
                frame.nzcv |= CARRY;
            }
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if number == 366 {
            // libpthread registers its thread and workqueue entry points once
            // during initialization. The current compatibility kernel executes
            // only the bootstrap guest thread, but accepting registration lets
            // pthread initialize its process-local state. bsdthread_create and
            // workqueue operations remain explicit unsupported boundaries.
            if frame.arguments[0] == 0 || frame.arguments[1] == 0 {
                frame.result = [22, 0];
                frame.nzcv |= CARRY;
            } else {
                // This libpthread requires the complete modern feature set
                // before it installs its process-local workqueue state. The
                // returned bits describe ABI features, not enabled guest
                // worker threads; thread creation remains unsupported later.
                const PTHREAD_FEATURES_REQUIRED_BY_IOS27: u64 = 0x4000_001e;
                frame.result = [PTHREAD_FEATURES_REQUIRED_BY_IOS27, 0];
                frame.nzcv &= !CARRY;
            }
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if let Some(result) = ports::dispatch(self, frame) {
            frame.result = [u64::from(result), 0];
            frame.nzcv &= !CARRY;
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
            -77 if frame.arguments[0] == 0x103 => {
                let result = self.ports.request_notification(
                    frame.arguments[1] as u32,
                    frame.arguments[2] as u32,
                    frame.arguments[4] as u32,
                    frame.arguments[5] as u32,
                );
                match result {
                    Ok(previous) => self.copy_out.map(|write| unsafe {
                        write(
                            self.host_context,
                            frame.arguments[6],
                            previous.to_le_bytes().as_ptr(),
                            size_of::<u32>(),
                        ) as u64
                    }),
                    Err(error) => Some(error as u64),
                }
            }
            -19 if frame.arguments[0] == 0x103 && frame.arguments[2] == 0 => Some(
                self.ports
                    .modify_send_refs(frame.arguments[1] as u32, frame.arguments[3] as u32 as i32)
                    as u64,
            ),
            -43 => activity::generate(self, frame).map(u64::from),
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
/// `process` is null or the live context of the current guest thread. Called
/// before resuming guest execution after a synchronous signal/trap.
#[no_mangle]
pub unsafe extern "C" fn hm_process_resume_pc(process: *const Process, pc: u64) -> u64 {
    process.as_ref().map_or(pc, |p| p.restartable.resume_pc(pc))
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
/// Configure before guest execution. The values describe the default host
/// display in physical pixels and must be finite and positive.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_display(
    process: *mut Process,
    width: u32,
    height: u32,
    scale: f32,
    native_scale: f32,
) {
    if let Some(process) = process.as_mut() {
        if width != 0
            && height != 0
            && scale.is_finite()
            && scale > 0.0
            && native_scale.is_finite()
            && native_scale > 0.0
        {
            process.display_width = width;
            process.display_height = height;
            process.display_scale = scale;
            process.display_native_scale = native_scale;
        }
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
/// Configure before guest execution. The callback maps only a guest-owned host
/// descriptor and returns a Darwin errno without retaining path data.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_map_file(process: *mut Process, callback: Option<MapFile>) {
    if let Some(process) = process.as_mut() {
        process.map_file = callback;
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
/// Configure before guest execution. The metadata callback resolves only
/// virtual guest paths and the host descriptors retained in `files`.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_file_stat(
    process: *mut Process,
    callback: Option<FileStat>,
) {
    if let Some(process) = process.as_mut() {
        process.file_stat = callback;
    }
}

/// # Safety
/// Configure before guest execution. The callback copies only the signed
/// executable's prevalidated entitlement blobs into guest-owned memory.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_code_signature(
    process: *mut Process,
    callback: Option<CodeSignatureBlob>,
) {
    if let Some(process) = process.as_mut() {
        process.code_signature_blob = callback;
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
        memory[..4].copy_from_slice(&0x31u32.to_le_bytes());
        frame.arguments[2] = 0x71b75ace;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        let guarded = u32::from_le_bytes(memory[32..36].try_into().unwrap());
        assert_eq!(process.ports.guard(guarded), Some(0x71b75ace));
        assert_eq!(process.ports.modify_send_refs(guarded, -1), 0);
        memory[..4].copy_from_slice(&0x28abu32.to_le_bytes());
        memory[8..16].copy_from_slice(&0xffff_fffeu64.to_le_bytes());
        frame.arguments[2] = 0x71b75ace;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        let connection = u32::from_le_bytes(memory[32..36].try_into().unwrap());
        assert!(process.ports.has_receive(connection));
        assert_eq!(process.ports.guard(connection), Some(0x71b75ace));
        memory[..4].copy_from_slice(&0x283fu32.to_le_bytes());
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        let sending = u32::from_le_bytes(memory[32..36].try_into().unwrap());
        assert_ne!(sending, connection);
        assert_eq!(process.ports.guard(sending), Some(0x71b75ace));
        assert_eq!(process.ports.modify_send_refs(sending, -1), 0);
        memory[..4].copy_from_slice(&1u32.to_le_bytes());
        assert!(!process.dispatch(&mut frame)); // a requested guard needs context
        assert_eq!(frame.result[0], 46);
    }

    #[test]
    fn port_notification_request_returns_the_previous_name() {
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
        let mut memory = [0u8; 40];
        let mut process = Process::new(1, 0, 2);
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_out = Some(write);
        let target = process.ports.construct(0x10).unwrap();
        let notify = process.ports.construct(0x10).unwrap();
        let mut frame = TrapFrame {
            number: -77,
            arguments: [0x103, target as u64, 69, 0, notify as u64, 21, 32, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert_eq!(u32::from_le_bytes(memory[32..36].try_into().unwrap()), 0);
        assert!(process.dispatch(&mut frame));
        assert!(process.dispatch(&mut frame));
        assert_eq!(
            u32::from_le_bytes(memory[32..36].try_into().unwrap()),
            notify
        );
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
    fn mach_timebase_matches_the_nanosecond_guest_clock() {
        unsafe extern "C" fn copy_out(
            context: *const c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            if address != 8 || size != 8 {
                return 1;
            }
            std::ptr::copy_nonoverlapping(data, (context as *mut u8).add(address as usize), size);
            0
        }
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 16];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_out = Some(copy_out);
        let mut frame = TrapFrame {
            number: -89,
            arguments: [8, 0, 0, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert_eq!(&memory[8..], &[1, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn special_reply_port_is_rebound_with_receive_and_send_rights() {
        let process = Process::new(1, 0, 2);
        let mut first = TrapFrame {
            number: -50,
            ..Default::default()
        };
        assert!(process.dispatch(&mut first));
        let initial = first.result[0] as u32;
        assert_ne!(initial, 0);
        assert!(process.ports.has_receive(initial));
        assert!(process.ports.has_send(initial));
        let mut second = TrapFrame {
            number: -50,
            ..Default::default()
        };
        assert!(process.dispatch(&mut second));
        let replacement = second.result[0] as u32;
        assert_ne!(replacement, 0);
        assert!(!process.ports.has_receive(initial) || replacement == initial);
        assert!(process.ports.has_receive(replacement));
        assert!(process.ports.has_send(replacement));
    }

    #[test]
    fn host_voucher_trap_returns_a_process_owned_port_and_validates_recipe() {
        unsafe extern "C" fn read(
            context: *const c_void,
            address: u64,
            out: *mut u8,
            size: usize,
        ) -> u32 {
            if address != 0 || size != 16 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(context.cast::<u8>().add(32), out, size);
            0
        }
        unsafe extern "C" fn write(
            context: *const c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            if address != 16 || size != 4 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(data, (context as *mut u8).add(16), size);
            0
        }
        let mut memory = [0u8; 64];
        memory[32..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let mut process = Process::new(1, 0, 2);
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let mut frame = TrapFrame {
            number: -70,
            arguments: [0x303, 0, 16, 16, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        let voucher = u32::from_le_bytes(memory[16..20].try_into().unwrap());
        assert_ne!(voucher, 0);
        assert!(process.ports.has_receive(voucher));
        assert!(process.ports.has_send(voucher));
        frame.arguments[2] = 5121;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 4);
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
