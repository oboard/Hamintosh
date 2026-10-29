//! Minimal process identity and Darwin ARM64 syscall ABI.
//!
//! Called on the synchronous trap path without allocation, locks or panic.
//! Native callbacks supply validated VM operations and the host random source.
//! Mach self ports identify real objects in this process model; IPC is separate.
use std::ffi::{c_char, c_void};
use std::mem::size_of;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
mod activity;
mod csops;
mod display;
mod files;
mod iokit;
pub(crate) mod ipc;
mod kevent;
mod memory;
mod ports;
mod proc_info;
mod restartable;
mod sandbox;
mod semwait;
mod signals;
mod sysctl;
mod threads;
mod time;
mod ulock;
mod workloop_sync;
mod workqueue;
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
pub type AotMapFile = unsafe extern "C" fn(*const c_void, *mut u64, u64, u32, u32, i32, u64) -> u32;
pub type Fcntl = unsafe extern "C" fn(*const c_void, i32, u32, u64) -> u32;
pub type VmRemap = unsafe extern "C" fn(
    *const c_void,
    *mut u64,
    u64,
    u64,
    u32,
    u64,
    u32,
    *mut u32,
    *mut u32,
    u32,
) -> u32;
pub type VmDeallocate = unsafe extern "C" fn(*const c_void, u64, u64) -> u32;
pub type Open =
    unsafe extern "C" fn(*const c_void, i32, *const u8, usize, u32, u32, *mut i32) -> u32;
pub type Close = unsafe extern "C" fn(*const c_void, i32) -> u32;
pub type Duplicate = unsafe extern "C" fn(*const c_void, i32, *mut i32) -> u32;
pub type ReadDirectory =
    unsafe extern "C" fn(*const c_void, i32, *mut u8, usize, *mut usize, *mut i64) -> u32;
pub type FileRead =
    unsafe extern "C" fn(*const c_void, i32, *mut u8, usize, i64, *mut usize) -> u32;
pub type FileSeek = unsafe extern "C" fn(*const c_void, i32, i64, u32, *mut i64) -> u32;
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
    pub(crate) pid: u32,
    pub(crate) parent_pid: u32,
    pub(crate) thread_id: u64,
    pub(crate) executable: *const c_char,
    pub(crate) executable_len: usize,
    pub(crate) tsd_base: AtomicU64,
    pub(crate) stopping: std::sync::atomic::AtomicBool,
    pub(crate) wait_leave: Option<unsafe extern "C" fn()>,
    pub(crate) wait_enter: Option<unsafe extern "C" fn()>,
    pub(crate) thread_start: AtomicU64,
    pub(crate) wq_thread: AtomicU64,
    pub(crate) tsd_offset: AtomicU64,
    pub(crate) pthread_size: AtomicU32,
    pub(crate) mach_thread_self_offset: AtomicU32,
    pub(crate) dispatchqueue_offset: AtomicU64,
    pub(crate) signal_mask: AtomicU32,
    pub(crate) identity_ports: [(i32, u32); 3],
    pub(crate) ports: crate::mach::Space,
    pub(crate) bootstrap_port: AtomicU32,
    pub(crate) notification_center_port: AtomicU32,
    pub(crate) backboard_hid_services_port: AtomicU32,
    pub(crate) debug_control_port: AtomicU32,
    pub(crate) io_main_port: AtomicU32,
    pub(crate) io_registry_port: AtomicU32,
    pub(crate) io_display_service_port: AtomicU32,
    pub(crate) iokit: iokit::State,
    pub(crate) special_reply_port: AtomicU32,
    pub(crate) clock_port: AtomicU32,
    pub(crate) semaphore_port: AtomicU32,
    pub(crate) xpc: xpc::State,
    pub(crate) restartable: restartable::Ranges,
    pub(crate) mig: crate::mig::MigRegistry,
    pub(crate) bootstrap_namespace: crate::services::BootstrapNamespace,
    pub(crate) workqueue: kevent::State,
    pub(crate) root_threads: workqueue::State,
    pub(crate) vm_protect: Option<VmProtect>,
    pub(crate) get_entropy: Option<GetEntropy>,
    pub(crate) copy_out: Option<CopyOut>,
    pub(crate) copy_in: Option<CopyIn>,
    pub(crate) shared_region_base: u64,
    pub(crate) display_width: u32,
    pub(crate) display_height: u32,
    pub(crate) display_scale: f32,
    pub(crate) display_native_scale: f32,
    pub(crate) clock: Option<Clock>,
    pub(crate) console: Option<Console>,
    pub(crate) vm_map: Option<VmMap>,
    pub(crate) vm_remap: Option<VmRemap>,
    pub(crate) map_file: Option<MapFile>,
    pub(crate) aot_map_file: Option<AotMapFile>,
    pub(crate) fcntl: Option<Fcntl>,
    pub(crate) vm_deallocate: Option<VmDeallocate>,
    pub(crate) open: Option<Open>,
    pub(crate) close: Option<Close>,
    pub(crate) duplicate: Option<Duplicate>,
    pub(crate) file_stat: Option<FileStat>,
    pub(crate) read_directory: Option<ReadDirectory>,
    pub(crate) file_read: Option<FileRead>,
    pub(crate) file_seek: Option<FileSeek>,
    pub(crate) code_signature_blob: Option<CodeSignatureBlob>,
    pub(crate) resolve_file_id: Option<ResolveFileId>,
    pub(crate) files: crate::vfs::Files,
    pub(crate) host_context: *const c_void,
    pub handled: AtomicU64,
    pub unsupported: AtomicU64,
    pub last_unsupported: AtomicI32,
}

impl Process {
    // libpthread/kern/kern_internal.h: packed registration data, size-versioned.
    // x6 is not a bsdthread_register argument. Modern TSD offsets come from
    // the copy-in structure at x3, not leftover values in that register.
    fn register_pthread(&self, frame: &TrapFrame) -> Result<(), u32> {
        let size = frame.arguments[2];
        if frame.arguments[0] == 0 || frame.arguments[1] == 0 || !(8..=32768).contains(&size) {
            return Err(22);
        }
        if self.wq_thread.load(Ordering::Acquire) != 0 {
            return Err(22);
        }
        let (mut tsd, mut mach_self) = (0, 0);
        let mut dispatch = frame.arguments[5];
        if frame.arguments[3] != 0 {
            let len = frame.arguments[4];
            if !(36..=4096).contains(&len) {
                return Err(22);
            }
            let Some(read) = self.copy_in else {
                return Err(14);
            };
            let mut bytes = [0u8; 60];
            let copied = len.min(bytes.len() as u64) as usize;
            if unsafe {
                read(
                    self.host_context,
                    frame.arguments[3],
                    bytes.as_mut_ptr(),
                    copied,
                )
            } != 0
            {
                return Err(14);
            }
            if u64::from_le_bytes(bytes[..8].try_into().unwrap()) != len {
                return Err(22);
            }
            dispatch = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
            tsd = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as u64;
            mach_self = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
            if tsd % 8 != 0
                || tsd > size - 8
                || !dispatch.is_multiple_of(8)
                || dispatch > size - tsd - 8
                || mach_self % 8 != 0
                || u64::from(mach_self) > size - tsd - 8
            {
                return Err(22);
            }
        }
        self.thread_start
            .store(frame.arguments[0], Ordering::Relaxed);
        self.dispatchqueue_offset.store(dispatch, Ordering::Relaxed);
        self.tsd_offset.store(tsd, Ordering::Relaxed);
        self.pthread_size.store(size as u32, Ordering::Relaxed);
        self.mach_thread_self_offset
            .store(mach_self, Ordering::Relaxed);
        self.wq_thread.store(frame.arguments[1], Ordering::Release);
        Ok(())
    }

    pub fn new(pid: u32, parent_pid: u32, thread_id: u64) -> Self {
        Self {
            pid,
            parent_pid,
            thread_id,
            executable: std::ptr::null(),
            executable_len: 0,
            tsd_base: AtomicU64::new(0),
            stopping: std::sync::atomic::AtomicBool::new(false),
            wait_leave: None,
            wait_enter: None,
            thread_start: AtomicU64::new(0),
            wq_thread: AtomicU64::new(0),
            tsd_offset: AtomicU64::new(0),
            pthread_size: AtomicU32::new(0),
            mach_thread_self_offset: AtomicU32::new(0),
            dispatchqueue_offset: AtomicU64::new(0),
            signal_mask: AtomicU32::new(0),
            // Per-process Mach name space: index in the high bits, generation 3.
            // These rights refer to this task, its bootstrap thread and its host.
            identity_ports: [(-28, 0x103), (-27, 0x203), (-29, 0x303)],
            ports: crate::mach::Space::default(),
            bootstrap_port: AtomicU32::new(0),
            notification_center_port: AtomicU32::new(0),
            backboard_hid_services_port: AtomicU32::new(0),
            debug_control_port: AtomicU32::new(0),
            io_main_port: AtomicU32::new(0),
            io_registry_port: AtomicU32::new(0),
            io_display_service_port: AtomicU32::new(0),
            iokit: iokit::State::default(),
            special_reply_port: AtomicU32::new(0),
            clock_port: AtomicU32::new(0),
            semaphore_port: AtomicU32::new(0),
            xpc: xpc::State::default(),
            restartable: restartable::Ranges::default(),
            mig: crate::mig::default_registry(),
            bootstrap_namespace: crate::services::default_bootstrap(),
            workqueue: kevent::State::default(),
            root_threads: workqueue::State::default(),
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
            vm_remap: None,
            map_file: None,
            aot_map_file: None,
            fcntl: None,
            vm_deallocate: None,
            open: None,
            close: None,
            duplicate: None,
            file_stat: None,
            read_directory: None,
            file_read: None,
            file_seek: None,
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
        // Cancellation is handled by the guest pthread wrappers. The nocancel
        // variants use the same file ABI and ownership checks in this kernel.
        let number = match frame.number as i32 {
            397 => 4,
            398 => 5,
            399 => 6,
            406 => 92,
            464 => 463,
            number => number,
        };
        // Identity and workqueue queries used by Foundation and libdispatch.
        // HarmonyOS reports the application sandbox as uid/gid 2000.
        if matches!(number, 24 | 25 | 43 | 47 | 327 | 367) {
            let value = match number {
                24 | 25 => 2000,
                43 | 47 => 20,
                _ => 0,
            };
            frame.result = [value, 0];
            frame.nzcv &= !CARRY;
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if number == 286 {
            let Some(copy_out) = self.copy_out else {
                frame.result = [14, 0];
                frame.nzcv |= CARRY;
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            };
            let uid = 2000u32.to_le_bytes();
            let gid = 20u32.to_le_bytes();
            let error = if frame.arguments[0] == 0 || frame.arguments[1] == 0 {
                14
            } else {
                let uid_error = unsafe {
                    copy_out(
                        self.host_context,
                        frame.arguments[0],
                        uid.as_ptr(),
                        uid.len(),
                    )
                };
                let gid_error = uid_error != 0
                    || unsafe {
                        copy_out(
                            self.host_context,
                            frame.arguments[1],
                            gid.as_ptr(),
                            gid.len(),
                        )
                    } != 0;
                if gid_error {
                    14
                } else {
                    0
                }
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
            let previous = threads::swap_reply(self, 0);
            if previous != 0 {
                self.ports.discard_unpublished(previous);
            }
            let name = self.ports.construct(0x10).unwrap_or(0);
            threads::swap_reply(self, name);
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
                            if flags & 2 != 0 {
                                let limit = u32::from_le_bytes(options[4..8].try_into().unwrap());
                                if let Err(error) = self.ports.set_queue_limit(name, limit) {
                                    self.ports.discard_unpublished(name);
                                    frame.result = [u64::from(error), 0];
                                    frame.nzcv &= !CARRY;
                                    self.handled.fetch_add(1, Ordering::Relaxed);
                                    return true;
                                }
                            }
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
            if let Some((error, result)) = proc_info::query(self, frame) {
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
        if number == 33 {
            if let Some(error) = files::access(self, frame) {
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
        if number == 344 {
            if let Some(result) = files::directory(self, frame) {
                match result {
                    Ok(value) => {
                        frame.result = [value, 0];
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
        if matches!(number, 3 | 153 | 199 | 396 | 414) {
            let result = if number == 199 {
                files::seek(self, frame)
            } else {
                files::read(self, frame)
            };
            if let Some(result) = result {
                match result {
                    Ok(value) => {
                        frame.result = [value, 0];
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
        if matches!(number, 338 | 339 | 340 | 470) {
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
        if number == 92 && matches!(frame.arguments[1], 97 | 98) {
            let error = match (self.files.host(frame.arguments[0] as u32), self.fcntl) {
                (None, _) => 9,
                (Some(fd), Some(callback)) => unsafe {
                    callback(
                        self.host_context,
                        fd,
                        frame.arguments[1] as u32,
                        frame.arguments[2],
                    )
                },
                _ => 78,
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
                threads::set_tsd(self, frame.arguments[0]);
                frame.result = [frame.arguments[0], frame.arguments[1]];
            } else {
                frame.result = [threads::tsd(self), frame.arguments[1]];
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
            const WQOPS_THREAD_RETURN: u64 = 0x4;
            const WQOPS_THREAD_KEVENT_RETURN: u64 = 0x40;
            const WQOPS_THREAD_WORKLOOP_RETURN: u64 = 0x100;
            const WQOPS_SETUP_DISPATCH: u64 = 0x400;
            if matches!(
                frame.arguments[0],
                WQOPS_THREAD_RETURN | WQOPS_THREAD_KEVENT_RETURN | WQOPS_THREAD_WORKLOOP_RETURN
            ) {
                frame.result = [0, 0];
                frame.nzcv &= !CARRY;
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            if frame.arguments[0] == 0x20 && self.wait_leave.is_some() && self.wait_enter.is_some()
            {
                match self
                    .root_threads
                    .request(frame.arguments[2] as u32, frame.arguments[3] as u32)
                {
                    Ok(()) => {
                        frame.result = [0, 0];
                        frame.nzcv &= !CARRY;
                    }
                    Err(error) => {
                        frame.result = [u64::from(error), 0];
                        frame.nzcv |= CARRY;
                    }
                }
                self.handled.fetch_add(1, Ordering::Relaxed);
                return true;
            }
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
        if matches!(number, 515 | 516 | 544) {
            let owner = self as *const Self as usize;
            let result = if number != 516 {
                ulock::wait_controlled(
                    self.copy_in,
                    self.host_context,
                    owner,
                    frame,
                    Some(ulock::WaitControl {
                        stopping: &self.stopping,
                        leave: self.wait_leave,
                        enter: self.wait_enter,
                    }),
                    self.clock,
                )
            } else {
                ulock::wake(owner, frame)
            };
            ulock::apply(frame, result, CARRY);
            self.handled.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if number == 366 {
            let result = self.register_pthread(frame);
            match result {
                Ok(()) => {
                    // A live native scheduler is required before libdispatch may
                    // install/use its workloop callback. Without bit 7 it
                    // leaves that callback null even if requests are issued.
                    let workloop = if self.wait_leave.is_some() && self.wait_enter.is_some() {
                        0x80
                    } else {
                        0
                    };
                    frame.result = [0x4000_001e | workloop, 0];
                    frame.nzcv &= !CARRY;
                }
                Err(error) => {
                    frame.result = [u64::from(error), 0];
                    frame.nzcv |= CARRY;
                }
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
            372 => Some(threads::id(self)),
            -27 if threads::port(self).is_some() => {
                let port = threads::port(self).unwrap();
                self.ports.acquire_send(port).then_some(u64::from(port))
            }
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
            -19 if frame.arguments[0] == 0x103 && frame.arguments[2] == 0 => {
                let result = self
                    .ports
                    .modify_send_refs(frame.arguments[1] as u32, frame.arguments[3] as u32 as i32);
                self.iokit.reap(self);
                Some(result as u64)
            }
            -43 => activity::generate(self, frame).map(u64::from),
            -18 if frame.arguments[0] == 0x103 => {
                let result = self.ports.deallocate(frame.arguments[1] as u32);
                self.iokit.reap(self);
                Some(result as u64)
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
/// `path` must remain valid for the lifetime of `process`; callers configure
/// this before guest execution.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_executable(
    process: *mut Process,
    path: *const c_char,
    length: usize,
) {
    if let Some(process) = process.as_mut() {
        process.executable = path;
        process.executable_len = length;
    }
}

/// # Safety
/// `process` is a live process context for the current guest thread.
#[no_mangle]
pub unsafe extern "C" fn hm_process_tsd_base(process: *const Process) -> u64 {
    process.as_ref().map_or(0, threads::tsd)
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

/// Register remapping of explicitly registered signed AOT trampoline pages.
/// # Safety
/// The callback must remain valid until the process is destroyed.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_vm_remap(process: *mut Process, callback: Option<VmRemap>) {
    if let Some(process) = process.as_mut() {
        process.vm_remap = callback;
    }
}

/// Register the native verifier for already signed, immutable AOT dylibs.
/// # Safety
/// The callback must remain valid until the process is destroyed.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_aot_map_file(
    process: *mut Process,
    callback: Option<AotMapFile>,
) {
    if let Some(process) = process.as_mut() {
        process.aot_map_file = callback;
    }
}

/// Register descriptor-based code-signature/library-validation checks.
/// # Safety
/// The callback must remain valid until the process is destroyed.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_fcntl(process: *mut Process, callback: Option<Fcntl>) {
    if let Some(process) = process.as_mut() {
        process.fcntl = callback;
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
/// Configure before guest execution. Callbacks operate only on registered
/// host descriptors; read writes at most the supplied buffer size.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_file_io(
    process: *mut Process,
    read: Option<FileRead>,
    seek: Option<FileSeek>,
) {
    if let Some(process) = process.as_mut() {
        process.file_read = read;
        process.file_seek = seek;
    }
}

/// # Safety
/// Configure before guest execution; callback emits bounded Darwin direntries
/// from a registered host directory descriptor without allocating.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_directory_reader(
    process: *mut Process,
    read: Option<ReadDirectory>,
) {
    if let Some(process) = process.as_mut() {
        process.read_directory = read;
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

/// # Safety
/// Configure on an owned process before guest threads start. The callbacks
/// release/reacquire the native execution gate around a real blocked wait.
#[no_mangle]
pub unsafe extern "C" fn hm_process_set_wait_hooks(
    process: *mut Process,
    leave: Option<unsafe extern "C" fn()>,
    enter: Option<unsafe extern "C" fn()>,
) {
    if let Some(process) = process.as_mut() {
        process.wait_leave = leave;
        process.wait_enter = enter;
    }
}

/// # Safety
/// The process is live. Cancellation is for shutdown, never a successful wake.
#[no_mangle]
pub unsafe extern "C" fn hm_process_stop_threads(process: *const Process) {
    if let Some(process) = process.as_ref() {
        process.stopping.store(true, Ordering::Release);
    }
}

/// # Safety
/// Retrieves registered bsdthread entry points.
#[no_mangle]
pub unsafe extern "C" fn hm_process_get_bsdthread_registration(
    process: *const Process,
    thread_start: *mut u64,
    wq_thread: *mut u64,
    tsd_offset: *mut u64,
    dispatchqueue_offset: *mut u64,
) -> bool {
    let Some(process) = process.as_ref() else {
        return false;
    };
    let ts = process.thread_start.load(Ordering::Acquire);
    let wq = process.wq_thread.load(Ordering::Acquire);
    if ts == 0 || wq == 0 {
        return false;
    }
    if !thread_start.is_null() {
        *thread_start = ts;
    }
    if !wq_thread.is_null() {
        *wq_thread = wq;
    }
    if !tsd_offset.is_null() {
        *tsd_offset = process.tsd_offset.load(Ordering::Acquire);
    }
    if !dispatchqueue_offset.is_null() {
        *dispatchqueue_offset = process.dispatchqueue_offset.load(Ordering::Acquire);
    }
    true
}

/// # Safety
/// `process` is live and `out` points to two writable u32 values.
#[no_mangle]
pub unsafe extern "C" fn hm_process_pthread_layout(process: *const Process, out: *mut u32) -> bool {
    let Some(process) = process.as_ref() else {
        return false;
    };
    if out.is_null() || process.wq_thread.load(Ordering::Acquire) == 0 {
        return false;
    }
    *out = process.pthread_size.load(Ordering::Relaxed);
    *out.add(1) = process.mach_thread_self_offset.load(Ordering::Relaxed);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn test_fcntl(
        context: *const c_void,
        fd: i32,
        command: u32,
        argument: u64,
    ) -> u32 {
        let observed = &mut *(context as *mut [u64; 3]);
        *observed = [fd as u64, command as u64, argument];
        if argument == 0xbad {
            14
        } else {
            0
        }
    }

    #[test]
    fn library_validation_uses_owned_host_descriptor_and_propagates_errno() {
        let mut process = Process::new(1, 0, 2);
        let mut observed = [0u64; 3];
        process.host_context = observed.as_mut_ptr().cast();
        process.fcntl = Some(test_fcntl);
        let fd = process.files.insert(91).unwrap();
        let mut frame = TrapFrame {
            number: 92,
            arguments: [fd as u64, 97, 0x1000, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0, 0]);
        assert_eq!(observed, [91, 97, 0x1000]);
        frame.arguments[2] = 0xbad;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [14, 0]);
        assert_ne!(frame.nzcv & CARRY, 0);
        frame.arguments[0] = 91;
        observed = [0; 3];
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [9, 0]);
        assert_eq!(observed, [0; 3]);
    }

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
        assert_eq!(name >> 8, 4); // slot reused with a fresh generation
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
    fn registration_reads_the_packed_abi_and_rejects_invalid_layouts() {
        unsafe extern "C" fn read(
            context: *const c_void,
            address: u64,
            out: *mut u8,
            len: usize,
        ) -> u32 {
            if address != 0x1000 || len > 60 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(context as *const u8, out, len);
            0
        }
        let mut bytes = [0u8; 60];
        bytes[..8].copy_from_slice(&60u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&160u64.to_le_bytes());
        bytes[24..28].copy_from_slice(&224u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&24u32.to_le_bytes());
        let mut frame = TrapFrame {
            number: 366,
            arguments: [
                0xee001234,
                0xab005678,
                0x4000,
                0x1000,
                60,
                160,
                0x4f00000000,
                0,
            ],
            ..Default::default()
        };
        let mut process = Process::new(1, 0, 2);
        process.copy_in = Some(read);
        process.host_context = bytes.as_ptr().cast();
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0x4000001e);
        assert_eq!(process.tsd_offset.load(Ordering::Acquire), 224);
        assert_eq!(process.pthread_size.load(Ordering::Relaxed), 0x4000);
        assert_eq!(process.mach_thread_self_offset.load(Ordering::Relaxed), 24);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 22); // Duplicate registration.
        let mut invalid = Process::new(1, 0, 2);
        invalid.copy_in = Some(read);
        invalid.host_context = bytes.as_ptr().cast();
        bytes[24..28].copy_from_slice(&0x4000u32.to_le_bytes());
        assert!(invalid.dispatch(&mut frame));
        assert_eq!(frame.result[0], 22);
        assert_eq!(invalid.wq_thread.load(Ordering::Acquire), 0);
        bytes[24..28].copy_from_slice(&224u32.to_le_bytes());
        frame.arguments[3] = 0x2000;
        assert!(invalid.dispatch(&mut frame));
        assert_eq!(frame.result[0], 14);
    }

    #[test]
    fn workloop_feature_requires_a_native_scheduler() {
        unsafe extern "C" fn gate() {}
        let mut process = Process::new(1, 0, 2);
        let mut trap = TrapFrame {
            number: 366,
            arguments: [0x1000, 0x2000, 0x4000, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        process.wait_enter = Some(gate);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0] & 0x80, 0);
        let mut process = Process::new(1, 0, 2);
        process.wait_enter = Some(gate);
        process.wait_leave = Some(gate);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0], 0x4000009e);
    }

    #[test]
    fn attached_threads_have_independent_tsd_ids_and_reply_ports() {
        let process = Process::new(1, 0, 2);
        let address = &process as *const Process as usize;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let workers: Vec<_> = (10..12)
            .map(|id| {
                let barrier = barrier.clone();
                std::thread::spawn(move || unsafe {
                    let process = &*(address as *const Process);
                    let port = threads::hm_process_attach_thread(process, id, id * 4096);
                    assert_ne!(port, 0);
                    barrier.wait();
                    assert_eq!(hm_process_tsd_base(process), id * 4096);
                    let mut trap = TrapFrame {
                        number: 372,
                        ..Default::default()
                    };
                    assert!(process.dispatch(&mut trap));
                    assert_eq!(trap.result[0], id);
                    trap.number = -27;
                    assert!(process.dispatch(&mut trap));
                    assert_eq!(trap.result[0], u64::from(port));
                    trap.number = -50;
                    assert!(process.dispatch(&mut trap));
                    let reply = trap.result[0];
                    barrier.wait();
                    assert!(process.ports.has_receive(reply as u32));
                    threads::hm_process_detach_thread(process);
                    assert_eq!(hm_process_tsd_base(process), 0);
                    (port, reply)
                })
            })
            .collect();
        barrier.wait();
        assert_eq!(unsafe { hm_process_tsd_base(&process) }, 0);
        barrier.wait();
        let first = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>();
        assert_ne!(first[0].0, first[1].0);
        assert_ne!(first[0].1, first[1].1);
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
    fn sandbox_identity_and_workqueue_queries_are_consistent() {
        let mut process = Process::new(1, 0, 2);
        for (number, expected) in [
            (24, 2000),
            (25, 2000),
            (43, 20),
            (47, 20),
            (327, 0),
            (367, 0),
        ] {
            let mut frame = TrapFrame {
                number,
                nzcv: CARRY,
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], expected);
            assert_eq!(frame.nzcv & CARRY, 0);
        }

        unsafe extern "C" fn write(
            context: *const c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            if size != 4 || address != 16 && address != 32 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(data, (context as *mut u8).add(address as usize), size);
            0
        }
        let mut memory = [0u8; 40];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_out = Some(write);
        let mut frame = TrapFrame {
            number: 286,
            arguments: [16, 32, 0, 0, 0, 0, 0, 0],
            nzcv: CARRY,
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert_eq!(u32::from_le_bytes(memory[16..20].try_into().unwrap()), 2000);
        assert_eq!(u32::from_le_bytes(memory[32..36].try_into().unwrap()), 20);
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
