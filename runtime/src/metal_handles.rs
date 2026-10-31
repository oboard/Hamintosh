//! C ABI opaque handles for the real Metal-to-Vulkan runtime.
//!
//! Every non-null handle owns its runtime object through a `Box`. Textures,
//! queues, and command buffers retain their parents internally, so parents may
//! be freed after their children are created. A handle must not be used after
//! it is freed, freed more than once, or freed concurrently with another call.
//!
//! Functions returning `i32` use 0 for success, -1 for invalid arguments, -2
//! for a runtime error, -3 for a caught Rust panic, -4 for a truncated JSON
//! buffer, -5 for a readback timeout, and -6 for an unsuccessful command-buffer
//! status. Pointer-returning constructors return null on failure. The most
//! recent error on the calling thread is available as bounded JSON through
//! [`hm_metal_last_error_json`].

use metal2vulkan::metal::{PixelFormat, TextureUsage};
use metal2vulkan_runtime::{
    BlitOption, CommandBuffer, CommandBufferStatus, CommandQueue, Device, DeviceOptions, Origin,
    ResourceOptions, Size, Texture, TextureDescriptor,
};
use serde_json::Value;
use std::cell::RefCell;
use std::fmt::Display;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

const HARMONY_VULKAN_LOADER: &str = "/system/lib64/libvulkan.so";
const READBACK_TIMEOUT: Duration = Duration::from_secs(60);

const HM_METAL_OK: i32 = 0;
const HM_METAL_INVALID_ARGUMENT: i32 = -1;
const HM_METAL_RUNTIME_ERROR: i32 = -2;
const HM_METAL_PANIC: i32 = -3;
const HM_METAL_JSON_TOO_SMALL: i32 = -4;
const HM_METAL_TIMEOUT: i32 = -5;
const HM_METAL_COMMAND_BUFFER_ERROR: i32 = -6;

thread_local! {
    /// Serialized `{"error": ...}` for this thread's most recent failed call.
    static LAST_ERROR_JSON: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Opaque owning device handle. Its layout is private to this module.
pub struct DeviceHandle(Device);

/// Opaque owning texture handle. Its layout is private to this module.
pub struct TextureHandle(Texture);

/// Opaque owning command-queue handle. Its layout is private to this module.
pub struct QueueHandle(CommandQueue);

/// Opaque owning command-buffer handle. Its layout is private to this module.
pub struct CommandBufferHandle(CommandBuffer);

#[derive(Debug)]
struct FfiError {
    code: i32,
    message: String,
}

impl FfiError {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(HM_METAL_INVALID_ARGUMENT, message)
    }

    fn runtime(context: &str, error: impl Display) -> Self {
        Self::new(HM_METAL_RUNTIME_ERROR, format!("{context}: {error}"))
    }
}

fn clear_last_error() {
    LAST_ERROR_JSON.with(|slot| *slot.borrow_mut() = None);
}

fn set_last_error(message: &str) {
    let json = serde_json::to_string(&serde_json::json!({ "error": message }))
        .unwrap_or_else(|_| "{\"error\":\"failed to serialize Metal error\"}".to_owned());
    LAST_ERROR_JSON.with(|slot| *slot.borrow_mut() = Some(json));
}

fn note_panic() {
    // TLS can be unavailable during thread destruction; never let that panic
    // cross the C boundary either.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        set_last_error("Rust panic caught at the Metal FFI boundary");
    }));
}

fn protect_handle<T>(operation: impl FnOnce() -> Result<*mut T, FfiError>) -> *mut T {
    match catch_unwind(AssertUnwindSafe(|| {
        clear_last_error();
        match operation() {
            Ok(handle) => handle,
            Err(error) => {
                set_last_error(&error.message);
                ptr::null_mut()
            }
        }
    })) {
        Ok(handle) => handle,
        Err(_) => {
            note_panic();
            ptr::null_mut()
        }
    }
}

fn protect_code(operation: impl FnOnce() -> Result<(), FfiError>) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        clear_last_error();
        match operation() {
            Ok(()) => HM_METAL_OK,
            Err(error) => {
                set_last_error(&error.message);
                error.code
            }
        }
    })) {
        Ok(code) => code,
        Err(_) => {
            note_panic();
            HM_METAL_PANIC
        }
    }
}

fn protect_free<T>(handle: *mut T) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        clear_last_error();
        if !handle.is_null() {
            // SAFETY: the handle contract transfers the one Box back to Rust.
            unsafe { drop(Box::from_raw(handle)) };
        }
    }));
    if result.is_err() {
        note_panic();
    }
}

fn owned_handle<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

/// Borrow a handle for one protected call.
///
/// # Safety
/// `handle` must be null or a live handle of `T`, and must not be freed during
/// the borrow. The caller cannot manufacture a valid handle except through the
/// corresponding constructor.
unsafe fn handle_ref<'a, T>(handle: *const T, kind: &str) -> Result<&'a T, FfiError> {
    if handle.is_null() {
        return Err(FfiError::invalid(format!("null {kind} handle")));
    }
    // SAFETY: the exported function's contract establishes type and lifetime.
    Ok(unsafe { &*handle })
}

/// Write at most `output_len` bytes, including the trailing NUL.
///
/// # Safety
/// `output` must address `output_len` writable bytes.
unsafe fn write_bytes(
    bytes: &[u8],
    output: *mut c_char,
    output_len: usize,
) -> Result<(), FfiError> {
    if output.is_null() || output_len == 0 {
        return Err(FfiError::invalid(
            "JSON output must be non-null with nonzero capacity",
        ));
    }
    let count = bytes.len().min(output_len - 1);
    // SAFETY: the caller supplies the output range; source and destination do
    // not overlap because the source is Rust-owned JSON storage.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast::<u8>(), count);
        *output.add(count) = 0;
    }
    if count != bytes.len() {
        return Err(FfiError::new(
            HM_METAL_JSON_TOO_SMALL,
            format!(
                "JSON output truncated: {} bytes including NUL required",
                bytes.len().saturating_add(1)
            ),
        ));
    }
    Ok(())
}

/// Serialize and bound a JSON value.
///
/// # Safety
/// `output` must address `output_len` writable bytes.
unsafe fn write_json(
    value: &Value,
    output: *mut c_char,
    output_len: usize,
) -> Result<(), FfiError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| FfiError::runtime("could not serialize JSON", error))?;
    // SAFETY: forwarded from this function's contract.
    unsafe { write_bytes(&bytes, output, output_len) }
}

fn device_options() -> DeviceOptions {
    let mut options = DeviceOptions::default();
    let loader = Path::new(HARMONY_VULKAN_LOADER);
    if loader.exists() {
        options.loader = Some(PathBuf::from(loader));
    }
    options
}

fn command_buffer_error_message(command_buffer: &CommandBuffer) -> Option<String> {
    let error = command_buffer.error()?;
    if let Some(description) = command_buffer.error_description() {
        if !description.is_empty() {
            return Some(description);
        }
    }
    if let Some(refusal) = command_buffer.refusal() {
        return Some(refusal.to_string());
    }
    Some(format!("{error:?}"))
}

fn require_completed(command_buffer: &CommandBuffer) -> Result<(), FfiError> {
    let status = command_buffer.status();
    if status == CommandBufferStatus::Completed {
        return Ok(());
    }
    let message = command_buffer_error_message(command_buffer).unwrap_or_else(|| {
        format!(
            "command buffer ended with status {status:?}: {:?}",
            command_buffer.error()
        )
    });
    Err(FfiError::new(HM_METAL_COMMAND_BUFFER_ERROR, message))
}

/// Create the system default real runtime device, selecting HarmonyOS's Vulkan
/// loader when it exists. Returns null on failure.
#[no_mangle]
pub extern "C" fn hm_metal_device_create() -> *mut DeviceHandle {
    protect_handle(|| {
        let device = Device::system_default_with(&device_options())
            .map_err(|error| FfiError::runtime("could not create Metal device", error))?;
        Ok(owned_handle(DeviceHandle(device)))
    })
}

/// Release a device handle. Null is accepted.
///
/// # Safety
/// `device` must be null or a live handle returned by
/// [`hm_metal_device_create`], transferred here exactly once.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_device_free(device: *mut DeviceHandle) {
    protect_free(device);
}

/// Write `{"name": ...}` for a real device. Returns -4 after writing bounded,
/// truncated JSON if the supplied buffer is too small.
///
/// # Safety
/// `device` must be live; `output` must address `output_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_device_name_json(
    device: *const DeviceHandle,
    output: *mut c_char,
    output_len: usize,
) -> i32 {
    protect_code(|| {
        let device = unsafe { handle_ref(device, "device")? };
        let json = serde_json::json!({ "name": device.0.name() });
        unsafe { write_json(&json, output, output_len) }
    })
}

/// Create a private 2D BGRA8 texture usable as a render target and for shader
/// reads. Returns null on failure.
///
/// # Safety
/// `device` must be a live device handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_device_new_bgra8_texture(
    device: *const DeviceHandle,
    width: u64,
    height: u64,
) -> *mut TextureHandle {
    protect_handle(|| {
        if width == 0 || height == 0 {
            return Err(FfiError::invalid(
                "BGRA8 texture dimensions must be nonzero",
            ));
        }
        let device = unsafe { handle_ref(device, "device")? };
        let mut descriptor =
            TextureDescriptor::texture_2d(PixelFormat::BGRA8Unorm, width, height, false);
        descriptor.usage = TextureUsage::RENDER_TARGET | TextureUsage::SHADER_READ;
        descriptor.resource_options = ResourceOptions::private();
        let texture = device
            .0
            .new_texture(&descriptor)
            .map_err(|error| FfiError::runtime("could not create BGRA8 texture", error))?;
        Ok(owned_handle(TextureHandle(texture)))
    })
}

/// Release a texture handle. Null is accepted.
///
/// # Safety
/// `texture` must be null or a live handle returned by
/// [`hm_metal_device_new_bgra8_texture`], transferred here exactly once.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_texture_free(texture: *mut TextureHandle) {
    protect_free(texture);
}

/// Create a real command queue. Returns null on failure.
///
/// # Safety
/// `device` must be a live device handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_device_new_command_queue(
    device: *const DeviceHandle,
) -> *mut QueueHandle {
    protect_handle(|| {
        let device = unsafe { handle_ref(device, "device")? };
        let queue = device
            .0
            .new_command_queue()
            .map_err(|error| FfiError::runtime("could not create command queue", error))?;
        Ok(owned_handle(QueueHandle(queue)))
    })
}

/// Release a command-queue handle. Null is accepted.
///
/// # Safety
/// `queue` must be null or a live handle returned by
/// [`hm_metal_device_new_command_queue`], transferred here exactly once.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_queue_free(queue: *mut QueueHandle) {
    protect_free(queue);
}

/// Create a command buffer on an existing queue. Returns null on failure.
///
/// # Safety
/// `queue` must be a live command-queue handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_queue_command_buffer(
    queue: *const QueueHandle,
) -> *mut CommandBufferHandle {
    protect_handle(|| {
        let queue = unsafe { handle_ref(queue, "command queue")? };
        let command_buffer = queue
            .0
            .command_buffer()
            .map_err(|error| FfiError::runtime("could not create command buffer", error))?;
        Ok(owned_handle(CommandBufferHandle(command_buffer)))
    })
}

/// Release a command-buffer handle. Null is accepted.
///
/// # Safety
/// `command_buffer` must be null or a live handle returned by
/// [`hm_metal_queue_command_buffer`], transferred here exactly once.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_command_buffer_free(command_buffer: *mut CommandBufferHandle) {
    protect_free(command_buffer);
}

/// Commit the command buffer's real encoded work.
///
/// # Safety
/// `command_buffer` must be a live command-buffer handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_command_buffer_commit(
    command_buffer: *mut CommandBufferHandle,
) -> i32 {
    protect_code(|| {
        unsafe { handle_ref(command_buffer, "command buffer")? }
            .0
            .commit()
            .map_err(|error| FfiError::runtime("could not commit command buffer", error))
    })
}

/// Wait without a timeout for completion and require `Completed` status.
///
/// # Safety
/// `command_buffer` must be a live command-buffer handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_command_buffer_wait_until_completed(
    command_buffer: *mut CommandBufferHandle,
) -> i32 {
    protect_code(|| {
        let command_buffer = unsafe { handle_ref(command_buffer, "command buffer")? };
        command_buffer
            .0
            .wait_until_completed()
            .map_err(|error| FfiError::runtime("could not wait for command buffer", error))?;
        require_completed(&command_buffer.0)
    })
}

/// Write the real status and error as bounded JSON. The object contains
/// `status`, `statusCode`, `error`, and `errorCode`; error fields are null when
/// the command buffer has not failed.
///
/// # Safety
/// `command_buffer` must be live; `output` must address `output_len` writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_command_buffer_error_json(
    command_buffer: *const CommandBufferHandle,
    output: *mut c_char,
    output_len: usize,
) -> i32 {
    protect_code(|| {
        let command_buffer = unsafe { handle_ref(command_buffer, "command buffer")? }
            .0
            .clone();
        let status = command_buffer.status();
        let error = command_buffer.error();
        let message = command_buffer_error_message(&command_buffer);
        let json = serde_json::json!({
            "status": format!("{status:?}"),
            "statusCode": status.raw(),
            "error": message,
            "errorCode": error.map(|value| value.metal_code()),
        });
        unsafe { write_json(&json, output, output_len) }
    })
}

/// Read the full texture as real BGRA bytes using a texture-to-buffer blit on
/// `queue`, followed by commit and a bounded wait. Pass the same queue used for
/// rendering so earlier committed rendering is ordered before this readback.
/// Row padding in `output` is left unchanged.
///
/// # Safety
/// `texture` and `queue` must be live handles; `output` must address at least
/// the validated `(height - 1) * stride + width * 4` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_texture_read_bgra(
    texture: *const TextureHandle,
    queue: *const QueueHandle,
    output: *mut u8,
    output_len: usize,
    stride: usize,
) -> i32 {
    protect_code(|| {
        let texture = unsafe { handle_ref(texture, "texture")? };
        let queue = unsafe { handle_ref(queue, "command queue")? };
        if output.is_null() {
            return Err(FfiError::invalid("null BGRA output buffer"));
        }

        let width = texture.0.width();
        let height = texture.0.height();
        let row_bytes_u64 = width
            .checked_mul(4)
            .ok_or_else(|| FfiError::invalid("BGRA row size overflows u64"))?;
        let readback_len_u64 = row_bytes_u64
            .checked_mul(height)
            .ok_or_else(|| FfiError::invalid("BGRA readback size overflows u64"))?;
        let row_bytes = usize::try_from(row_bytes_u64)
            .map_err(|_| FfiError::invalid("BGRA row size does not fit usize"))?;
        let readback_len = usize::try_from(readback_len_u64)
            .map_err(|_| FfiError::invalid("BGRA readback size does not fit usize"))?;
        let height = usize::try_from(height)
            .map_err(|_| FfiError::invalid("texture height does not fit usize"))?;
        if height == 0 || stride < row_bytes {
            return Err(FfiError::invalid(format!(
                "BGRA stride {stride} is smaller than row size {row_bytes}"
            )));
        }
        let required = (height - 1)
            .checked_mul(stride)
            .and_then(|prefix| prefix.checked_add(row_bytes))
            .ok_or_else(|| FfiError::invalid("BGRA output range overflows usize"))?;
        if output_len < required {
            return Err(FfiError::invalid(format!(
                "BGRA output buffer has {output_len} bytes; {required} required"
            )));
        }

        let readback = texture
            .0
            .device()
            .new_buffer(readback_len_u64, ResourceOptions::shared())
            .map_err(|error| FfiError::runtime("could not create readback buffer", error))?;
        let command_buffer = queue.0.command_buffer().map_err(|error| {
            FfiError::runtime("could not create readback command buffer", error)
        })?;
        let mut blit = command_buffer
            .blit_command_encoder()
            .map_err(|error| FfiError::runtime("could not create readback blit encoder", error))?;
        blit.copy_from_texture_to_buffer(
            &texture.0,
            0,
            0,
            Origin::new(0, 0, 0),
            Size::new(width, texture.0.height(), 1),
            &readback,
            0,
            row_bytes_u64,
            readback_len_u64,
            BlitOption::None,
        )
        .map_err(|error| FfiError::runtime("could not encode BGRA readback", error))?;
        blit.end_encoding()
            .map_err(|error| FfiError::runtime("could not end BGRA readback encoder", error))?;
        command_buffer
            .commit()
            .map_err(|error| FfiError::runtime("could not commit BGRA readback", error))?;
        command_buffer
            .wait_until_completed_for(READBACK_TIMEOUT)
            .map_err(|_| {
                FfiError::new(
                    HM_METAL_TIMEOUT,
                    "BGRA readback did not complete within 60 seconds",
                )
            })?;
        require_completed(&command_buffer)?;

        let contents = readback.contents().ok_or_else(|| {
            FfiError::new(
                HM_METAL_RUNTIME_ERROR,
                "shared readback buffer has no CPU contents",
            )
        })?;
        // SAFETY: completion ended GPU writes; `contents` covers the validated
        // shared-buffer length. The output range was checked before submission,
        // and its row padding is never touched.
        unsafe {
            let bytes = std::slice::from_raw_parts(contents.as_ptr(), readback_len);
            for row in 0..height {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(row * row_bytes),
                    output.add(row * stride),
                    row_bytes,
                );
            }
        }
        Ok(())
    })
}

/// Copy this thread's most recent error as bounded JSON, or `{"error":null}`
/// when there is none. This query does not clear the stored error.
///
/// # Safety
/// `output` must address `output_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_last_error_json(output: *mut c_char, output_len: usize) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        let json = LAST_ERROR_JSON.with(|slot| {
            slot.borrow()
                .clone()
                .unwrap_or_else(|| "{\"error\":null}".to_owned())
        });
        unsafe { write_bytes(json.as_bytes(), output, output_len) }
    })) {
        Ok(Ok(())) => HM_METAL_OK,
        Ok(Err(error)) => error.code,
        Err(_) => HM_METAL_PANIC,
    }
}
