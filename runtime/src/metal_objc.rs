//! Minimal C ABI for the guest Objective-C Metal facade.
//!
//! Every nonzero handle owns a real metal2vulkan-runtime object. The C++ side
//! owns the corresponding Objective-C object and releases the handle from its
//! `-dealloc`; clone operations retain the underlying Rust `Arc` rather than
//! manufacturing a second view of raw Vulkan state.

use metal2vulkan::bind::SamplerDescriptor;
use metal2vulkan::library::{FunctionConstantValue, FunctionConstantValues};
use metal2vulkan::metal::{
    BlendFactor, BlendOperation, ColorWriteMask, CompareFunction, DataType, FunctionOptions,
    IndexType, PixelFormat, PrimitiveType, SamplerAddressMode, SamplerBorderColor,
    SamplerMinMagFilter, SamplerMipFilter, SamplerReductionMode, TextureUsage, VertexFormat,
    VertexStepFunction,
};
use metal2vulkan::pipeline::{
    ColorAttachmentDescriptor, RenderPipelineDescriptor, StageSource, VertexAttributeDescriptor,
    VertexBufferLayoutDescriptor, VertexDescriptor,
};
use metal2vulkan_runtime::{
    Buffer, ClearColor, CommandBuffer, CommandBufferStatus, CommandQueue, CpuCacheMode, Device,
    DeviceOptions, Function, FunctionDescriptor as RuntimeFunctionDescriptor, HazardTrackingMode,
    Library, LoadAction, PipelineOptions, PrivateCount, Region, RenderCommandEncoder,
    RenderPassDescriptor, RenderPipelineState, ResourceOptions, SamplerState, SamplerStateOptions,
    ScissorRect, StorageMode, StoreAction, StoreActionOptions, Texture, TextureDescriptor,
    Viewport,
};
use std::cell::RefCell;
use std::ffi::{c_char, c_void, CString};
use std::path::Path;
use std::ptr;
use std::time::Duration;

/// C layout shared with ca_renderer_probe.cpp. All fields use Metal's raw
/// 64-bit `NSUInteger` representation on the ARM64 guest.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HmMetalTextureInfo {
    pub device_registry_id: u64,
    pub pixel_format: u64,
    pub texture_type: u64,
    pub width: u64,
    pub height: u64,
    pub depth: u64,
    pub mipmap_level_count: u64,
    pub array_length: u64,
    pub sample_count: u64,
    pub usage: u64,
    pub storage_mode: u64,
    pub cpu_cache_mode: u64,
    pub hazard_tracking_mode: u64,
    pub resource_options: u64,
    pub allow_gpu_optimized_contents: u64,
}

/// C layout shared with ca_renderer_probe.cpp for `MTLRegion` readback.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HmMetalRegion {
    pub origin_x: u64,
    pub origin_y: u64,
    pub origin_z: u64,
    pub width: u64,
    pub height: u64,
    pub depth: u64,
}

/// The single color attachment needed by the scene-0 render pass. Other
/// attachments are rejected by the Objective-C descriptor translator rather
/// than silently discarded.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HmMetalRenderPassInfo {
    pub texture: u64,
    pub level: u64,
    pub slice: u64,
    pub depth_plane: u64,
    pub load_action: u64,
    pub store_action: u64,
    pub store_action_options: u64,
    pub clear_red: f64,
    pub clear_green: f64,
    pub clear_blue: f64,
    pub clear_alpha: f64,
    pub render_target_array_length: u64,
    pub render_target_width: u64,
    pub render_target_height: u64,
    pub default_raster_sample_count: u64,
}

/// `MTLRenderPipelineColorAttachmentDescriptor`'s real blend state.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HmMetalColorAttachmentInfo {
    pub pixel_format: u64,
    pub blending_enabled: u64,
    pub source_rgb_blend_factor: u64,
    pub destination_rgb_blend_factor: u64,
    pub rgb_blend_operation: u64,
    pub source_alpha_blend_factor: u64,
    pub destination_alpha_blend_factor: u64,
    pub alpha_blend_operation: u64,
    pub write_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HmMetalVertexAttributeInfo {
    pub index: u64,
    pub format: u64,
    pub offset: u64,
    pub buffer_index: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HmMetalVertexLayoutInfo {
    pub buffer_index: u64,
    pub stride: u64,
    pub step_function: u64,
    pub step_rate: u64,
}

/// The real `MTLSamplerDescriptor` fields needed to create a sampler state.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HmMetalSamplerInfo {
    pub min_filter: u64,
    pub mag_filter: u64,
    pub mip_filter: u64,
    pub s_address_mode: u64,
    pub t_address_mode: u64,
    pub r_address_mode: u64,
    pub border_color: u64,
    pub normalized_coordinates: u64,
    pub max_anisotropy: u64,
    pub compare_function: u64,
    pub reduction_mode: u64,
    pub support_argument_buffers: u64,
    pub lod_average: u64,
    pub lod_min_clamp: f32,
    pub lod_max_clamp: f32,
}

/// One borrowed function-constant value, valid for the descriptor call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HmMetalFunctionConstantValue {
    pub name: *const c_char,
    pub index: u64,
    pub use_index: u64,
    pub data_type: u64,
    pub bytes: *const u8,
    pub byte_count: u64,
}

/// Public declaration metadata for one function constant.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HmMetalFunctionConstantInfo {
    pub index: u64,
    pub data_type: u64,
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new(Vec::<u8>::new()).unwrap());
}

fn clear_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(Vec::<u8>::new()).unwrap();
    });
}

fn set_error(error: impl ToString) {
    let text = error.to_string().replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(text).unwrap_or_default();
    });
}

fn protect<T>(fallback: T, operation: impl FnOnce() -> Result<T, String>) -> T {
    clear_error();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            set_error(error);
            fallback
        }
        Err(_) => {
            set_error("metal2vulkan panicked across the Objective-C bridge operation");
            fallback
        }
    }
}

fn owned_handle<T>(value: T) -> u64 {
    Box::into_raw(Box::new(value)) as usize as u64
}

/// Borrow a handle for one protected operation.
///
/// # Safety
/// `handle` must be a live handle of `T` returned by this module and must not
/// be released concurrently. The Objective-C facade provides that lifetime.
unsafe fn handle_ref<'a, T>(handle: u64, kind: &str) -> Result<&'a T, String> {
    if handle == 0 || handle > usize::MAX as u64 {
        return Err(format!("invalid {kind} handle {handle:#x}"));
    }
    // SAFETY: the caller establishes the handle type and lifetime contract.
    Ok(unsafe { &*(handle as usize as *const T) })
}

/// Mutably borrow an encoder handle for one protected Objective-C call.
///
/// # Safety
/// The caller must provide unique access to a live handle of `T`.
unsafe fn handle_mut<'a, T>(handle: u64, kind: &str) -> Result<&'a mut T, String> {
    if handle == 0 || handle > usize::MAX as u64 {
        return Err(format!("invalid {kind} handle {handle:#x}"));
    }
    // SAFETY: the caller establishes the handle type, lifetime and uniqueness.
    Ok(unsafe { &mut *(handle as usize as *mut T) })
}

/// Release a handle exactly once.
///
/// # Safety
/// `handle` must be zero or a live handle of `T` from this module.
unsafe fn release_handle<T>(handle: u64) {
    if handle != 0 {
        // SAFETY: the caller transfers the single owned handle back to Rust.
        drop(unsafe { Box::from_raw(handle as usize as *mut T) });
    }
}

/// Copy a bounded C string without exposing Rust-owned storage to the guest.
///
/// # Safety
/// `output` must address `output_len` writable bytes.
unsafe fn copy_c_string(text: &str, output: *mut c_char, output_len: usize) -> Result<(), String> {
    if output.is_null() || output_len == 0 {
        return Err("null or zero-length C string output".into());
    }
    let bytes = text.as_bytes();
    let count = bytes.len().min(output_len - 1);
    // SAFETY: the caller supplies the output range; the NUL fits by construction.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast::<u8>(), count);
        *output.add(count) = 0;
    }
    Ok(())
}

fn device_options() -> DeviceOptions {
    let mut options = DeviceOptions::default();
    let harmony_loader = Path::new("/system/lib64/libvulkan.so");
    if harmony_loader.exists() {
        options.loader = Some(harmony_loader.to_path_buf());
    }
    // Shader-cache selection intentionally remains DeviceOptions::default():
    // the Harmony host has already established XDG_CACHE_HOME for this app.
    options
}

fn command_buffer_failure(command_buffer: &CommandBuffer) -> String {
    if let Some(description) = command_buffer.error_description() {
        if !description.is_empty() {
            return description;
        }
    }
    if let Some(refusal) = command_buffer.refusal() {
        return refusal.to_string();
    }
    format!("{:?}", command_buffer.error())
}

/// The most recent protected-bridge error on this thread, or an empty string.
/// The pointer remains valid until the next bridge call on the same thread.
#[no_mangle]
pub extern "C" fn hm_metal_objc_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

/// Create the system default runtime device using the Harmony Vulkan loader
/// when present. Returns zero on failure.
#[no_mangle]
pub extern "C" fn hm_metal_objc_device_create() -> u64 {
    protect(0, || {
        let device = Device::system_default_with(&device_options()).map_err(|e| e.to_string())?;
        Ok(owned_handle(device))
    })
}

/// Clone (retain) a device handle. Returns zero on failure.
///
/// # Safety
/// `device` must be a live device handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_clone(device: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<Device>(device, "device")? }.clone(),
        ))
    })
}

/// Release a device handle. Zero is accepted.
///
/// # Safety
/// `device` must be zero or a live device handle owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_release(device: u64) {
    protect((), || {
        unsafe { release_handle::<Device>(device) };
        Ok(())
    });
}

/// Read a device's real Vulkan-backed name into a bounded buffer.
///
/// # Safety
/// `device` must be live and `output` must address `output_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_name(
    device: u64,
    output: *mut c_char,
    output_len: usize,
) -> i32 {
    protect(1, || {
        let name = unsafe { handle_ref::<Device>(device, "device")? }.name();
        unsafe { copy_c_string(name, output, output_len)? };
        Ok(0)
    })
}

/// Return a device's Metal-compatible registry identifier.
///
/// # Safety
/// `device` must be a live device handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_registry_id(device: u64) -> u64 {
    protect(0, || {
        Ok(unsafe { handle_ref::<Device>(device, "device")? }.registry_id())
    })
}

/// Return Metal's `maxBufferLength` from the actual runtime device.
///
/// # Safety
/// `device` must be a live device handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_max_buffer_length(device: u64) -> u64 {
    protect(0, || {
        Ok(unsafe { handle_ref::<Device>(device, "device")? }
            .properties()
            .max_buffer_length)
    })
}

/// Return an Apple private numeric MTLDevice property when metal2vulkan has a
/// device-backed answer. Unknown properties and Apple-only reference values
/// remain errors rather than impersonating the host GPU.
///
/// # Safety
/// `device` must be live and `name` must point to a NUL-terminated selector.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_private_count(
    device: u64,
    name: *const c_char,
) -> u64 {
    protect(0, || {
        if name.is_null() {
            return Err("null private device property name".into());
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name) }
            .to_str()
            .map_err(|e| e.to_string())?;
        let property = PrivateCount::ALL
            .into_iter()
            .find(|property| property.selector() == name)
            .ok_or_else(|| format!("unknown private device property {name}"))?;
        unsafe { handle_ref::<Device>(device, "device")? }
            .private_properties()
            .count(property)
            .value()
            .ok_or_else(|| format!("no device-backed answer for private device property {name}"))
    })
}

/// Create a shared 2D BGRA8 texture for CARenderer and real blit readback,
/// matching `MTLTextureDescriptor`'s default storage mode and preserving Store.
/// `usage` contains Metal `MTLTextureUsage` bits. Returns zero on failure.
///
/// # Safety
/// `device` must be a live device handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_new_bgra8_texture(
    device: u64,
    width: u64,
    height: u64,
    usage: u32,
) -> u64 {
    protect(0, || {
        new_2d_texture(
            device,
            width,
            height,
            usage,
            PixelFormat::BGRA8Unorm.as_raw(),
        )
    })
}

/// Create a shared, single-level 2D texture with the descriptor's real pixel
/// format. This is the upload/render-target path used by CoreAnimation.
///
/// # Safety
/// `device` must be a live device handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_new_texture(
    device: u64,
    width: u64,
    height: u64,
    usage: u32,
    pixel_format: u64,
) -> u64 {
    protect(0, || {
        let pixel_format = u32::try_from(pixel_format).map_err(|e| e.to_string())?;
        new_2d_texture(device, width, height, usage, pixel_format)
    })
}

fn new_2d_texture(
    device: u64,
    width: u64,
    height: u64,
    usage: u32,
    pixel_format: u32,
) -> Result<u64, String> {
    if width == 0 || height == 0 {
        return Err("texture dimensions must be nonzero".into());
    }
    let pixel_format = PixelFormat::try_from(pixel_format).map_err(|e| e.to_string())?;
    eprintln!(
        "hm texture create begin format={} width={} height={} usage={}",
        pixel_format.as_raw(),
        width,
        height,
        usage
    );
    let usage = TextureUsage::try_from(usage).map_err(|e| e.to_string())?;
    let mut descriptor = TextureDescriptor::texture_2d(pixel_format, width, height, false);
    descriptor.usage = usage;
    descriptor.resource_options = ResourceOptions::new(
        StorageMode::Shared,
        CpuCacheMode::DefaultCache,
        HazardTrackingMode::Default,
    );
    let texture = unsafe { handle_ref::<Device>(device, "device")? }
        .new_texture(&descriptor)
        .map_err(|e| e.to_string())?;
    eprintln!(
        "hm texture create completed format={}",
        texture.pixel_format().as_raw()
    );
    Ok(owned_handle(texture))
}

/// Create a real command queue. Returns zero on failure.
///
/// # Safety
/// `device` must be a live device handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_new_command_queue(device: u64) -> u64 {
    protect(0, || {
        let queue = unsafe { handle_ref::<Device>(device, "device")? }
            .new_command_queue()
            .map_err(|e| e.to_string())?;
        Ok(owned_handle(queue))
    })
}

/// Clone (retain) a texture handle.
///
/// # Safety
/// `texture` must be a live texture handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_texture_clone(texture: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<Texture>(texture, "texture")? }.clone(),
        ))
    })
}

/// Release a texture handle. Zero is accepted.
///
/// # Safety
/// `texture` must be zero or a live texture handle owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_texture_release(texture: u64) {
    protect((), || {
        unsafe { release_handle::<Texture>(texture) };
        Ok(())
    });
}

/// Clone the texture's device into a new owned handle.
///
/// # Safety
/// `texture` must be a live texture handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_texture_device(texture: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<Texture>(texture, "texture")? }
                .device()
                .clone(),
        ))
    })
}

/// Read real texture properties. Returns zero on success and one on failure.
///
/// # Safety
/// `texture` must be live and `info` must address a writable info structure.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_texture_info(
    texture: u64,
    info: *mut HmMetalTextureInfo,
) -> i32 {
    protect(1, || {
        if info.is_null() {
            return Err("null texture info output".into());
        }
        let texture = unsafe { handle_ref::<Texture>(texture, "texture")? };
        let value = HmMetalTextureInfo {
            device_registry_id: texture.device().registry_id(),
            pixel_format: u64::from(texture.pixel_format().as_raw()),
            texture_type: u64::from(texture.texture_type().as_raw()),
            width: texture.width(),
            height: texture.height(),
            depth: texture.depth(),
            mipmap_level_count: texture.mipmap_level_count(),
            array_length: texture.array_length(),
            sample_count: texture.sample_count(),
            usage: u64::from(texture.usage().as_raw()),
            storage_mode: texture.storage_mode().raw(),
            cpu_cache_mode: texture.cpu_cache_mode().raw(),
            hazard_tracking_mode: texture.hazard_tracking_mode().raw(),
            resource_options: texture.resource_options().raw(),
            allow_gpu_optimized_contents: u64::from(texture.allow_gpu_optimized_contents()),
        };
        // SAFETY: the caller supplies the writable output structure.
        unsafe { *info = value };
        Ok(0)
    })
}

/// Synchronously read texels through `Texture::get_bytes` (Metal `getBytes`).
/// Returns zero on success and one on failure.
///
/// # Safety
/// `texture` must be live, `region` must be readable, and `output` must address
/// `output_len` writable bytes with the supplied row/image strides.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_texture_get_bytes(
    texture: u64,
    output: *mut c_void,
    output_len: usize,
    bytes_per_row: u64,
    bytes_per_image: u64,
    region: *const HmMetalRegion,
    level: u64,
    slice: u64,
) -> i32 {
    protect(1, || {
        if output.is_null() || region.is_null() {
            return Err("null texture readback argument".into());
        }
        let region = unsafe { *region };
        let bytes = unsafe { std::slice::from_raw_parts_mut(output.cast::<u8>(), output_len) };
        unsafe { handle_ref::<Texture>(texture, "texture")? }
            .get_bytes(
                bytes,
                bytes_per_row,
                bytes_per_image,
                Region::new_3d(
                    region.origin_x,
                    region.origin_y,
                    region.origin_z,
                    region.width,
                    region.height,
                    region.depth,
                ),
                level,
                slice,
            )
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Upload real caller-owned texels through `Texture::replace_region` (Metal
/// `replaceRegion`). The runtime consumes the bytes synchronously; no pointer
/// is retained after this call.
///
/// # Safety
/// `texture` must be live, `region` readable, and `bytes` must address
/// `bytes_len` readable bytes with the supplied row/image strides.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_texture_replace_region(
    texture: u64,
    bytes: *const c_void,
    bytes_len: usize,
    bytes_per_row: u64,
    bytes_per_image: u64,
    region: *const HmMetalRegion,
    level: u64,
    slice: u64,
) -> i32 {
    protect(1, || {
        if bytes.is_null() || region.is_null() {
            return Err("null texture upload argument".into());
        }
        let region = unsafe { *region };
        let bytes = unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), bytes_len) };
        unsafe { handle_ref::<Texture>(texture, "texture")? }
            .replace_region(
                Region::new_3d(
                    region.origin_x,
                    region.origin_y,
                    region.origin_z,
                    region.width,
                    region.height,
                    region.depth,
                ),
                level,
                slice,
                bytes,
                bytes_per_row,
                bytes_per_image,
            )
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Clone (retain) a command queue handle.
///
/// # Safety
/// `queue` must be a live command queue handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_queue_clone(queue: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<CommandQueue>(queue, "command queue")? }.clone(),
        ))
    })
}

/// Release a command queue handle. Zero is accepted.
///
/// # Safety
/// `queue` must be zero or a live queue handle owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_queue_release(queue: u64) {
    protect((), || {
        unsafe { release_handle::<CommandQueue>(queue) };
        Ok(())
    });
}

/// Clone the queue's device into a new owned handle.
///
/// # Safety
/// `queue` must be a live command queue handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_queue_device(queue: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<CommandQueue>(queue, "command queue")? }
                .device()
                .clone(),
        ))
    })
}

/// Create a command buffer. Returns zero on failure.
///
/// # Safety
/// `queue` must be a live command queue handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_queue_command_buffer(queue: u64) -> u64 {
    protect(0, || {
        let command_buffer = unsafe { handle_ref::<CommandQueue>(queue, "command queue")? }
            .command_buffer()
            .map_err(|e| e.to_string())?;
        Ok(owned_handle(command_buffer))
    })
}

/// Release a command buffer handle. Zero is accepted.
///
/// # Safety
/// `command_buffer` must be zero or a live command buffer owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_command_buffer_release(command_buffer: u64) {
    protect((), || {
        unsafe { release_handle::<CommandBuffer>(command_buffer) };
        Ok(())
    });
}

/// Clone the command buffer's device into a new owned handle.
///
/// # Safety
/// `command_buffer` must be a live command buffer handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_command_buffer_device(command_buffer: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<CommandBuffer>(command_buffer, "command buffer")? }
                .device()
                .clone(),
        ))
    })
}

/// Commit real recorded work. Returns zero on success and one on refusal.
///
/// # Safety
/// `command_buffer` must be a live command buffer handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_command_buffer_commit(command_buffer: u64) -> i32 {
    protect(1, || {
        unsafe { handle_ref::<CommandBuffer>(command_buffer, "command buffer")? }
            .commit()
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Wait for completion, requiring `MTLCommandBufferStatusCompleted`.
/// `timeout_ms == 0` selects the runtime's unbounded wait; otherwise the wait
/// is bounded. Returns zero only for successful completion.
///
/// # Safety
/// `command_buffer` must be a live command buffer handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_command_buffer_wait(
    command_buffer: u64,
    timeout_ms: u64,
) -> i32 {
    protect(1, || {
        let command_buffer =
            unsafe { handle_ref::<CommandBuffer>(command_buffer, "command buffer")? };
        if timeout_ms == 0 {
            command_buffer
                .wait_until_completed()
                .map_err(|e| e.to_string())?;
        } else {
            command_buffer
                .wait_until_completed_for(Duration::from_millis(timeout_ms))
                .map_err(|_| format!("command buffer did not complete within {timeout_ms} ms"))?;
        }
        if command_buffer.status() != CommandBufferStatus::Completed {
            return Err(command_buffer_failure(command_buffer));
        }
        Ok(0)
    })
}

/// Return the real `MTLCommandBufferStatus` ordinal, or -1 for a bad handle.
///
/// # Safety
/// `command_buffer` must be a live command buffer handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_command_buffer_status(command_buffer: u64) -> i32 {
    protect(-1, || {
        Ok(
            unsafe { handle_ref::<CommandBuffer>(command_buffer, "command buffer")? }
                .status()
                .raw() as i32,
        )
    })
}

/// Copy the command buffer's real error description, or an empty string when
/// it has not failed. Returns zero on success and one on bridge failure.
///
/// # Safety
/// `command_buffer` must be live and `output` must address `output_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_command_buffer_error(
    command_buffer: u64,
    output: *mut c_char,
    output_len: usize,
) -> i32 {
    protect(1, || {
        let command_buffer =
            unsafe { handle_ref::<CommandBuffer>(command_buffer, "command buffer")? };
        let text = if command_buffer.status() == CommandBufferStatus::Error {
            command_buffer_failure(command_buffer)
        } else {
            String::new()
        };
        unsafe { copy_c_string(&text, output, output_len)? };
        Ok(0)
    })
}

/// Create a real Metal library from metallib bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_new_library_with_data(
    device: u64,
    data: *const u8,
    data_len: usize,
) -> u64 {
    protect(0, || {
        if data.is_null() || data_len == 0 {
            return Err("library data is empty".into());
        }
        let bytes = unsafe { std::slice::from_raw_parts(data, data_len) };
        let library = unsafe { handle_ref::<Device>(device, "device")? }
            .new_library_with_data(bytes)
            .map_err(|e| e.to_string())?;
        Ok(owned_handle(library))
    })
}

/// Create a function from a real Metal library entry point.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_library_new_function(
    library: u64,
    name: *const c_char,
) -> u64 {
    protect(0, || {
        if name.is_null() {
            return Err("null function name".into());
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name) }
            .to_str()
            .map_err(|e| e.to_string())?;
        let function = unsafe { handle_ref::<Library>(library, "library")? }
            .new_function_with_name(name)
            .map_err(|e| e.to_string())?;
        Ok(owned_handle(function))
    })
}

/// Create a function from a real `MTLFunctionDescriptor`, including all
/// supplied function-constant bytes and their indexed/named identity.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_library_new_function_descriptor(
    library: u64,
    name: *const c_char,
    options: u64,
    has_constant_values: u64,
    constants: *const HmMetalFunctionConstantValue,
    constant_count: u64,
) -> u64 {
    protect(0, || {
        if name.is_null() || (constant_count != 0 && constants.is_null()) {
            return Err("null function descriptor argument".into());
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name) }
            .to_str()
            .map_err(|e| e.to_string())?;
        let mut descriptor = RuntimeFunctionDescriptor::new(name);
        descriptor.options =
            FunctionOptions::try_from(u32::try_from(options).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        if has_constant_values != 0 {
            let count = usize::try_from(constant_count).map_err(|e| e.to_string())?;
            let borrowed = if count == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(constants, count) }
            };
            let mut values = FunctionConstantValues::defaults();
            for constant in borrowed {
                if constant.bytes.is_null() {
                    return Err("null function constant bytes".into());
                }
                let byte_count = usize::try_from(constant.byte_count).map_err(|e| e.to_string())?;
                let ty = DataType::try_from(
                    u32::try_from(constant.data_type).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                let bytes = unsafe { std::slice::from_raw_parts(constant.bytes, byte_count) };
                let value = FunctionConstantValue::new(ty, bytes.to_vec());
                if constant.use_index != 0 {
                    let index = u32::try_from(constant.index).map_err(|e| e.to_string())?;
                    values = values.with_index(index, value);
                } else {
                    if constant.name.is_null() {
                        return Err("named function constant has a null name".into());
                    }
                    let name = unsafe { std::ffi::CStr::from_ptr(constant.name) }
                        .to_str()
                        .map_err(|e| e.to_string())?;
                    values = values.with_name(name, value);
                }
            }
            descriptor.constant_values = Some(values);
        }
        let function = unsafe { handle_ref::<Library>(library, "library")? }
            .new_function_with_descriptor(&descriptor)
            .map_err(|e| e.to_string())?;
        Ok(owned_handle(function))
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_function_name(
    function: u64,
    output: *mut c_char,
    output_len: usize,
) -> i32 {
    protect(1, || {
        let name = unsafe { handle_ref::<Function>(function, "function")? }.name();
        unsafe { copy_c_string(name, output, output_len)? };
        Ok(0)
    })
}

/// Return the number of constants declared by a real Metal function.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_function_constant_count(function: u64) -> u64 {
    protect(0, || {
        let constants = unsafe { handle_ref::<Function>(function, "function")? }
            .function_constants_dictionary()
            .map_err(|e| e.to_string())?;
        u64::try_from(constants.len()).map_err(|e| e.to_string())
    })
}

/// Read one declared constant's index, type and name for default-value setup.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_function_constant_info(
    function: u64,
    ordinal: u64,
    info: *mut HmMetalFunctionConstantInfo,
    name: *mut c_char,
    name_len: usize,
) -> i32 {
    protect(1, || {
        if info.is_null() {
            return Err("null function constant info".into());
        }
        let constants = unsafe { handle_ref::<Function>(function, "function")? }
            .function_constants_dictionary()
            .map_err(|e| e.to_string())?;
        let ordinal = usize::try_from(ordinal).map_err(|e| e.to_string())?;
        let constant = constants
            .values()
            .nth(ordinal)
            .ok_or_else(|| "function constant ordinal is out of range".to_string())?;
        unsafe {
            *info = HmMetalFunctionConstantInfo {
                index: u64::from(constant.index()),
                data_type: u64::from(constant.data_type().as_raw()),
            };
        }
        unsafe { copy_c_string(constant.name(), name, name_len)? };
        Ok(0)
    })
}

/// Create a render pipeline from real vertex/fragment functions.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_new_render_pipeline(
    device: u64,
    vertex: u64,
    fragment: u64,
    attachment_info: *const HmMetalColorAttachmentInfo,
    attributes: *const HmMetalVertexAttributeInfo,
    attribute_count: u64,
    layouts: *const HmMetalVertexLayoutInfo,
    layout_count: u64,
) -> u64 {
    protect(0, || {
        if attachment_info.is_null() {
            return Err("null render pipeline color attachment".into());
        }
        let info = unsafe { *attachment_info };
        let vertex = unsafe { handle_ref::<Function>(vertex, "vertex function")? };
        let fragment = unsafe { handle_ref::<Function>(fragment, "fragment function")? };
        fn raw(value: u64) -> Result<u32, String> {
            u32::try_from(value).map_err(|e| e.to_string())
        }
        let pixel_format =
            PixelFormat::try_from(raw(info.pixel_format)?).map_err(|e| e.to_string())?;
        let mut color = ColorAttachmentDescriptor::new(pixel_format);
        color.blending_enabled = info.blending_enabled != 0;
        color.source_rgb_blend_factor =
            BlendFactor::try_from(raw(info.source_rgb_blend_factor)?).map_err(|e| e.to_string())?;
        color.destination_rgb_blend_factor =
            BlendFactor::try_from(raw(info.destination_rgb_blend_factor)?)
                .map_err(|e| e.to_string())?;
        color.rgb_blend_operation =
            BlendOperation::try_from(raw(info.rgb_blend_operation)?).map_err(|e| e.to_string())?;
        color.source_alpha_blend_factor =
            BlendFactor::try_from(raw(info.source_alpha_blend_factor)?)
                .map_err(|e| e.to_string())?;
        color.destination_alpha_blend_factor =
            BlendFactor::try_from(raw(info.destination_alpha_blend_factor)?)
                .map_err(|e| e.to_string())?;
        color.alpha_blend_operation = BlendOperation::try_from(raw(info.alpha_blend_operation)?)
            .map_err(|e| e.to_string())?;
        color.write_mask =
            ColorWriteMask::try_from(raw(info.write_mask)?).map_err(|e| e.to_string())?;
        let mut descriptor =
            RenderPipelineDescriptor::new(StageSource::Function(vertex.function_descriptor()));
        descriptor.fragment = Some(StageSource::Function(fragment.function_descriptor()));
        descriptor.color_attachments[0] = Some(color);
        if attribute_count != 0 {
            if attributes.is_null() || (layout_count != 0 && layouts.is_null()) {
                return Err("null vertex descriptor array".into());
            }
            let attribute_count = usize::try_from(attribute_count).map_err(|e| e.to_string())?;
            let layout_count = usize::try_from(layout_count).map_err(|e| e.to_string())?;
            let attributes = unsafe { std::slice::from_raw_parts(attributes, attribute_count) };
            let layouts = if layout_count == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(layouts, layout_count) }
            };
            let mut vertex_descriptor = VertexDescriptor::new();
            for attribute in attributes {
                let index = u32::try_from(attribute.index).map_err(|e| e.to_string())?;
                let format =
                    VertexFormat::try_from(raw(attribute.format)?).map_err(|e| e.to_string())?;
                let offset = u32::try_from(attribute.offset).map_err(|e| e.to_string())?;
                let buffer_index =
                    u32::try_from(attribute.buffer_index).map_err(|e| e.to_string())?;
                vertex_descriptor.attributes.insert(
                    index,
                    VertexAttributeDescriptor::new(format, offset, buffer_index),
                );
            }
            for layout in layouts {
                let buffer_index = u32::try_from(layout.buffer_index).map_err(|e| e.to_string())?;
                let stride = if layout.stride == u64::MAX {
                    None
                } else {
                    Some(u32::try_from(layout.stride).map_err(|e| e.to_string())?)
                };
                let step_function = VertexStepFunction::try_from(raw(layout.step_function)?)
                    .map_err(|e| e.to_string())?;
                let step_rate = u32::try_from(layout.step_rate).map_err(|e| e.to_string())?;
                let mut converted = VertexBufferLayoutDescriptor::new(stride);
                converted.step_function = step_function;
                converted.step_rate = step_rate;
                vertex_descriptor.layouts.insert(buffer_index, converted);
            }
            descriptor.vertex_descriptor = Some(vertex_descriptor);
        }
        let pipeline = unsafe { handle_ref::<Device>(device, "device")? }
            .new_render_pipeline_state(&descriptor, &PipelineOptions::default())
            .map_err(|e| e.to_string())?;
        Ok(owned_handle(pipeline))
    })
}

/// Create a real sampler state from the Objective-C descriptor. No sampler
/// property is replaced with a scene-specific constant.
///
/// # Safety
/// `device` must be live and `info` must point to a readable descriptor.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_new_sampler(
    device: u64,
    info: *const HmMetalSamplerInfo,
) -> u64 {
    protect(0, || {
        if info.is_null() {
            return Err("null sampler descriptor".into());
        }
        let info = unsafe { *info };
        fn raw(value: u64) -> Result<u32, String> {
            u32::try_from(value).map_err(|e| e.to_string())
        }
        let mut descriptor = SamplerDescriptor::new();
        descriptor.min_filter =
            SamplerMinMagFilter::try_from(raw(info.min_filter)?).map_err(|e| e.to_string())?;
        descriptor.mag_filter =
            SamplerMinMagFilter::try_from(raw(info.mag_filter)?).map_err(|e| e.to_string())?;
        descriptor.mip_filter =
            SamplerMipFilter::try_from(raw(info.mip_filter)?).map_err(|e| e.to_string())?;
        descriptor.s_address_mode =
            SamplerAddressMode::try_from(raw(info.s_address_mode)?).map_err(|e| e.to_string())?;
        descriptor.t_address_mode =
            SamplerAddressMode::try_from(raw(info.t_address_mode)?).map_err(|e| e.to_string())?;
        descriptor.r_address_mode =
            SamplerAddressMode::try_from(raw(info.r_address_mode)?).map_err(|e| e.to_string())?;
        descriptor.border_color =
            SamplerBorderColor::try_from(raw(info.border_color)?).map_err(|e| e.to_string())?;
        descriptor.normalized_coordinates = info.normalized_coordinates != 0;
        descriptor.lod_min_clamp = info.lod_min_clamp;
        descriptor.lod_max_clamp = info.lod_max_clamp;
        descriptor.lod_average = info.lod_average != 0;
        descriptor.max_anisotropy = raw(info.max_anisotropy)?;
        descriptor.compare_function =
            CompareFunction::try_from(raw(info.compare_function)?).map_err(|e| e.to_string())?;
        descriptor.reduction_mode =
            SamplerReductionMode::try_from(raw(info.reduction_mode)?).map_err(|e| e.to_string())?;
        let mut options = SamplerStateOptions::default();
        options.support_argument_buffers = info.support_argument_buffers != 0;
        let sampler = unsafe { handle_ref::<Device>(device, "device")? }
            .new_sampler_state_with_options(&descriptor, options)
            .map_err(|e| e.to_string())?;
        Ok(owned_handle(sampler))
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_sampler_release(sampler: u64) {
    protect((), || {
        unsafe { release_handle::<SamplerState>(sampler) };
        Ok(())
    });
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_library_clone(library: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<Library>(library, "library")? }.clone(),
        ))
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_library_release(library: u64) {
    protect((), || {
        unsafe { release_handle::<Library>(library) };
        Ok(())
    });
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_function_clone(function: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<Function>(function, "function")? }.clone(),
        ))
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_function_release(function: u64) {
    protect((), || {
        unsafe { release_handle::<Function>(function) };
        Ok(())
    });
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_pipeline_clone(pipeline: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<RenderPipelineState>(pipeline, "pipeline")? }.clone(),
        ))
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_pipeline_release(pipeline: u64) {
    protect((), || {
        unsafe { release_handle::<RenderPipelineState>(pipeline) };
        Ok(())
    });
}

/// Return the runtime texture's actual protection options (Metal's default is
/// zero; this runtime does not manufacture protected resources).
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_texture_protection_options(texture: u64) -> u64 {
    protect(0, || {
        Ok(unsafe { handle_ref::<Texture>(texture, "texture")? }.protection_options())
    })
}

/// Apply Metal's real command-buffer protection state transition.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_command_buffer_set_protection_options(
    command_buffer: u64,
    options: u64,
) -> i32 {
    protect(1, || {
        unsafe { handle_ref::<CommandBuffer>(command_buffer, "command buffer")? }
            .set_protection_options(options)
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Create a real buffer, copying bytes when `bytes` is non-null and otherwise
/// returning Metal's zero-initialized buffer of `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_device_new_buffer(
    device: u64,
    bytes: *const u8,
    length: u64,
    options: u64,
) -> u64 {
    protect(0, || {
        let device = unsafe { handle_ref::<Device>(device, "device")? };
        let options = ResourceOptions::from_raw(options).map_err(|e| e.to_string())?;
        let buffer = if bytes.is_null() {
            device.new_buffer(length, options)
        } else {
            let length = usize::try_from(length).map_err(|e| e.to_string())?;
            let bytes = unsafe { std::slice::from_raw_parts(bytes, length) };
            device.new_buffer_with_bytes(bytes, options)
        }
        .map_err(|e| e.to_string())?;
        Ok(owned_handle(buffer))
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_buffer_clone(buffer: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<Buffer>(buffer, "buffer")? }.clone(),
        ))
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_buffer_release(buffer: u64) {
    protect((), || {
        unsafe { release_handle::<Buffer>(buffer) };
        Ok(())
    });
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_buffer_device(buffer: u64) -> u64 {
    protect(0, || {
        Ok(owned_handle(
            unsafe { handle_ref::<Buffer>(buffer, "buffer")? }
                .device()
                .clone(),
        ))
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_buffer_length(buffer: u64) -> u64 {
    protect(0, || {
        Ok(unsafe { handle_ref::<Buffer>(buffer, "buffer")? }.length())
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_buffer_contents(buffer: u64) -> *mut c_void {
    protect(ptr::null_mut(), || {
        let contents = unsafe { handle_ref::<Buffer>(buffer, "buffer")? }
            .contents()
            .ok_or_else(|| "buffer has no CPU contents".to_string())?;
        Ok(contents.as_ptr().cast::<c_void>())
    })
}

/// Open a real render encoder from the translated descriptor. The returned
/// object owns the runtime encoder until `endEncoding` consumes it.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_command_buffer_render_encoder(
    command_buffer: u64,
    pass_info: *const HmMetalRenderPassInfo,
) -> u64 {
    protect(0, || {
        if pass_info.is_null() {
            return Err("null render pass descriptor".into());
        }
        let info = unsafe { *pass_info };
        let mut pass = RenderPassDescriptor::new();
        let color = &mut pass.color_attachments[0];
        if info.texture != 0 {
            color.texture =
                Some(unsafe { handle_ref::<Texture>(info.texture, "texture")? }.clone());
        }
        color.level = info.level;
        color.slice = info.slice;
        color.depth_plane = info.depth_plane;
        color.load_action = LoadAction::from_raw(info.load_action).map_err(|e| e.to_string())?;
        color.store_action = StoreAction::from_raw(info.store_action).map_err(|e| e.to_string())?;
        color.store_action_options =
            StoreActionOptions::from_raw(info.store_action_options).map_err(|e| e.to_string())?;
        color.clear_color = ClearColor::new(
            info.clear_red,
            info.clear_green,
            info.clear_blue,
            info.clear_alpha,
        );
        pass.render_target_array_length = info.render_target_array_length;
        pass.render_target_width = info.render_target_width;
        pass.render_target_height = info.render_target_height;
        pass.default_raster_sample_count = info.default_raster_sample_count;
        let encoder = unsafe { handle_ref::<CommandBuffer>(command_buffer, "command buffer")? }
            .render_command_encoder(&pass)
            .map_err(|e| e.to_string())?;
        Ok(owned_handle(encoder))
    })
}

/// Drop an encoder abandoned without `endEncoding`.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_release(encoder: u64) {
    protect((), || {
        unsafe { release_handle::<RenderCommandEncoder>(encoder) };
        Ok(())
    });
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_set_pipeline(encoder: u64, pipeline: u64) -> i32 {
    protect(1, || {
        eprintln!("hm set pipeline begin encoder={} pipeline={}", encoder, pipeline);
        let pipeline = unsafe { handle_ref::<RenderPipelineState>(pipeline, "pipeline")? };
        unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? }
            .set_render_pipeline_state(pipeline)
            .map_err(|e| e.to_string())?;
        eprintln!("hm set pipeline completed encoder={}", encoder);
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_set_buffer(
    encoder: u64,
    buffer: u64,
    offset: u64,
    index: u64,
    fragment: u64,
) -> i32 {
    protect(1, || {
        let buffer = if buffer == 0 {
            None
        } else {
            Some(unsafe { handle_ref::<Buffer>(buffer, "buffer")? })
        };
        let index = u32::try_from(index).map_err(|e| e.to_string())?;
        let encoder = unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? };
        if fragment != 0 {
            encoder.set_fragment_buffer(buffer, offset, index)
        } else {
            encoder.set_vertex_buffer(buffer, offset, index)
        }
        .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Bind or unbind a real fragment texture. The runtime encoder retains the
/// resource according to its normal command-buffer lifetime rules.
///
/// # Safety
/// `encoder` must be live; a nonzero `texture` must be a live texture handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_set_fragment_texture(
    encoder: u64,
    texture: u64,
    index: u64,
) -> i32 {
    protect(1, || {
        let texture = if texture == 0 {
            None
        } else {
            Some(unsafe { handle_ref::<Texture>(texture, "texture")? })
        };
        let index = u32::try_from(index).map_err(|e| e.to_string())?;
        unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? }
            .set_fragment_texture(texture, index)
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Bind or unbind a real fragment sampler state.
///
/// # Safety
/// `encoder` must be live; a nonzero `sampler` must be a live sampler handle.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_set_fragment_sampler(
    encoder: u64,
    sampler: u64,
    index: u64,
) -> i32 {
    protect(1, || {
        let sampler = if sampler == 0 {
            None
        } else {
            Some(unsafe { handle_ref::<SamplerState>(sampler, "sampler")? })
        };
        let index = u32::try_from(index).map_err(|e| e.to_string())?;
        unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? }
            .set_fragment_sampler_state(sampler, index)
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_set_viewport(
    encoder: u64,
    origin_x: f64,
    origin_y: f64,
    width: f64,
    height: f64,
    znear: f64,
    zfar: f64,
) -> i32 {
    protect(1, || {
        unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? }
            .set_viewport(Viewport::new(
                origin_x, origin_y, width, height, znear, zfar,
            ))
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_draw(
    encoder: u64,
    primitive_type: u64,
    vertex_start: u64,
    vertex_count: u64,
    instance_count: u64,
    base_instance: u64,
) -> i32 {
    protect(1, || {
        let primitive_type =
            PrimitiveType::try_from(u32::try_from(primitive_type).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let vertex_start = u32::try_from(vertex_start).map_err(|e| e.to_string())?;
        let vertex_count = u32::try_from(vertex_count).map_err(|e| e.to_string())?;
        let instance_count = u32::try_from(instance_count).map_err(|e| e.to_string())?;
        let base_instance = u32::try_from(base_instance).map_err(|e| e.to_string())?;
        unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? }
            .draw_primitives(
                primitive_type,
                vertex_start,
                vertex_count,
                instance_count,
                base_instance,
            )
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Consume the Rust encoder exactly once. Both success and failure consume it,
/// matching `RenderCommandEncoder::end_encoding(self)`.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_end(encoder: u64) -> i32 {
    protect(1, || {
        if encoder == 0 || encoder > usize::MAX as u64 {
            return Err(format!("invalid render encoder handle {encoder:#x}"));
        }
        let encoder = unsafe { Box::from_raw(encoder as usize as *mut RenderCommandEncoder) };
        (*encoder).end_encoding().map_err(|e| e.to_string())?;
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_set_scissor(
    encoder: u64,
    x: u64,
    y: u64,
    width: u64,
    height: u64,
) -> i32 {
    protect(1, || {
        unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? }
            .set_scissor_rect(ScissorRect::new(x, y, width, height))
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_set_buffer_offset(
    encoder: u64,
    offset: u64,
    index: u64,
    fragment: u64,
) -> i32 {
    protect(1, || {
        let index = u32::try_from(index).map_err(|e| e.to_string())?;
        let encoder = unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? };
        if fragment != 0 {
            encoder.set_fragment_buffer_offset(offset, index)
        } else {
            encoder.set_vertex_buffer_offset(offset, index)
        }
        .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn hm_metal_objc_encoder_draw_indexed(
    encoder: u64,
    primitive_type: u64,
    index_count: u64,
    index_type: u64,
    index_buffer: u64,
    index_buffer_offset: u64,
    instance_count: u64,
    base_vertex: i64,
    base_instance: u64,
) -> i32 {
    protect(1, || {
        let primitive_type =
            PrimitiveType::try_from(u32::try_from(primitive_type).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let index_count = u32::try_from(index_count).map_err(|e| e.to_string())?;
        let index_type = IndexType::try_from(u32::try_from(index_type).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let index_buffer = unsafe { handle_ref::<Buffer>(index_buffer, "index buffer")? };
        let instance_count = u32::try_from(instance_count).map_err(|e| e.to_string())?;
        let base_vertex = i32::try_from(base_vertex).map_err(|e| e.to_string())?;
        let base_instance = u32::try_from(base_instance).map_err(|e| e.to_string())?;
        unsafe { handle_mut::<RenderCommandEncoder>(encoder, "render encoder")? }
            .draw_indexed_primitives(
                primitive_type,
                index_count,
                index_type,
                index_buffer,
                index_buffer_offset,
                instance_count,
                base_vertex,
                base_instance,
            )
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}
