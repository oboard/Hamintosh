//! Offscreen Metal-to-Vulkan feasibility probe using the upstream owned fixture.
//! No guest framework or application pixels are synthesized: the only output is
//! the command buffer's real readback and a per-texel comparison.

use metal2vulkan::metal::{PixelFormat, PrimitiveType, TextureUsage};
use metal2vulkan::pipeline::{ColorAttachmentDescriptor, RenderPipelineDescriptor, StageSource};
use metal2vulkan_runtime::{
    BlitOption, ClearColor, CommandBufferStatus, Device, DeviceOptions, LoadAction, Origin,
    PipelineOptions, RenderPassDescriptor, ResourceOptions, Size, StoreAction, TextureDescriptor,
};
use serde::Serialize;
use std::error::Error;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::time::Duration;

const SIDE: u64 = 8;
const DRAWN: [f32; 4] = [1.0, 0.2, 0.0, 1.0];
const DRAWN_TEXEL: [u8; 4] = [255, 51, 0, 255];
const CLEARED_TEXEL: [u8; 4] = [0, 0, 255, 255];
const FIXTURE_AIR: &[u8] = include_bytes!("../assets/runtime_examples.air");

#[derive(Serialize)]
struct ProbeReport {
    device: String,
    width: u64,
    height: u64,
    correct: bool,
    non_zero_pixels: usize,
    readback_fnv1a64: String,
}

fn render_probe() -> Result<ProbeReport, Box<dyn Error>> {
    let mut options = DeviceOptions::default();
    if PathBuf::from("/system/lib64/libvulkan.so").exists() {
        options.loader = Some(PathBuf::from("/system/lib64/libvulkan.so"));
    }
    let device = Device::system_default_with(&options)?;
    let name = device.name();
    let library = metal2vulkan::library::Library::from_air(FIXTURE_AIR)?;
    let library = device.new_library_with_compile_library(library);
    let vertex = library.new_function_with_name("colored_vertex")?;
    let fragment = library.new_function_with_name("colored_fragment")?;

    let mut descriptor =
        RenderPipelineDescriptor::new(StageSource::Function(vertex.function_descriptor()));
    descriptor.fragment = Some(StageSource::Function(fragment.function_descriptor()));
    descriptor.color_attachments[0] = Some(ColorAttachmentDescriptor::new(PixelFormat::RGBA8Unorm));
    let state = device.new_render_pipeline_state(&descriptor, &PipelineOptions::default())?;

    let mut texture = TextureDescriptor::texture_2d(PixelFormat::RGBA8Unorm, SIDE, SIDE, false);
    texture.usage = TextureUsage::RENDER_TARGET;
    texture.resource_options = ResourceOptions::private();
    let target = device.new_texture(&texture)?;

    let positions: [[f32; 2]; 6] = [
        [-1.0, 1.0],
        [0.0, 1.0],
        [-1.0, 0.0],
        [0.0, 1.0],
        [0.0, 0.0],
        [-1.0, 0.0],
    ];
    let positions: Vec<u8> = positions
        .iter()
        .flatten()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let colors: Vec<u8> = (0..6)
        .flat_map(|_| DRAWN)
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let positions = device.new_buffer_with_bytes(&positions, ResourceOptions::shared())?;
    let colors = device.new_buffer_with_bytes(&colors, ResourceOptions::shared())?;

    let mut pass = RenderPassDescriptor::new();
    let color = &mut pass.color_attachments[0];
    color.texture = Some(target.clone());
    color.load_action = LoadAction::Clear;
    color.store_action = StoreAction::Store;
    color.clear_color = ClearColor::new(0.0, 0.0, 1.0, 1.0);

    let row = SIDE * 4;
    let readback = device.new_buffer(row * SIDE, ResourceOptions::shared())?;
    let queue = device.new_command_queue()?;
    let command_buffer = queue.command_buffer()?;
    let mut encoder = command_buffer.render_command_encoder(&pass)?;
    encoder.set_render_pipeline_state(&state)?;
    encoder.set_vertex_buffer(Some(&positions), 0, 0)?;
    encoder.set_vertex_buffer(Some(&colors), 0, 1)?;
    encoder.draw_primitives(PrimitiveType::Triangle, 0, 6, 1, 0)?;
    encoder.end_encoding()?;
    let mut blit = command_buffer.blit_command_encoder()?;
    blit.copy_from_texture_to_buffer(
        &target,
        0,
        0,
        Origin::new(0, 0, 0),
        Size::new(SIDE, SIDE, 1),
        &readback,
        0,
        row,
        row * SIDE,
        BlitOption::None,
    )?;
    blit.end_encoding()?;
    command_buffer.commit()?;
    command_buffer
        .wait_until_completed_for(Duration::from_secs(60))
        .map_err(|_| "command buffer did not complete within 60 seconds")?;
    if command_buffer.status() != CommandBufferStatus::Completed {
        return Err(format!(
            "command buffer ended {:?}: {:?}",
            command_buffer.status(),
            command_buffer.error()
        )
        .into());
    }

    let contents = readback
        .contents()
        .ok_or("readback buffer has no contents")?;
    // SAFETY: the completed command buffer no longer writes the shared buffer,
    // and contents covers exactly buffer.length() readable bytes.
    let texels =
        unsafe { std::slice::from_raw_parts(contents.as_ptr(), readback.length() as usize) };
    let mut correct = true;
    let mut non_zero_pixels = 0;
    let mut hash = 0xcbf29ce484222325u64;
    for (index, texel) in texels.chunks_exact(4).enumerate() {
        let x = index % SIDE as usize;
        let y = index / SIDE as usize;
        let expected = if x < SIDE as usize / 2 && y < SIDE as usize / 2 {
            DRAWN_TEXEL
        } else {
            CLEARED_TEXEL
        };
        correct &= texel == expected;
        if texel.iter().any(|byte| *byte != 0) {
            non_zero_pixels += 1;
        }
        for byte in texel {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
    Ok(ProbeReport {
        device: name.to_string(),
        width: SIDE,
        height: SIDE,
        correct,
        non_zero_pixels,
        readback_fnv1a64: format!("{hash:016x}"),
    })
}

/// Run the offscreen probe and write a bounded JSON result into `output`.
/// Returns 0 when every texel matched and 1 otherwise.
///
/// # Safety
/// `output` must point to `output_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn hm_metal_probe_render_json(output: *mut c_char, output_len: usize) -> i32 {
    if output.is_null() || output_len < 2 {
        return 1;
    }
    let json = match render_probe() {
        Ok(report) => serde_json::to_string(&report),
        Err(error) => serde_json::to_string(&serde_json::json!({"error": error.to_string()})),
    };
    let Ok(json) = json else { return 1 };
    let bytes = json.as_bytes();
    let count = bytes.len().min(output_len - 1);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast::<u8>(), count);
    *output.add(count) = 0;
    0
}
