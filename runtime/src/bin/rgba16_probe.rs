use metal2vulkan::metal::{PixelFormat, TextureUsage};
use metal2vulkan_runtime::{Device, ResourceOptions, TextureDescriptor};

fn main() {
    let device = Device::system_default().expect("create device");
    let mut descriptor = TextureDescriptor::texture_2d(PixelFormat::RGBA8Unorm, 16, 16, false);
    descriptor.usage = TextureUsage::RENDER_TARGET | TextureUsage::SHADER_READ;
    descriptor.resource_options = ResourceOptions::shared();
    let texture = device
        .new_texture(&descriptor)
        .expect("create RGBA16Unorm texture");
    println!(
        "device={} format={} width={} height={}",
        device.name(),
        texture.pixel_format().as_raw(),
        texture.width(),
        texture.height()
    );
}
