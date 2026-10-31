// Offscreen scene-0 CALayer/CARenderer probe over metal2vulkan-runtime.
//
// This file deliberately contains no UIWindow, presentationLayer, render-server
// IPC, or synthetic pixels. Apple CoreAnimation receives real CALayer objects
// and Metal facade objects whose handles own real Rust runtime objects.
//
// Type encodings used for registered methods were checked against the Apple
// SDK runtime on ARM64. Forwarded selectors use protocol_getMethodDescription;
// no private method signature is guessed.

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <exception>
#include <fstream>
#include <limits>
#include <mutex>
#include <new>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <unistd.h>

#if __has_include(<hilog/log.h>)
#include <hilog/log.h>
#define HM_CA_HAS_HILOG 1
#endif

// Supplied by execution_probe.cpp while an audited Apple cache is active.
uint64_t HmGuestObjcRuntimeSymbol(const char *name);

extern "C" {
// Supplied by native/abi/pac_sign.S on Harmony ARM64.
uint64_t hm_pac_sign_pointer(uint64_t pointer, uint64_t modifier, uint32_t key);
uint64_t hm_pac_strip_instruction(uint64_t pointer);
uint64_t hm_pac_strip_data(uint64_t pointer);

// Rust C ABI from runtime/src/metal_objc.rs.
const char *hm_metal_objc_last_error();
uint64_t hm_metal_objc_device_create();
uint64_t hm_metal_objc_device_clone(uint64_t device);
void hm_metal_objc_device_release(uint64_t device);
int32_t hm_metal_objc_device_name(uint64_t device, char *output, size_t output_len);
uint64_t hm_metal_objc_device_registry_id(uint64_t device);
uint64_t hm_metal_objc_device_max_buffer_length(uint64_t device);
uint64_t hm_metal_objc_device_private_count(uint64_t device, const char *name);
uint64_t hm_metal_objc_device_new_bgra8_texture(
    uint64_t device, uint64_t width, uint64_t height, uint32_t usage);
uint64_t hm_metal_objc_device_new_texture(
    uint64_t device, uint64_t width, uint64_t height, uint32_t usage, uint64_t pixel_format);
uint64_t hm_metal_objc_device_new_command_queue(uint64_t device);
uint64_t hm_metal_objc_texture_clone(uint64_t texture);
void hm_metal_objc_texture_release(uint64_t texture);
uint64_t hm_metal_objc_texture_device(uint64_t texture);
uint64_t hm_metal_objc_queue_clone(uint64_t queue);
void hm_metal_objc_queue_release(uint64_t queue);
uint64_t hm_metal_objc_queue_device(uint64_t queue);
uint64_t hm_metal_objc_queue_command_buffer(uint64_t queue);
void hm_metal_objc_command_buffer_release(uint64_t command_buffer);
uint64_t hm_metal_objc_command_buffer_device(uint64_t command_buffer);
int32_t hm_metal_objc_command_buffer_commit(uint64_t command_buffer);
int32_t hm_metal_objc_command_buffer_wait(uint64_t command_buffer, uint64_t timeout_ms);
int32_t hm_metal_objc_command_buffer_status(uint64_t command_buffer);
int32_t hm_metal_objc_command_buffer_error(
    uint64_t command_buffer, char *output, size_t output_len);

struct HmMetalTextureInfo {
    uint64_t device_registry_id;
    uint64_t pixel_format;
    uint64_t texture_type;
    uint64_t width;
    uint64_t height;
    uint64_t depth;
    uint64_t mipmap_level_count;
    uint64_t array_length;
    uint64_t sample_count;
    uint64_t usage;
    uint64_t storage_mode;
    uint64_t cpu_cache_mode;
    uint64_t hazard_tracking_mode;
    uint64_t resource_options;
    uint64_t allow_gpu_optimized_contents;
};

struct HmMetalRegion {
    uint64_t origin_x, origin_y, origin_z;
    uint64_t width, height, depth;
};

int32_t hm_metal_objc_texture_info(uint64_t texture, HmMetalTextureInfo *info);
int32_t hm_metal_objc_texture_get_bytes(uint64_t texture, void *output, size_t output_len,
    uint64_t bytes_per_row, uint64_t bytes_per_image, const HmMetalRegion *region,
    uint64_t level, uint64_t slice);
int32_t hm_metal_objc_texture_replace_region(uint64_t texture, const void *bytes,
    size_t bytes_len, uint64_t bytes_per_row, uint64_t bytes_per_image,
    const HmMetalRegion *region, uint64_t level, uint64_t slice);
uint64_t hm_metal_objc_device_new_library_with_data(uint64_t device, const uint8_t *data, size_t data_len);
uint64_t hm_metal_objc_library_new_function(uint64_t library, const char *name);
struct HmMetalColorAttachmentInfo {
    uint64_t pixel_format;
    uint64_t blending_enabled;
    uint64_t source_rgb_blend_factor;
    uint64_t destination_rgb_blend_factor;
    uint64_t rgb_blend_operation;
    uint64_t source_alpha_blend_factor;
    uint64_t destination_alpha_blend_factor;
    uint64_t alpha_blend_operation;
    uint64_t write_mask;
};
struct HmMetalRenderPassInfo {
    uint64_t texture;
    uint64_t level, slice, depth_plane;
    uint64_t load_action, store_action, store_action_options;
    double clear_red, clear_green, clear_blue, clear_alpha;
    uint64_t render_target_array_length;
    uint64_t render_target_width, render_target_height;
    uint64_t default_raster_sample_count;
};
struct HmMetalVertexAttributeInfo { uint64_t index, format, offset, buffer_index; };
struct HmMetalVertexLayoutInfo { uint64_t buffer_index, stride, step_function, step_rate; };
struct HmMetalSamplerInfo {
    uint64_t min_filter, mag_filter, mip_filter;
    uint64_t s_address_mode, t_address_mode, r_address_mode, border_color;
    uint64_t normalized_coordinates, max_anisotropy, compare_function, reduction_mode;
    uint64_t support_argument_buffers, lod_average;
    float lod_min_clamp, lod_max_clamp;
};
uint64_t hm_metal_objc_device_new_sampler(uint64_t device, const HmMetalSamplerInfo *info);
void hm_metal_objc_sampler_release(uint64_t sampler);
uint64_t hm_metal_objc_device_new_render_pipeline(uint64_t device, uint64_t vertex,
    uint64_t fragment, const HmMetalColorAttachmentInfo *attachment,
    const HmMetalVertexAttributeInfo *attributes, uint64_t attribute_count,
    const HmMetalVertexLayoutInfo *layouts, uint64_t layout_count);
uint64_t hm_metal_objc_library_clone(uint64_t library);
void hm_metal_objc_library_release(uint64_t library);
uint64_t hm_metal_objc_function_clone(uint64_t function);
void hm_metal_objc_function_release(uint64_t function);
struct HmMetalFunctionConstantValue {
    const char *name;
    uint64_t index, use_index, data_type;
    const uint8_t *bytes;
    uint64_t byte_count;
};
uint64_t hm_metal_objc_library_new_function_descriptor(uint64_t library, const char *name,
    uint64_t options, uint64_t has_constant_values, const HmMetalFunctionConstantValue *constants,
    uint64_t constant_count);
int32_t hm_metal_objc_function_name(uint64_t function, char *output, size_t output_len);
struct HmMetalFunctionConstantInfo { uint64_t index, data_type; };
uint64_t hm_metal_objc_function_constant_count(uint64_t function);
int32_t hm_metal_objc_function_constant_info(uint64_t function, uint64_t ordinal,
    HmMetalFunctionConstantInfo *info, char *name, size_t name_len);
uint64_t hm_metal_objc_pipeline_clone(uint64_t pipeline);
void hm_metal_objc_pipeline_release(uint64_t pipeline);
uint64_t hm_metal_objc_texture_protection_options(uint64_t texture);
int32_t hm_metal_objc_command_buffer_set_protection_options(uint64_t command_buffer, uint64_t options);
uint64_t hm_metal_objc_device_new_buffer(uint64_t device, const uint8_t *bytes,
    uint64_t length, uint64_t options);
uint64_t hm_metal_objc_buffer_clone(uint64_t buffer);
void hm_metal_objc_buffer_release(uint64_t buffer);
uint64_t hm_metal_objc_buffer_device(uint64_t buffer);
uint64_t hm_metal_objc_buffer_length(uint64_t buffer);
void *hm_metal_objc_buffer_contents(uint64_t buffer);
uint64_t hm_metal_objc_command_buffer_render_encoder(uint64_t command_buffer,
    const HmMetalRenderPassInfo *pass);
void hm_metal_objc_encoder_release(uint64_t encoder);
int32_t hm_metal_objc_encoder_set_pipeline(uint64_t encoder, uint64_t pipeline);
int32_t hm_metal_objc_encoder_set_buffer(uint64_t encoder, uint64_t buffer,
    uint64_t offset, uint64_t index, uint64_t fragment);
int32_t hm_metal_objc_encoder_set_fragment_texture(uint64_t encoder,
    uint64_t texture, uint64_t index);
int32_t hm_metal_objc_encoder_set_fragment_sampler(uint64_t encoder,
    uint64_t sampler, uint64_t index);
int32_t hm_metal_objc_encoder_set_viewport(uint64_t encoder, double origin_x,
    double origin_y, double width, double height, double znear, double zfar);
int32_t hm_metal_objc_encoder_draw(uint64_t encoder, uint64_t primitive_type,
    uint64_t vertex_start, uint64_t vertex_count, uint64_t instance_count, uint64_t base_instance);
int32_t hm_metal_objc_encoder_set_scissor(uint64_t encoder, uint64_t x,
    uint64_t y, uint64_t width, uint64_t height);
int32_t hm_metal_objc_encoder_set_buffer_offset(uint64_t encoder, uint64_t offset,
    uint64_t index, uint64_t fragment);
int32_t hm_metal_objc_encoder_draw_indexed(uint64_t encoder, uint64_t primitive_type,
    uint64_t index_count, uint64_t index_type, uint64_t index_buffer,
    uint64_t index_buffer_offset, uint64_t instance_count, int64_t base_vertex,
    uint64_t base_instance);
int32_t hm_metal_objc_encoder_end(uint64_t encoder);
}

namespace {

constexpr uint64_t kWidth = 256;
constexpr uint64_t kHeight = 256;
constexpr uint64_t kRGBA8Unorm = 10;
constexpr uint64_t kBGRA8Unorm = 80;
constexpr uint64_t kRGBA16Unorm = 70;
constexpr uint64_t kBGRA10XR = 115;
constexpr uint64_t kTextureType2D = 2;
constexpr uint64_t kTextureUsageShaderRead = 0x1;
constexpr uint64_t kTextureUsageRenderTarget = 0x4;
constexpr uint64_t kCompleted = 4;
// Native Apple CARenderer scene-0 reference (tests/ca_renderer_scene0.m).
constexpr uint64_t kScene0ReferenceFnv1a64 = 0xd15e8d0a54169a25ULL;
// Native Maleoon blend rounding: R is one LSB lower only in the 4,800
// red/green-overlap texels not covered by the opaque blue layer.
constexpr uint64_t kScene0MaleoonRoundingFnv1a64 = 0x8445581fde5db025ULL;
// Native Apple CARenderer scene-1 reference, same CGImage and layer geometry.
constexpr uint64_t kScene1ReferenceFnv1a64 = 0x71b0a93f2a0f4f25ULL;
// Native Apple CARenderer scene-2 reference: a real axial CAGradientLayer,
// opaque red at startPoint=(0,0.5), opaque blue at endPoint=(1,0.5).
constexpr uint64_t kScene2ReferenceFnv1a64 = 0x7103cb201d85fe35ULL;
// Native Apple CARenderer scene-3 reference: guest CoreText draws "鸿蒙"
// from the bundled PingFang SC 32pt TTF into a real 224x64 CGBitmapContext.
// CGBitmapContextCreateImage supplies an ordinary CALayer's contents. No old
// CATextLayer hash, backend profile or reference texel constructs the scene.
constexpr uint64_t kScene3AppleReferenceFnv1a64 = 0x1ff8a71d36a1d74cULL;
constexpr uint64_t kScene3BackendReferenceFnv1a64 = 0xf30c0f733e400003ULL;
constexpr size_t kMaxLoggedSelectors = 32;

void Log(const char *level, const std::string &message)
{
#if defined(HM_CA_HAS_HILOG)
    OH_LOG_Print(LOG_APP, std::strcmp(level, "ERROR") == 0 ? LOG_ERROR : LOG_INFO,
        0x484d, "HarmoniosCARenderer", "%{public}s: %{public}s", level, message.c_str());
#else
    std::fprintf(stderr, "HarmoniosCARenderer %s: %s\n", level, message.c_str());
#endif
}

uint64_t StripCode(uint64_t pointer)
{
#if defined(__aarch64__)
    return hm_pac_strip_instruction(pointer);
#else
    return pointer;
#endif
}

uint64_t StripData(uint64_t pointer)
{
#if defined(__aarch64__)
    return hm_pac_strip_data(pointer);
#else
    return pointer;
#endif
}

template <typename T>
T CodePointer(uint64_t pointer)
{
    if (!pointer) return nullptr;
    const uint64_t raw = StripCode(pointer);
#if defined(__aarch64__)
    return reinterpret_cast<T>(hm_pac_sign_pointer(raw, 0, 0));
#else
    return reinterpret_cast<T>(raw);
#endif
}

template <typename T>
T HostImplementation(T pointer)
{
#if defined(__aarch64__)
    return reinterpret_cast<T>(hm_pac_sign_pointer(reinterpret_cast<uint64_t>(pointer), 0, 0));
#else
    return pointer;
#endif
}

struct ObjcMethodDescription {
    void *name;
    const char *types;
};

struct RuntimeApi {
    void *(*objc_getClass)(const char *) = nullptr;
    void *(*objc_allocateClassPair)(void *, const char *, size_t) = nullptr;
    void (*objc_registerClassPair)(void *) = nullptr;
    bool (*class_addMethod)(void *, void *, void *, const char *) = nullptr;
    bool (*class_addProtocol)(void *, void *) = nullptr;
    bool (*class_conformsToProtocol)(void *, void *) = nullptr;
    void *(*object_getClass)(void *) = nullptr;
    const char *(*class_getName)(void *) = nullptr;
    void *(*class_getSuperclass)(void *) = nullptr;
    void *(*class_getInstanceMethod)(void *, void *) = nullptr;
    void *(*sel_registerName)(const char *) = nullptr;
    const char *(*sel_getName)(void *) = nullptr;
    void *(*class_getMethodImplementation)(void *, void *) = nullptr;
    bool (*class_respondsToSelector)(void *, void *) = nullptr;
    const char *(*method_getTypeEncoding)(void *) = nullptr;
    void *(*objc_getProtocol)(const char *) = nullptr;
    void **(*objc_copyProtocolList)(unsigned *) = nullptr;
    const char *(*protocol_getName)(void *) = nullptr;
    ObjcMethodDescription (*protocol_getMethodDescription)(void *, void *, bool, bool) = nullptr;
    void (*guest_free)(void *) = nullptr;
    void *(*dlopen)(const char *, int) = nullptr;
    void *(*dlsym)(void *, const char *) = nullptr;
};

RuntimeApi g_rt;
bool g_runtimeReady = false;
std::string g_runtimeError;

template <typename T>
bool ResolveRuntime(T &output, const char *name, std::vector<std::string> &missing)
{
    const uint64_t address = HmGuestObjcRuntimeSymbol(name);
    if (!address) {
        missing.emplace_back(name);
        return false;
    }
    output = CodePointer<T>(address);
    return output != nullptr;
}

bool EnsureRuntime()
{
    if (g_runtimeReady) return true;
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    if (g_runtimeReady) return true;
    RuntimeApi api;
    std::vector<std::string> missing;
    ResolveRuntime(api.objc_getClass, "_objc_getClass", missing);
    ResolveRuntime(api.objc_allocateClassPair, "_objc_allocateClassPair", missing);
    ResolveRuntime(api.objc_registerClassPair, "_objc_registerClassPair", missing);
    ResolveRuntime(api.class_addMethod, "_class_addMethod", missing);
    ResolveRuntime(api.class_addProtocol, "_class_addProtocol", missing);
    ResolveRuntime(api.class_conformsToProtocol, "_class_conformsToProtocol", missing);
    ResolveRuntime(api.object_getClass, "_object_getClass", missing);
    ResolveRuntime(api.class_getName, "_class_getName", missing);
    ResolveRuntime(api.class_getSuperclass, "_class_getSuperclass", missing);
    ResolveRuntime(api.class_getInstanceMethod, "_class_getInstanceMethod", missing);
    ResolveRuntime(api.sel_registerName, "_sel_registerName", missing);
    ResolveRuntime(api.sel_getName, "_sel_getName", missing);
    ResolveRuntime(api.class_getMethodImplementation, "_class_getMethodImplementation", missing);
    ResolveRuntime(api.class_respondsToSelector, "_class_respondsToSelector", missing);
    ResolveRuntime(api.method_getTypeEncoding, "_method_getTypeEncoding", missing);
    ResolveRuntime(api.objc_getProtocol, "_objc_getProtocol", missing);
    ResolveRuntime(api.objc_copyProtocolList, "_objc_copyProtocolList", missing);
    ResolveRuntime(api.protocol_getName, "_protocol_getName", missing);
    ResolveRuntime(api.protocol_getMethodDescription, "_protocol_getMethodDescription", missing);
    ResolveRuntime(api.guest_free, "_free", missing);
    ResolveRuntime(api.dlopen, "_dlopen", missing);
    ResolveRuntime(api.dlsym, "_dlsym", missing);
    if (!missing.empty()) {
        std::ostringstream error;
        error << "guest runtime symbols unavailable:";
        for (const auto &name : missing) error << ' ' << name;
        g_runtimeError = error.str();
        return false;
    }
    g_rt = api;
    // RTLD_NOW on Darwin is 2. Loading the real frameworks also makes their
    // classes, protocols, C entry points and exported NSString keys visible.
    const char *const frameworks[] = {
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        "/System/Library/Frameworks/CoreText.framework/CoreText",
        "/System/Library/Frameworks/Metal.framework/Metal",
        "/System/Library/Frameworks/QuartzCore.framework/QuartzCore",
    };
    for (const char *path : frameworks) {
        if (!g_rt.dlopen(path, 2)) {
            g_runtimeError = std::string("guest dlopen failed: ") + path;
            g_rt = {};
            return false;
        }
    }
    g_runtimeReady = true;
    g_runtimeError.clear();
    return true;
}

void *Selector(const char *name)
{
    if (!g_runtimeReady || !name) return nullptr;
    return reinterpret_cast<void *>(StripData(
        reinterpret_cast<uint64_t>(g_rt.sel_registerName(name))));
}

void *GetClass(const char *name)
{
    return g_runtimeReady && name ? g_rt.objc_getClass(name) : nullptr;
}

void *Lookup(void *receiver, const char *name)
{
    if (!receiver || !name) return nullptr;
    void *selector = Selector(name);
    void *cls = g_rt.object_getClass(receiver);
    if (!selector || !cls || !g_rt.class_respondsToSelector(cls, selector)) return nullptr;
    return CodePointer<void *>(reinterpret_cast<uint64_t>(
        g_rt.class_getMethodImplementation(cls, selector)));
}

// Local equivalents of the execution probe's minimal helpers. They resolve
// through Apple class_getMethodImplementation rather than objc_msgSend so the
// same PAC convention is applied at every indirect guest call.
void *CallObject(void *receiver, const char *name)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return nullptr;
    using Method = void *(*)(void *, void *);
    return reinterpret_cast<Method>(implementation)(receiver, Selector(name));
}

void *CallObjects(void *receiver, const char *name, void *a0 = nullptr,
    void *a1 = nullptr, void *a2 = nullptr, void *a3 = nullptr, void *a4 = nullptr)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return nullptr;
    using Method = void *(*)(void *, void *, void *, void *, void *, void *, void *);
    return reinterpret_cast<Method>(implementation)(receiver, Selector(name), a0, a1, a2, a3, a4);
}

bool CallVoid(void *receiver, const char *name)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return false;
    using Method = void (*)(void *, void *);
    reinterpret_cast<Method>(implementation)(receiver, Selector(name));
    return true;
}

bool CallVoidObjects(void *receiver, const char *name, void *a0 = nullptr,
    void *a1 = nullptr, void *a2 = nullptr, void *a3 = nullptr, void *a4 = nullptr)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return false;
    using Method = void (*)(void *, void *, void *, void *, void *, void *, void *);
    reinterpret_cast<Method>(implementation)(receiver, Selector(name), a0, a1, a2, a3, a4);
    return true;
}

uint64_t CallUint(void *receiver, const char *name)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return 0;
    using Method = uint64_t (*)(void *, void *);
    return reinterpret_cast<Method>(implementation)(receiver, Selector(name));
}

float CallFloat(void *receiver, const char *name)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return 0;
    using Method = float (*)(void *, void *);
    return reinterpret_cast<Method>(implementation)(receiver, Selector(name));
}

struct CGPoint { double x, y; };
struct CGSize { double width, height; };
struct CGRect { CGPoint origin; CGSize size; };
struct CATransform3D { double m[16]; };
static_assert(sizeof(CGPoint) == 16 && sizeof(CGRect) == 32 && sizeof(CATransform3D) == 128,
    "ARM64 CoreGraphics/CoreAnimation layout");

struct MTLTextureDescriptorPrivatePrefix {
    uint64_t textureType, pixelFormat, width, height, depth, mipmapLevelCount, sampleCount, arrayLength;
    bool zeroFill;
    uint64_t rotation;
    bool framebufferOnly, isDrawable;
    uint32_t swizzle;
    bool writeSwizzleEnabled;
    uint64_t compressionMode, usage;
};
static_assert(sizeof(MTLTextureDescriptorPrivatePrefix) == 112 &&
    offsetof(MTLTextureDescriptorPrivatePrefix, width) == 16 &&
    offsetof(MTLTextureDescriptorPrivatePrefix, usage) == 104,
    "MTLTextureDescriptorPrivate prefix layout");

struct MTLOrigin { uint64_t x, y, z; };
struct MTLSize { uint64_t width, height, depth; };
struct MTLRegion { MTLOrigin origin; MTLSize size; };
struct MTLClearColor { double red, green, blue, alpha; };
struct MTLViewport { double originX, originY, width, height, znear, zfar; };
struct MTLScissorRect { uint64_t x, y, width, height; };
static_assert(sizeof(MTLRegion) == 48, "ARM64 MTLRegion layout");
static_assert(sizeof(MTLClearColor) == 32, "ARM64 MTLClearColor layout");

MTLClearColor CallClearColor(void *receiver, const char *name)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return {0, 0, 0, 1};
    using Method = MTLClearColor (*)(void *, void *);
    return reinterpret_cast<Method>(implementation)(receiver, Selector(name));
}

bool CallBool(void *receiver, const char *name)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return false;
    using Method = bool (*)(void *, void *);
    return reinterpret_cast<Method>(implementation)(receiver, Selector(name));
}

bool SetRect(void *receiver, const char *name, CGRect value)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return false;
    using Method = void (*)(void *, void *, CGRect);
    reinterpret_cast<Method>(implementation)(receiver, Selector(name), value);
    return true;
}

CGRect CallRect(void *receiver, const char *name)
{
    CGRect value {};
    void *implementation = Lookup(receiver, name);
    if (!implementation) return value;
    using Method = CGRect (*)(void *, void *);
    return reinterpret_cast<Method>(implementation)(receiver, Selector(name));
}

bool SetPoint(void *receiver, const char *name, CGPoint value)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return false;
    using Method = void (*)(void *, void *, CGPoint);
    reinterpret_cast<Method>(implementation)(receiver, Selector(name), value);
    return true;
}

bool SetBool(void *receiver, const char *name, bool value)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return false;
    using Method = void (*)(void *, void *, bool);
    reinterpret_cast<Method>(implementation)(receiver, Selector(name), value);
    return true;
}

bool SetUint(void *receiver, const char *name, uint64_t value)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return false;
    using Method = void (*)(void *, void *, uint64_t);
    reinterpret_cast<Method>(implementation)(receiver, Selector(name), value);
    return true;
}

bool SetDouble(void *receiver, const char *name, double value)
{
    void *implementation = Lookup(receiver, name);
    if (!implementation) return false;
    using Method = void (*)(void *, void *, double);
    reinterpret_cast<Method>(implementation)(receiver, Selector(name), value);
    return true;
}

bool SetLayerTransform(void *receiver, CATransform3D transform)
{
    void *implementation = Lookup(receiver, "setTransform:");
    if (!implementation) return false;
    using Method = void (*)(void *, void *, CATransform3D);
    reinterpret_cast<Method>(implementation)(receiver, Selector("setTransform:"), transform);
    return true;
}

std::string BridgeError()
{
    const char *error = hm_metal_objc_last_error();
    return error && *error ? error : "unspecified Metal bridge error";
}

std::mutex g_selectorMutex;
std::set<std::string> g_seenSelectors;
std::vector<std::string> g_unimplementedSelectors;
thread_local std::string t_facadeError;

void NoteUnimplemented(void *receiver, void *selector)
{
    const char *selectorName = selector ? g_rt.sel_getName(selector) : nullptr;
    void *cls = receiver ? g_rt.object_getClass(receiver) : nullptr;
    const char *className = cls ? g_rt.class_getName(cls) : nullptr;
    std::string key = std::string(className ? className : "<nil>") + " " +
        (selectorName ? selectorName : "<nil>");
    {
        std::lock_guard<std::mutex> lock(g_selectorMutex);
        if (!g_seenSelectors.insert(key).second) return;
        if (g_unimplementedSelectors.size() < kMaxLoggedSelectors)
            g_unimplementedSelectors.push_back(key);
    }
    Log("INFO", key + ": unimplemented selector; forwarding a zero return");
}

void *MethodSignatureForSelector(void *self, void *, void *selector)
{
    void *cls = g_rt.object_getClass(self);
    void *method = g_rt.class_getInstanceMethod(cls, selector);
    if (method) {
        const char *types = g_rt.method_getTypeEncoding(method);
        if (types) return CallObjects(GetClass("NSMethodSignature"),
            "signatureWithObjCTypes:", const_cast<char *>(types));
    }
    // All facade classes implement only MTL* protocols. Restrict fallback to
    // those declarations, as Chlorophyll does, instead of swallowing arbitrary
    // NSObject messages with fabricated signatures. This also covers inherited
    // MTLResource and MTLAllocation declarations.
    unsigned count = 0;
    void **all = g_rt.objc_copyProtocolList(&count);
    void *signature = nullptr;
    for (unsigned i = 0; i < count && !signature; ++i) {
        const char *candidate = g_rt.protocol_getName(all[i]);
        if (!candidate || std::strncmp(candidate, "MTL", 3) != 0) continue;
        for (int required = 1; required >= 0 && !signature; --required) {
            ObjcMethodDescription description = g_rt.protocol_getMethodDescription(
                all[i], selector, required != 0, true);
            if (description.name && description.types) {
                signature = CallObjects(GetClass("NSMethodSignature"),
                    "signatureWithObjCTypes:", const_cast<char *>(description.types));
            }
        }
    }
    if (all) g_rt.guest_free(all);
    return signature;
}

void ForwardInvocation(void *self, void *, void *invocation)
{
    void *selector = CallObject(invocation, "selector");
    NoteUnimplemented(self, selector);
    void *signature = CallObject(invocation, "methodSignature");
    const uint64_t length = signature ? CallUint(signature, "methodReturnLength") : 0;
    if (!length) return;
    if (length > 4096) {
        Log("ERROR", "refusing an excessive forwarded return allocation");
        return;
    }
    std::vector<uint8_t> zero(static_cast<size_t>(length), 0);
    CallVoidObjects(invocation, "setReturnValue:", zero.data());
}

enum class FacadeKind {
    Device, Texture, Queue, CommandBuffer, Library, Function, Pipeline, Buffer, RenderEncoder,
    Sampler, Count
};
constexpr size_t kFacadeCount = static_cast<size_t>(FacadeKind::Count);
std::array<void *, kFacadeCount> g_facadeClasses {};
std::array<const char *, kFacadeCount> g_facadeNames {{
    "HarmoniosMetalDevice", "HarmoniosMetalTexture",
    "HarmoniosMetalCommandQueue", "HarmoniosMetalCommandBuffer",
    "HarmoniosMetalLibrary", "HarmoniosMetalFunction", "HarmoniosMetalRenderPipelineState",
    "HarmoniosMetalBuffer", "HarmoniosMetalRenderCommandEncoder",
    "HarmoniosMetalSamplerState"
}};

struct HandleEntry {
    FacadeKind kind;
    uint64_t handle;
    uint64_t protectionOptions = 0;
    void *label = nullptr;
    void *parent = nullptr;
    std::vector<uint32_t> responsibleTaskIds {};
};
std::mutex g_handleMutex;
std::unordered_map<void *, HandleEntry> g_handles;

uint64_t Handle(void *object)
{
    std::lock_guard<std::mutex> lock(g_handleMutex);
    auto found = g_handles.find(object);
    return found == g_handles.end() ? 0 : found->second.handle;
}

FacadeKind Kind(void *object)
{
    std::lock_guard<std::mutex> lock(g_handleMutex);
    auto found = g_handles.find(object);
    return found == g_handles.end() ? FacadeKind::Count : found->second.kind;
}

uint64_t TakeHandle(void *object, FacadeKind expected)
{
    HandleEntry entry {FacadeKind::Count, 0};
    {
        std::lock_guard<std::mutex> lock(g_handleMutex);
        auto found = g_handles.find(object);
        if (found == g_handles.end() || found->second.kind != expected) return 0;
        entry = found->second;
        g_handles.erase(found);
    }
    if (entry.label) CallVoid(entry.label, "release");
    if (entry.parent) CallVoid(entry.parent, "release");
    return entry.handle;
}

uint64_t CommandBufferProtection(void *object)
{
    std::lock_guard<std::mutex> lock(g_handleMutex);
    auto found = g_handles.find(object);
    return found != g_handles.end() && found->second.kind == FacadeKind::CommandBuffer
        ? found->second.protectionOptions : 0;
}

void *Parent(void *object)
{
    std::lock_guard<std::mutex> lock(g_handleMutex);
    auto found = g_handles.find(object);
    return found == g_handles.end() ? nullptr : found->second.parent;
}

void ReleaseRustHandle(FacadeKind kind, uint64_t handle)
{
    if (!handle) return;
    switch (kind) {
    case FacadeKind::Device: hm_metal_objc_device_release(handle); break;
    case FacadeKind::Texture: hm_metal_objc_texture_release(handle); break;
    case FacadeKind::Queue: hm_metal_objc_queue_release(handle); break;
    case FacadeKind::CommandBuffer: hm_metal_objc_command_buffer_release(handle); break;
    case FacadeKind::Library: hm_metal_objc_library_release(handle); break;
    case FacadeKind::Function: hm_metal_objc_function_release(handle); break;
    case FacadeKind::Pipeline: hm_metal_objc_pipeline_release(handle); break;
    case FacadeKind::Buffer: hm_metal_objc_buffer_release(handle); break;
    case FacadeKind::RenderEncoder: hm_metal_objc_encoder_release(handle); break;
    case FacadeKind::Sampler: hm_metal_objc_sampler_release(handle); break;
    case FacadeKind::Count: break;
    }
}

void Dealloc(void *self, void *)
{
    HandleEntry entry {FacadeKind::Count, 0};
    {
        std::lock_guard<std::mutex> lock(g_handleMutex);
        auto found = g_handles.find(self);
        if (found != g_handles.end()) {
            entry = found->second;
            g_handles.erase(found);
        }
    }
    ReleaseRustHandle(entry.kind, entry.handle);
    if (entry.label) CallVoid(entry.label, "release");
    if (entry.parent) CallVoid(entry.parent, "release");
    // The facade has no Apple C++ implementation object. Calling a private
    // Metal superclass destructor would dereference state that never existed.

}

struct MethodSpec { const char *name; void *implementation; const char *types; };

bool AddMethods(void *cls, const MethodSpec *specs, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (!g_rt.class_addMethod(cls, Selector(specs[i].name), specs[i].implementation, specs[i].types)) {
            Log("ERROR", std::string("class_addMethod failed for ") + specs[i].name);
            return false;
        }
    }
    return true;
}

bool AddProtocol(void *cls, const char *name)
{
    void *protocol = g_rt.objc_getProtocol(name);
    if (!protocol) {
        Log("INFO", std::string("optional protocol absent: ") + name);
        return true;
    }
    if (g_rt.class_conformsToProtocol(cls, protocol)) return true;
    if (g_rt.class_addProtocol(cls, protocol)) return true;
    return g_rt.class_conformsToProtocol(cls, protocol);
}

void *MakeFacade(FacadeKind kind, uint64_t handle, void *parent = nullptr);

void *DeviceNewTexture(void *self, void *, void *descriptor);
void *DeviceNewQueue(void *self, void *);
void *DeviceNewQueueDescriptor(void *self, void *, void *);
void *DeviceName(void *self, void *);
uint64_t DeviceRegistryID(void *self, void *);
uint64_t DeviceFeatureProfile(void *, void *) { return 1; }
uint64_t DeviceMaxBufferLength(void *self, void *);
uint64_t DevicePrivateCount(void *self, void *selector);
bool DeviceSupportsVertexAmplification(void *, void *, uint64_t) { return false; }
void *DeviceNewDepthStencil(void *self, void *, void *descriptor);
void *DeviceNewLibraryURL(void *self, void *, void *url, void **error);
void *DeviceNewLibraryData(void *self, void *, void *data, void **error);
void *DeviceNewDefaultLibrary(void *self, void *);
void *DeviceNewRenderPipeline(void *self, void *, void *descriptor, void **error);
void *DeviceNewSampler(void *self, void *, void *descriptor);
void *SamplerDevice(void *, void *);
void *SamplerLabel(void *, void *);
void *LibraryNewFunction(void *self, void *, void *name);
void *LibraryNewFunctionDescriptor(void *self, void *, void *descriptor, void *archive, void **error);
void *FunctionName(void *self, void *);
void *FunctionNewSpecialized(void *self, void *, void *descriptor, void *archive,
    void *cache, void **error);
void *PipelineDevice(void *, void *);
void *PipelineLabel(void *, void *);
void *DepthLabel(void *, void *);
void *DepthDevice(void *, void *);
uint64_t DepthCompare(void *, void *);
bool DepthWrite(void *, void *);
bool DepthReadsDepth(void *, void *);
bool DepthReadsStencil(void *, void *);
bool DepthWritesDepth(void *, void *);
bool DepthWritesStencil(void *, void *);
uint64_t DepthUniqueIdentifier(void *, void *);
uint64_t DepthResourceIndex(void *, void *);
uint64_t DepthHash(void *, void *);
struct DepthResourceID;
DepthResourceID DepthGpuResourceID(void *, void *);
extern void *g_defaultDevice;
void *UnsupportedObject(void *self, void *selector);
void *UnsupportedObjectObject(void *self, void *selector, void *object);
void *UnsupportedObjectObjectError(void *self, void *selector, void *object, void **error);
void *DeviceNewBufferLength(void *self, void *, uint64_t length, uint64_t options);
void *DeviceNewBufferBytes(void *self, void *, const void *bytes,
    uint64_t length, uint64_t options);
void *BufferDevice(void *self, void *);
uint64_t BufferLength(void *self, void *);
void *BufferContents(void *self, void *);
void BufferSetLabel(void *self, void *, void *label);
void *BufferLabel(void *self, void *);
void *TextureDevice(void *self, void *);
uint64_t TextureWidth(void *self, void *);
uint64_t TextureHeight(void *self, void *);
uint64_t TextureDepth(void *self, void *);
uint64_t TextureMipmaps(void *self, void *);
uint64_t TextureArrayLength(void *self, void *);
uint64_t TextureSamples(void *self, void *);
uint64_t TexturePixelFormat(void *self, void *);
uint64_t TextureType(void *self, void *);
uint64_t TextureUsage(void *self, void *);
uint64_t TextureAPI(void *, void *) { return 2; }
uint64_t TextureStorageMode(void *self, void *);
uint64_t TextureCacheMode(void *self, void *);
uint64_t TextureHazardMode(void *self, void *);
uint64_t TextureResourceOptions(void *self, void *);
bool TextureAllowOptimized(void *self, void *);
bool TextureFramebufferOnly(void *, void *) { return false; }
uint64_t TextureProtectionOptions(void *self, void *);
void TextureGetBytes(void *self, void *, void *bytes, uint64_t bytesPerRow,
    MTLRegion region, uint64_t level);
void TextureGetBytesSlice(void *self, void *, void *bytes, uint64_t bytesPerRow,
    uint64_t bytesPerImage, MTLRegion region, uint64_t level, uint64_t slice);
void TextureReplaceRegion(void *self, void *, MTLRegion region, uint64_t level,
    const void *bytes, uint64_t bytesPerRow);
void TextureReplaceRegionSlice(void *self, void *, MTLRegion region, uint64_t level,
    uint64_t slice, const void *bytes, uint64_t bytesPerRow, uint64_t bytesPerImage);
void *QueueDevice(void *self, void *);
void *QueueCommandBuffer(void *self, void *);
void *QueueCommandBufferDescriptor(void *self, void *, void *);
void *CommandBufferDevice(void *self, void *);
void CommandBufferCommit(void *self, void *);
void CommandBufferWait(void *self, void *);
void CommandBufferWaitScheduled(void *self, void *);
uint64_t CommandBufferStatus(void *self, void *);
bool CommandBufferRetainedReferences(void *, void *) { return true; }
void CommandBufferSetProtectionOptions(void *self, void *, uint64_t options);
uint64_t CommandBufferProtectionOptions(void *self, void *);
void CommandBufferSetResponsibleTaskIDs(void *self, void *, const uint32_t *ids, uint32_t count);
void *CommandBufferRenderEncoder(void *self, void *, void *descriptor);
void EncoderSetLabel(void *self, void *, void *label);
void *EncoderLabel(void *self, void *);
void EncoderSetViewport(void *self, void *, MTLViewport viewport);
void EncoderSetScissor(void *self, void *, MTLScissorRect rect);
void EncoderSetVertexBufferOffset(void *self, void *, uint64_t offset, uint64_t index);
void EncoderSetFragmentBufferOffset(void *self, void *, uint64_t offset, uint64_t index);
void EncoderDrawIndexed(void *self, void *, uint64_t primitive, uint64_t count,
    uint64_t indexType, void *indexBuffer, uint64_t indexOffset);
void EncoderSetPipeline(void *self, void *, void *pipeline);
void EncoderSetVertexBuffer(void *self, void *, void *buffer, uint64_t offset, uint64_t index);
void EncoderSetFragmentBuffer(void *self, void *, void *buffer, uint64_t offset, uint64_t index);
void EncoderSetFragmentTexture(void *self, void *, void *texture, uint64_t index);
void EncoderSetFragmentSampler(void *self, void *, void *sampler, uint64_t index);
void EncoderDraw(void *self, void *, uint64_t primitive, uint64_t start, uint64_t count);
void EncoderDrawInstances(void *self, void *, uint64_t primitive, uint64_t start,
    uint64_t count, uint64_t instances);
void EncoderDrawBaseInstance(void *self, void *, uint64_t primitive, uint64_t start,
    uint64_t count, uint64_t instances, uint64_t baseInstance);
void EncoderEnd(void *self, void *);

bool EnsureFacades()
{
    static std::mutex mutex;
    static bool ready = false;
    if (ready) return true;
    std::lock_guard<std::mutex> lock(mutex);
    if (ready) return true;
    if (!EnsureRuntime()) return false;

    const MethodSpec deviceMethods[] = {
        {"newTextureWithDescriptor:", reinterpret_cast<void *>(&DeviceNewTexture), "@24@0:8@16"},
        {"newCommandQueue", reinterpret_cast<void *>(&DeviceNewQueue), "@16@0:8"},
        {"newCommandQueueWithDescriptor:", reinterpret_cast<void *>(&DeviceNewQueueDescriptor), "@24@0:8@16"},
        {"name", reinterpret_cast<void *>(&DeviceName), "@16@0:8"},
        {"registryID", reinterpret_cast<void *>(&DeviceRegistryID), "Q16@0:8"},
        {"featureProfile", reinterpret_cast<void *>(&DeviceFeatureProfile), "Q16@0:8"},
        {"maxBufferLength", reinterpret_cast<void *>(&DeviceMaxBufferLength), "Q16@0:8"},
        {"gpuCoreCount", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxVertexAmplificationCount", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"deviceLinearTextureAlignmentBytes", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"linearTextureAlignmentBytes", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"iosurfaceTextureAlignmentBytes", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"iosurfaceReadOnlyTextureAlignmentBytes", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxVertexBuffers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxFragmentBuffers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxComputeBuffers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxTileBuffers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxVertexTextures", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxFragmentTextures", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxComputeTextures", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxTileTextures", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxVertexSamplers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxFragmentSamplers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxComputeSamplers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxTileSamplers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxComputeLocalMemorySizes", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxComputeThreadgroupMemory", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxComputeThreadgroupMemoryAlignmentBytes", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxPredicatedNestingDepth", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxRasterizationRateLayerCount", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxTextureWidth2D", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxTextureHeight2D", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxTextureLayers", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxTotalComputeThreadsPerThreadgroup", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"maxViewportCount", reinterpret_cast<void *>(&DevicePrivateCount), "Q16@0:8"},
        {"supportsVertexAmplificationCount:", reinterpret_cast<void *>(&DeviceSupportsVertexAmplification), "B24@0:8Q16"},
        {"newLibraryWithURL:error:", reinterpret_cast<void *>(&DeviceNewLibraryURL), "@32@0:8@16^@24"},
        {"newLibraryWithFile:error:", reinterpret_cast<void *>(&DeviceNewLibraryURL), "@32@0:8@16^@24"},
        {"newLibraryWithData:error:", reinterpret_cast<void *>(&DeviceNewLibraryData), "@32@0:8@16^@24"},
        {"newDefaultLibrary", reinterpret_cast<void *>(&DeviceNewDefaultLibrary), "@16@0:8"},
        {"newDefaultLibraryWithBundle:error:", reinterpret_cast<void *>(&DeviceNewDefaultLibrary), "@32@0:8@16^@24"},
        {"newBufferWithLength:options:", reinterpret_cast<void *>(&DeviceNewBufferLength), "@32@0:8Q16Q24"},
        {"newBufferWithBytes:length:options:", reinterpret_cast<void *>(&DeviceNewBufferBytes), "@40@0:8r^v16Q24Q32"},
        {"newRenderPipelineStateWithDescriptor:error:", reinterpret_cast<void *>(&DeviceNewRenderPipeline), "@32@0:8@16^@24"},
        {"newSamplerStateWithDescriptor:", reinterpret_cast<void *>(&DeviceNewSampler), "@24@0:8@16"},
        {"newDepthStencilStateWithDescriptor:", reinterpret_cast<void *>(&DeviceNewDepthStencil), "@24@0:8@16"},
    };
    const MethodSpec textureMethods[] = {
        {"device", reinterpret_cast<void *>(&TextureDevice), "@16@0:8"},
        {"width", reinterpret_cast<void *>(&TextureWidth), "Q16@0:8"},
        {"height", reinterpret_cast<void *>(&TextureHeight), "Q16@0:8"},
        {"depth", reinterpret_cast<void *>(&TextureDepth), "Q16@0:8"},
        {"mipmapLevelCount", reinterpret_cast<void *>(&TextureMipmaps), "Q16@0:8"},
        {"arrayLength", reinterpret_cast<void *>(&TextureArrayLength), "Q16@0:8"},
        {"sampleCount", reinterpret_cast<void *>(&TextureSamples), "Q16@0:8"},
        {"pixelFormat", reinterpret_cast<void *>(&TexturePixelFormat), "Q16@0:8"},
        {"textureType", reinterpret_cast<void *>(&TextureType), "Q16@0:8"},
        {"usage", reinterpret_cast<void *>(&TextureUsage), "Q16@0:8"},
        {"API", reinterpret_cast<void *>(&TextureAPI), "Q16@0:8"},
        {"storageMode", reinterpret_cast<void *>(&TextureStorageMode), "Q16@0:8"},
        {"cpuCacheMode", reinterpret_cast<void *>(&TextureCacheMode), "Q16@0:8"},
        {"hazardTrackingMode", reinterpret_cast<void *>(&TextureHazardMode), "Q16@0:8"},
        {"resourceOptions", reinterpret_cast<void *>(&TextureResourceOptions), "Q16@0:8"},
        {"allowGPUOptimizedContents", reinterpret_cast<void *>(&TextureAllowOptimized), "B16@0:8"},
        {"isFramebufferOnly", reinterpret_cast<void *>(&TextureFramebufferOnly), "B16@0:8"},
        {"protectionOptions", reinterpret_cast<void *>(&TextureProtectionOptions), "Q16@0:8"},
        {"getBytes:bytesPerRow:fromRegion:mipmapLevel:", reinterpret_cast<void *>(&TextureGetBytes),
            "v88@0:8^v16Q24{?={?=QQQ}{?=QQQ}}32Q80"},
        {"getBytes:bytesPerRow:bytesPerImage:fromRegion:mipmapLevel:slice:",
            reinterpret_cast<void *>(&TextureGetBytesSlice),
            "v104@0:8^v16Q24Q32{?={?=QQQ}{?=QQQ}}40Q88Q96"},
        {"replaceRegion:mipmapLevel:withBytes:bytesPerRow:",
            reinterpret_cast<void *>(&TextureReplaceRegion),
            "v88@0:8{?={?=QQQ}{?=QQQ}}16Q64^v72Q80"},
        {"replaceRegion:mipmapLevel:slice:withBytes:bytesPerRow:bytesPerImage:",
            reinterpret_cast<void *>(&TextureReplaceRegionSlice),
            "v104@0:8{?={?=QQQ}{?=QQQ}}16Q64Q72^v80Q88Q96"},
    };
    const MethodSpec queueMethods[] = {
        {"device", reinterpret_cast<void *>(&QueueDevice), "@16@0:8"},
        {"commandBuffer", reinterpret_cast<void *>(&QueueCommandBuffer), "@16@0:8"},
        {"commandBufferWithDescriptor:", reinterpret_cast<void *>(&QueueCommandBufferDescriptor), "@24@0:8@16"},
    };
    const MethodSpec bufferMethods[] = {
        {"device", reinterpret_cast<void *>(&CommandBufferDevice), "@16@0:8"},
        {"commit", reinterpret_cast<void *>(&CommandBufferCommit), "v16@0:8"},
        {"waitUntilCompleted", reinterpret_cast<void *>(&CommandBufferWait), "v16@0:8"},
        {"waitUntilScheduled", reinterpret_cast<void *>(&CommandBufferWaitScheduled), "v16@0:8"},
        {"status", reinterpret_cast<void *>(&CommandBufferStatus), "Q16@0:8"},
        {"retainedReferences", reinterpret_cast<void *>(&CommandBufferRetainedReferences), "B16@0:8"},
        {"setResponsibleTaskIDs:count:", reinterpret_cast<void *>(&CommandBufferSetResponsibleTaskIDs), "v28@0:8r^I16I24"},
        {"setProtectionOptions:", reinterpret_cast<void *>(&CommandBufferSetProtectionOptions), "v24@0:8Q16"},
        {"protectionOptions", reinterpret_cast<void *>(&CommandBufferProtectionOptions), "Q16@0:8"},
        {"renderCommandEncoderWithDescriptor:", reinterpret_cast<void *>(&CommandBufferRenderEncoder), "@24@0:8@16"},
        {"blitCommandEncoder", reinterpret_cast<void *>(&UnsupportedObject), "@16@0:8"},
        {"computeCommandEncoder", reinterpret_cast<void *>(&UnsupportedObject), "@16@0:8"},
        {"computeCommandEncoderWithDescriptor:", reinterpret_cast<void *>(&UnsupportedObjectObject), "@24@0:8@16"},
        {"blitCommandEncoderWithDescriptor:", reinterpret_cast<void *>(&UnsupportedObjectObject), "@24@0:8@16"},
    };
    const MethodSpec libraryMethods[] = {
        {"newFunctionWithName:", reinterpret_cast<void *>(&LibraryNewFunction), "@24@0:8@16"},
        {"newFunctionWithDescriptor:destinationArchive:error:",
            reinterpret_cast<void *>(&LibraryNewFunctionDescriptor), "@40@0:8@16@24^@32"},
    };
    const MethodSpec functionMethods[] = {
        {"name", reinterpret_cast<void *>(&FunctionName), "@16@0:8"},
        {"newSpecializedFunctionWithDescriptor:destinationArchive:functionCache:error:",
            reinterpret_cast<void *>(&FunctionNewSpecialized), "@48@0:8@16@24@32^@40"},
    };
    const MethodSpec pipelineMethods[] = {
        {"label", reinterpret_cast<void *>(&PipelineLabel), "@16@0:8"},
        {"device", reinterpret_cast<void *>(&PipelineDevice), "@16@0:8"},
    };
    const MethodSpec realBufferMethods[] = {
        {"device", reinterpret_cast<void *>(&BufferDevice), "@16@0:8"},
        {"length", reinterpret_cast<void *>(&BufferLength), "Q16@0:8"},
        {"contents", reinterpret_cast<void *>(&BufferContents), "^v16@0:8"},
        {"setLabel:", reinterpret_cast<void *>(&BufferSetLabel), "v24@0:8@16"},
        {"label", reinterpret_cast<void *>(&BufferLabel), "@16@0:8"},
    };
    const MethodSpec encoderMethods[] = {
        {"setLabel:", reinterpret_cast<void *>(&EncoderSetLabel), "v24@0:8@16"},
        {"label", reinterpret_cast<void *>(&EncoderLabel), "@16@0:8"},
        {"setViewport:", reinterpret_cast<void *>(&EncoderSetViewport), "v64@0:8{?=dddddd}16"},
        {"setScissorRect:", reinterpret_cast<void *>(&EncoderSetScissor), "v48@0:8{?=QQQQ}16"},
        {"setVertexBufferOffset:atIndex:", reinterpret_cast<void *>(&EncoderSetVertexBufferOffset), "v32@0:8Q16Q24"},
        {"setFragmentBufferOffset:atIndex:", reinterpret_cast<void *>(&EncoderSetFragmentBufferOffset), "v32@0:8Q16Q24"},
        {"drawIndexedPrimitives:indexCount:indexType:indexBuffer:indexBufferOffset:", reinterpret_cast<void *>(&EncoderDrawIndexed), "v56@0:8Q16Q24Q32@40Q48"},
        {"setRenderPipelineState:", reinterpret_cast<void *>(&EncoderSetPipeline), "v24@0:8@16"},
        {"setVertexBuffer:offset:atIndex:", reinterpret_cast<void *>(&EncoderSetVertexBuffer), "v40@0:8@16Q24Q32"},
        {"setFragmentBuffer:offset:atIndex:", reinterpret_cast<void *>(&EncoderSetFragmentBuffer), "v40@0:8@16Q24Q32"},
        {"setFragmentTexture:atIndex:", reinterpret_cast<void *>(&EncoderSetFragmentTexture), "v32@0:8@16Q24"},
        {"setFragmentSamplerState:atIndex:", reinterpret_cast<void *>(&EncoderSetFragmentSampler), "v32@0:8@16Q24"},
        {"drawPrimitives:vertexStart:vertexCount:", reinterpret_cast<void *>(&EncoderDraw), "v40@0:8Q16Q24Q32"},
        {"drawPrimitives:vertexStart:vertexCount:instanceCount:", reinterpret_cast<void *>(&EncoderDrawInstances), "v48@0:8Q16Q24Q32Q40"},
        {"drawPrimitives:vertexStart:vertexCount:instanceCount:baseInstance:", reinterpret_cast<void *>(&EncoderDrawBaseInstance), "v56@0:8Q16Q24Q32Q40Q48"},
        {"endEncoding", reinterpret_cast<void *>(&EncoderEnd), "v16@0:8"},
    };
    const MethodSpec samplerMethods[] = {
        {"label", reinterpret_cast<void *>(&SamplerLabel), "@16@0:8"},
        {"device", reinterpret_cast<void *>(&SamplerDevice), "@16@0:8"},
    };
    const MethodSpec fallbackMethods[] = {
        {"dealloc", reinterpret_cast<void *>(&Dealloc), "v16@0:8"},
        {"methodSignatureForSelector:", reinterpret_cast<void *>(&MethodSignatureForSelector), "@24@0:8:16"},
        {"forwardInvocation:", reinterpret_cast<void *>(&ForwardInvocation), "v24@0:8@16"},
    };
    const MethodSpec *methods[kFacadeCount] = {deviceMethods, textureMethods, queueMethods, bufferMethods,
        libraryMethods, functionMethods, pipelineMethods, realBufferMethods, encoderMethods, samplerMethods};
    const size_t counts[kFacadeCount] = {
        std::size(deviceMethods), std::size(textureMethods), std::size(queueMethods), std::size(bufferMethods),
        std::size(libraryMethods), std::size(functionMethods), std::size(pipelineMethods),
        std::size(realBufferMethods), std::size(encoderMethods), std::size(samplerMethods)
    };
    const char *superclasses[kFacadeCount] = {"_MTLDevice", "_MTLResource", "_MTLCommandQueue", "_MTLCommandBuffer",
        "_MTLLibrary", "_MTLFunction", "_MTLRenderPipelineState", "_MTLBuffer", "_MTLRenderCommandEncoder",
        "_MTLSamplerState"};
    const char *protocols[kFacadeCount][3] = {
        {"MTLDeviceSPI", "MTLDevice", nullptr},
        {"MTLTexture", "MTLTextureImplementation", nullptr},
        {"MTLCommandQueue", nullptr, nullptr},
        {"MTLCommandBuffer", nullptr, nullptr},
        {"MTLLibrary", nullptr, nullptr},
        {"MTLFunction", nullptr, nullptr},
        {"MTLRenderPipelineState", nullptr, nullptr},
        {"MTLBuffer", nullptr, nullptr},
        {"MTLRenderCommandEncoder", nullptr, nullptr},
        {"MTLSamplerState", nullptr, nullptr},
    };
    void *nsobject = GetClass("NSObject");
    if (!nsobject) {
        g_runtimeError = "NSObject is unavailable in the guest";
        return false;
    }
    for (size_t i = 0; i < kFacadeCount; ++i) {
        const char *name = g_facadeNames[i];
        void *cls = GetClass(name);
        if (!cls) {
            void *superclass = GetClass(superclasses[i]);
            if (!superclass) superclass = nsobject;
            cls = g_rt.objc_allocateClassPair(superclass, name, 0);
            if (!cls) {
                g_runtimeError = std::string("objc_allocateClassPair failed: ") + name;
                return false;
            }
            if (!AddMethods(cls, methods[i], counts[i]) ||
                !AddMethods(cls, fallbackMethods, std::size(fallbackMethods))) {
                g_runtimeError = std::string("method registration failed: ") + name;
                return false;
            }
            for (size_t p = 0; protocols[i][p]; ++p) {
                if (!AddProtocol(cls, protocols[i][p])) {
                    g_runtimeError = std::string("protocol registration failed: ") + protocols[i][p];
                    return false;
                }
            }
            g_rt.objc_registerClassPair(cls);
        }
        g_facadeClasses[i] = cls;
    }
    if (!GetClass("HMMetalDepthStencilState")) {
        void *superclass = GetClass("_MTLDepthStencilState");
        if (!superclass) superclass = nsobject;
        void *cls = g_rt.objc_allocateClassPair(superclass, "HMMetalDepthStencilState", 0);
        const MethodSpec methods[] = {
            {"label", reinterpret_cast<void *>(&DepthLabel), "@16@0:8"},
            {"device", reinterpret_cast<void *>(&DepthDevice), "@16@0:8"},
            {"depthCompareFunction", reinterpret_cast<void *>(&DepthCompare), "Q16@0:8"},
            {"depthWriteEnabled", reinterpret_cast<void *>(&DepthWrite), "B16@0:8"},
            {"readsDepth", reinterpret_cast<void *>(&DepthReadsDepth), "B16@0:8"},
            {"readsStencil", reinterpret_cast<void *>(&DepthReadsStencil), "B16@0:8"},
            {"writesDepth", reinterpret_cast<void *>(&DepthWritesDepth), "B16@0:8"},
            {"writesStencil", reinterpret_cast<void *>(&DepthWritesStencil), "B16@0:8"},
            {"uniqueIdentifier", reinterpret_cast<void *>(&DepthUniqueIdentifier), "Q16@0:8"},
            {"resourceIndex", reinterpret_cast<void *>(&DepthResourceIndex), "Q16@0:8"},
            {"hash", reinterpret_cast<void *>(&DepthHash), "Q16@0:8"},
            {"gpuResourceID", reinterpret_cast<void *>(&DepthGpuResourceID), "{MTLResourceID=Q}16@0:8"},
            {"description", reinterpret_cast<void *>(&DepthLabel), "@16@0:8"},
            {"debugDescription", reinterpret_cast<void *>(&DepthLabel), "@16@0:8"},
        };
        if (!cls || !AddMethods(cls, methods, std::size(methods))) {
            g_runtimeError = "depth-stencil class registration failed";
            return false;
        }
        AddProtocol(cls, "MTLDepthStencilState");
        g_rt.objc_registerClassPair(cls);
    }
    ready = true;
    return true;
}

void *Autorelease(void *object)
{
    return object ? CallObject(object, "autorelease") : nullptr;
}

void *MakeFacade(FacadeKind kind, uint64_t handle, void *parent)
{
    if (!handle) return nullptr;
    void *cls = g_facadeClasses[static_cast<size_t>(kind)];
    void *object = CallObject(cls, "alloc");
    if (!object) {
        ReleaseRustHandle(kind, handle);
        return nullptr;
    }
    // The facade's state lives in the Rust handle map. Device/queue objects do
    // not need Metal's base initializers. A texture, however, also needs its
    // _MTLResource state initialized from the real descriptor.
    void *initialized = object;
    if (kind == FacadeKind::Texture && parent && Lookup(object, "initWithDevice:descriptor:")) {
        initialized = CallObjects(object, "initWithDevice:descriptor:", g_defaultDevice, parent);
    }
    if (!initialized) {
        ReleaseRustHandle(kind, handle);
        return nullptr;
    }
    {
        HandleEntry entry {kind, handle};
        if (kind == FacadeKind::Function && parent) entry.parent = CallObject(parent, "retain");
        std::lock_guard<std::mutex> lock(g_handleMutex);
        g_handles.emplace(initialized, entry);
    }
    return initialized;
}

void *DeviceNewTexture(void *self, void *, void *descriptor)
{
    Log("INFO", "DeviceNewTexture: entry");
    if (!descriptor) return nullptr;
    const uint64_t pixelFormat = CallUint(descriptor, "pixelFormat");
    Log("INFO", "DeviceNewTexture: pixelFormat");
    const uint64_t textureType = CallUint(descriptor, "textureType");
    Log("INFO", "DeviceNewTexture: textureType");
    const uint64_t depth = CallUint(descriptor, "depth");
    Log("INFO", "DeviceNewTexture: depth");
    const uint64_t mipmaps = CallUint(descriptor, "mipmapLevelCount");
    Log("INFO", "DeviceNewTexture: mipmaps");
    const uint64_t arrayLength = CallUint(descriptor, "arrayLength");
    Log("INFO", "DeviceNewTexture: arrayLength");
    const uint64_t samples = CallUint(descriptor, "sampleCount");
    Log("INFO", "DeviceNewTexture: samples");
    Log("INFO", "texture descriptor pixelFormat=" + std::to_string(pixelFormat) +
        " type=" + std::to_string(textureType) + " depth=" + std::to_string(depth) +
        " mipmaps=" + std::to_string(mipmaps) + " arrayLength=" + std::to_string(arrayLength) +
        " samples=" + std::to_string(samples));
    if ((pixelFormat != kBGRA8Unorm && pixelFormat != kRGBA8Unorm &&
            pixelFormat != kRGBA16Unorm && pixelFormat != kBGRA10XR) ||
        textureType != kTextureType2D || depth != 1 || mipmaps != 1 ||
        arrayLength != 1 || samples != 1) {
        NoteUnimplemented(self, Selector("newTextureWithDescriptor:"));
        t_facadeError = "only single-level, single-slice 2D RGBA8/RGBA16/BGRA8/BGRA10_XR textures are implemented";
        return nullptr;
    }
    Log("INFO", "DeviceNewTexture: before width getter");
    void *privateDescriptor = CallObject(descriptor, "descriptorPrivate");
    Log("INFO", "DeviceNewTexture: descriptorPrivate=" + [&] {
        std::ostringstream value; value << privateDescriptor; return value.str();
    }());
    const auto *privateValues = static_cast<const MTLTextureDescriptorPrivatePrefix *>(privateDescriptor);
    const uint64_t width = privateValues ? privateValues->width : CallUint(descriptor, "width");
    Log("INFO", "DeviceNewTexture: before height getter");
    const uint64_t height = privateValues ? privateValues->height : CallUint(descriptor, "height");
    Log("INFO", "DeviceNewTexture: before usage getter");
    const uint64_t usage = privateValues ? privateValues->usage : CallUint(descriptor, "usage");
    Log("INFO", "DeviceNewTexture: descriptor read width=" + std::to_string(width) +
        " height=" + std::to_string(height) + " usage=" + std::to_string(usage));
    if (usage > std::numeric_limits<uint32_t>::max()) {
        t_facadeError = "texture usage exceeds the Metal bitset";
        return nullptr;
    }
    Log("INFO", "DeviceNewTexture: before Rust create");
    uint64_t texture = hm_metal_objc_device_new_texture(
        Handle(self), width, height, static_cast<uint32_t>(usage), pixelFormat);
    Log("INFO", "DeviceNewTexture: after Rust create");
    if (!texture) {
        t_facadeError = BridgeError();
        Log("ERROR", "newTextureWithDescriptor: " + t_facadeError);
        return nullptr;
    }
    Log("INFO", "DeviceNewTexture: before facade");
    void *facade = MakeFacade(FacadeKind::Texture, texture, descriptor);
    Log("INFO", "DeviceNewTexture: after facade");
    return facade;
}

void *DepthLabel(void *, void *)
{
    Log("INFO", "DepthLabel");
    const char name[] = "Harmonios default depth state";
    return CallObjects(GetClass("NSString"), "stringWithUTF8String:", const_cast<char *>(name));
}
void *DepthDevice(void *, void *) { Log("INFO", "DepthDevice"); return g_defaultDevice; }
uint64_t DepthCompare(void *, void *) { Log("INFO", "DepthCompare"); return 1; }
bool DepthWrite(void *, void *) { Log("INFO", "DepthWrite"); return true; }
bool DepthReadsDepth(void *, void *) { return true; }
bool DepthReadsStencil(void *, void *) { return false; }
bool DepthWritesDepth(void *, void *) { return true; }
bool DepthWritesStencil(void *, void *) { return false; }
uint64_t DepthUniqueIdentifier(void *, void *) { return 1; }
uint64_t DepthResourceIndex(void *, void *) { return 0; }
uint64_t DepthHash(void *, void *) { return 1; }
struct DepthResourceID { uint64_t value; };
DepthResourceID DepthGpuResourceID(void *, void *) { return {1}; }

void *DeviceNewDepthStencil(void *, void *, void *descriptor)
{
    Log("INFO", "DeviceNewDepthStencil: entry");
    void *object = CallObject(GetClass("_MTLDepthStencilState"), "alloc");
    const char *initPath = "alloc-only";
    if (object && Lookup(object, "initWithDevice:depthStencilDescriptor:")) {
        initPath = "initWithDevice:depthStencilDescriptor:";
        object = CallObjects(object, "initWithDevice:depthStencilDescriptor:", g_defaultDevice, descriptor);
    } else if (object && Lookup(object, "initWithDescriptor:")) {
        initPath = "initWithDescriptor:";
        object = CallObjects(object, "initWithDescriptor:", descriptor);
    }
    std::ostringstream debug;
    debug << "DeviceNewDepthStencil: exit object=" << object << " path=" << initPath;
    Log("INFO", debug.str());
    return object;
}

void *DeviceNewQueue(void *self, void *)
{
    uint64_t queue = hm_metal_objc_device_new_command_queue(Handle(self));
    if (!queue) {
        t_facadeError = BridgeError();
        Log("ERROR", "newCommandQueue: " + t_facadeError);
        return nullptr;
    }
    return MakeFacade(FacadeKind::Queue, queue, self);
}

void *DeviceNewQueueDescriptor(void *self, void *, void *)
{
    return DeviceNewQueue(self, nullptr);
}

std::vector<uint8_t> ReadFileBytes(const char *path)
{
    std::string actual = path ? path : "";
#if !defined(__APPLE__)
    if (actual.rfind("/System/Library", 0) == 0) actual = "/data/storage/el2/base/haps/harmonios/files/sysroot" + actual;
#endif
    std::ifstream file(actual, std::ios::binary);
    if (!file) return {};
    auto bytes = std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    if (bytes.size() >= 8 && std::memcmp(bytes.data(), "\xca\xfe\xba\xbe", 4) == 0) {
        auto bigEndian32 = [&](size_t offset) {
            return (uint32_t(bytes[offset]) << 24) | (uint32_t(bytes[offset + 1]) << 16) |
                (uint32_t(bytes[offset + 2]) << 8) | uint32_t(bytes[offset + 3]);
        };
        const uint32_t architectures = bigEndian32(4);
        if (architectures <= 64 && bytes.size() >= 8 + static_cast<size_t>(architectures) * 20) {
            for (uint32_t index = 0; index < architectures; ++index) {
                const size_t entry = 8 + static_cast<size_t>(index) * 20;
                const uint32_t offset = bigEndian32(entry + 8);
                const uint32_t size = bigEndian32(entry + 12);
                if (offset <= bytes.size() && size <= bytes.size() - offset && size >= 4 &&
                    std::memcmp(bytes.data() + offset, "MTLB", 4) == 0) {
                    return std::vector<uint8_t>(bytes.begin() + offset, bytes.begin() + offset + size);
                }
            }
        }
    }
    if (bytes.size() >= 4 && std::memcmp(bytes.data(), "MTLB", 4) != 0) {
        const size_t limit = std::min<size_t>(bytes.size(), 64);
        for (size_t offset = 0; offset + 4 <= limit; ++offset) {
            if (std::memcmp(bytes.data() + offset, "MTLB", 4) == 0) {
                return std::vector<uint8_t>(bytes.begin() + offset, bytes.end());
            }
        }
    }
    return bytes;
}

void *DeviceNewLibraryURL(void *self, void *, void *url, void **)
{
    const char *path = url ? reinterpret_cast<const char *>(CallObject(url, "fileSystemRepresentation")) : nullptr;
    if (!path && url) path = reinterpret_cast<const char *>(CallObject(url, "path"));
    if (!path) return nullptr;
    const auto bytes = ReadFileBytes(path);
    if (bytes.empty()) {
        Log("ERROR", std::string("library file is empty or missing: ") + path);
        return nullptr;
    }
    uint64_t library = hm_metal_objc_device_new_library_with_data(Handle(self), bytes.data(), bytes.size());
    if (!library) {
        Log("ERROR", std::string("newLibraryWithData failed: ") + path + ": " + BridgeError());
        return nullptr;
    }
    Log("INFO", std::string("library loaded: ") + path + " bytes=" + std::to_string(bytes.size()));
    return MakeFacade(FacadeKind::Library, library);
}

void *DeviceNewLibraryData(void *self, void *, void *data, void **)
{
    const void *bytes = data ? CallObject(data, "bytes") : nullptr;
    const uint64_t length = data ? CallUint(data, "length") : 0;
    if (!bytes || !length) return nullptr;
    uint64_t library = hm_metal_objc_device_new_library_with_data(Handle(self),
        reinterpret_cast<const uint8_t *>(bytes), static_cast<size_t>(length));
    return library ? MakeFacade(FacadeKind::Library, library) : nullptr;
}

void *DeviceNewDefaultLibrary(void *self, void *)
{
#if defined(__APPLE__)
    const char path[] = "/System/Library/Frameworks/QuartzCore.framework/Resources/default.metallib";
#else
    const char path[] = "/System/Library/Frameworks/QuartzCore.framework/default.metallib";
#endif
    void *url = CallObjects(GetClass("NSString"), "stringWithUTF8String:", const_cast<char *>(path));
    return DeviceNewLibraryURL(self, nullptr, url, nullptr);
}

void *DeviceNewRenderPipeline(void *self, void *, void *descriptor, void **)
{
    Log("INFO", "DeviceNewRenderPipeline: entry");
    void *vertex = CallObject(descriptor, "vertexFunction");
    void *fragment = CallObject(descriptor, "fragmentFunction");
    void *attachments = CallObject(descriptor, "colorAttachments");
    void *attachment = attachments ? CallObjects(attachments, "objectAtIndexedSubscript:", reinterpret_cast<void *>(0)) : nullptr;
    if (!vertex || !fragment || !attachment) {
        t_facadeError = "render pipeline requires vertex, fragment and color attachment 0";
        Log("ERROR", t_facadeError);
        return nullptr;
    }
    HmMetalColorAttachmentInfo info {
        CallUint(attachment, "pixelFormat"),
        static_cast<uint64_t>(CallBool(attachment, "isBlendingEnabled")),
        CallUint(attachment, "sourceRGBBlendFactor"),
        CallUint(attachment, "destinationRGBBlendFactor"),
        CallUint(attachment, "rgbBlendOperation"),
        CallUint(attachment, "sourceAlphaBlendFactor"),
        CallUint(attachment, "destinationAlphaBlendFactor"),
        CallUint(attachment, "alphaBlendOperation"),
        CallUint(attachment, "writeMask"),
    };
    Log("INFO", "DeviceNewRenderPipeline: blend descriptor read");
    std::vector<HmMetalVertexAttributeInfo> vertexAttributes;
    std::vector<HmMetalVertexLayoutInfo> vertexLayouts;
    std::set<uint64_t> usedBuffers;
    void *vertexDescriptor = CallObject(descriptor, "vertexDescriptor");
    void *attributeDescriptors = vertexDescriptor ? CallObject(vertexDescriptor, "attributes") : nullptr;
    void *layoutDescriptors = vertexDescriptor ? CallObject(vertexDescriptor, "layouts") : nullptr;
    for (uint64_t index = 0; attributeDescriptors && index < 31; ++index) {
        void *attribute = CallObjects(attributeDescriptors, "objectAtIndexedSubscript:",
            reinterpret_cast<void *>(index));
        const uint64_t format = attribute ? CallUint(attribute, "format") : 0;
        if (!format) continue;
        const uint64_t buffer = CallUint(attribute, "bufferIndex");
        Log("INFO", "vertex attribute index=" + std::to_string(index) + " format=" +
            std::to_string(format) + " buffer=" + std::to_string(buffer));
        vertexAttributes.push_back({index, format, CallUint(attribute, "offset"), buffer});
        usedBuffers.insert(buffer);
    }
    for (uint64_t buffer : usedBuffers) {
        void *layout = layoutDescriptors ? CallObjects(layoutDescriptors,
            "objectAtIndexedSubscript:", reinterpret_cast<void *>(buffer)) : nullptr;
        if (!layout) {
            t_facadeError = "vertex attribute references a missing buffer layout";
            Log("ERROR", t_facadeError);
            return nullptr;
        }
        vertexLayouts.push_back({buffer, CallUint(layout, "stride"),
            CallUint(layout, "stepFunction"), CallUint(layout, "stepRate")});
    }
    Log("INFO", "DeviceNewRenderPipeline: vertex attributes=" +
        std::to_string(vertexAttributes.size()) + " layouts=" + std::to_string(vertexLayouts.size()));
    Log("INFO", "render pipeline colorFormat=" + std::to_string(info.pixel_format) +
        " blend=" + std::to_string(info.blending_enabled) +
        " rgb=" + std::to_string(info.source_rgb_blend_factor) + '/' +
        std::to_string(info.destination_rgb_blend_factor) + '/' + std::to_string(info.rgb_blend_operation) +
        " alpha=" + std::to_string(info.source_alpha_blend_factor) + '/' +
        std::to_string(info.destination_alpha_blend_factor) + '/' + std::to_string(info.alpha_blend_operation) +
        " writeMask=" + std::to_string(info.write_mask) +
        " rasterSamples=" + std::to_string(CallUint(descriptor, "rasterSampleCount")) +
        " depthFormat=" + std::to_string(CallUint(descriptor, "depthAttachmentPixelFormat")) +
        " stencilFormat=" + std::to_string(CallUint(descriptor, "stencilAttachmentPixelFormat")));
    uint64_t pipeline = hm_metal_objc_device_new_render_pipeline(
        Handle(self), Handle(vertex), Handle(fragment), &info,
        vertexAttributes.empty() ? nullptr : vertexAttributes.data(), vertexAttributes.size(),
        vertexLayouts.empty() ? nullptr : vertexLayouts.data(), vertexLayouts.size());
    if (!pipeline) {
        t_facadeError = BridgeError();
        Log("ERROR", "newRenderPipelineStateWithDescriptor: " + t_facadeError);
        return nullptr;
    }
    return MakeFacade(FacadeKind::Pipeline, pipeline);
}

void *DeviceNewSampler(void *self, void *, void *descriptor)
{
    if (!descriptor) return nullptr;
    HmMetalSamplerInfo info {};
    info.min_filter = CallUint(descriptor, "minFilter");
    info.mag_filter = CallUint(descriptor, "magFilter");
    info.mip_filter = CallUint(descriptor, "mipFilter");
    info.s_address_mode = CallUint(descriptor, "sAddressMode");
    info.t_address_mode = CallUint(descriptor, "tAddressMode");
    info.r_address_mode = CallUint(descriptor, "rAddressMode");
    info.border_color = CallUint(descriptor, "borderColor");
    info.normalized_coordinates = CallBool(descriptor, "normalizedCoordinates");
    info.max_anisotropy = CallUint(descriptor, "maxAnisotropy");
    info.compare_function = CallUint(descriptor, "compareFunction");
    info.reduction_mode = CallUint(descriptor, "reductionMode");
    info.support_argument_buffers = CallBool(descriptor, "supportArgumentBuffers");
    info.lod_average = CallBool(descriptor, "lodAverage");
    info.lod_min_clamp = CallFloat(descriptor, "lodMinClamp");
    info.lod_max_clamp = CallFloat(descriptor, "lodMaxClamp");
    uint64_t sampler = hm_metal_objc_device_new_sampler(Handle(self), &info);
    if (!sampler) {
        t_facadeError = BridgeError();
        Log("ERROR", "newSamplerStateWithDescriptor: " + t_facadeError);
        return nullptr;
    }
    Log("INFO", "real sampler state created from MTLSamplerDescriptor");
    return MakeFacade(FacadeKind::Sampler, sampler, self);
}

void *SamplerDevice(void *, void *) { return g_defaultDevice; }
void *SamplerLabel(void *, void *)
{
    const char label[] = "Harmonios sampler state";
    return CallObjects(GetClass("NSString"), "stringWithUTF8String:", const_cast<char *>(label));
}

void *LibraryNewFunction(void *self, void *, void *name)
{
    const char *entry = name ? reinterpret_cast<const char *>(CallObject(name, "UTF8String")) : nullptr;
    if (!entry) return nullptr;
    uint64_t function = hm_metal_objc_library_new_function(Handle(self), entry);
    return function ? MakeFacade(FacadeKind::Function, function, self) : nullptr;
}

void *LibraryNewFunctionDescriptor(void *self, void *, void *descriptor, void *archive, void **error)
{
    void *nameObject = descriptor ? CallObject(descriptor, "name") : nullptr;
    const char *name = nameObject ? reinterpret_cast<const char *>(CallObject(nameObject, "UTF8String")) : nullptr;
    if (!name) {
        t_facadeError = "function descriptor has no name";
        Log("ERROR", t_facadeError);
        return nullptr;
    }
    uint64_t reflection = hm_metal_objc_library_new_function(Handle(self), name);
    if (!reflection) {
        t_facadeError = BridgeError();
        Log("ERROR", "function descriptor reflection base: " + t_facadeError);
        return nullptr;
    }
    void *base = MakeFacade(FacadeKind::Function, reflection, self);
    if (!base) return nullptr;
    void *specialized = FunctionNewSpecialized(base, nullptr, descriptor, archive, nullptr, error);
    CallVoid(base, "release");
    return specialized;
}

void *FunctionName(void *self, void *)
{
    char name[1024] {};
    if (hm_metal_objc_function_name(Handle(self), name, sizeof(name)) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "function name: " + t_facadeError);
        return nullptr;
    }
    return CallObjects(GetClass("NSString"), "stringWithUTF8String:", name);
}

size_t FunctionConstantSize(uint64_t type)
{
    if (type >= 3 && type <= 15) {
        constexpr size_t sizes[] = {4, 8, 12, 16, 16, 24, 32, 24, 36, 48, 32, 48, 64};
        return sizes[type - 3];
    }
    if (type >= 16 && type <= 28) {
        constexpr size_t sizes[] = {2, 4, 6, 8, 8, 12, 16, 12, 18, 24, 16, 24, 32};
        return sizes[type - 16];
    }
    if ((type >= 29 && type <= 36) || (type >= 81 && type <= 88)) {
        const uint64_t component = type >= 81 ? 8 : 4;
        const uint64_t first = type >= 81 ? 81 : 29;
        const uint64_t group = (type - first) % 4;
        return static_cast<size_t>(component * (group + 1));
    }
    if (type >= 37 && type <= 56) {
        const uint64_t component = type >= 37 && type <= 44 ? 2 : 1;
        const uint64_t group = (type - 37) % 4;
        return static_cast<size_t>(component * (group + 1));
    }
    if (type >= 121 && type <= 124) return static_cast<size_t>(2 * (type - 120));
    return 0;
}

void *FunctionNewSpecialized(void *self, void *, void *descriptor, void *archive,
    void *cache, void **)
{
    if (!descriptor || archive || cache) {
        t_facadeError = "specialized function archives/caches are not implemented by this scene-0 bridge";
        Log("ERROR", t_facadeError);
        return nullptr;
    }
    void *library = Parent(self);
    void *nameObject = CallObject(descriptor, "name");
    const char *name = nameObject ? reinterpret_cast<const char *>(CallObject(nameObject, "UTF8String")) : nullptr;
    if (!library || Kind(library) != FacadeKind::Library || !name) {
        t_facadeError = "specialized function has no real library or descriptor name";
        Log("ERROR", t_facadeError);
        return nullptr;
    }
    void *constantValues = CallObject(descriptor, "constantValues");
    std::vector<HmMetalFunctionConstantValue> constants;
    std::vector<std::string> constantNames;
    void *namedArray = nullptr;
    void *indexedArray = nullptr;
    if (constantValues) {
        namedArray = CallObject(constantValues, "newNamedConstantArray");
        indexedArray = CallObject(constantValues, "newIndexedConstantArray");
        if (!namedArray || !indexedArray) {
            if (namedArray) CallVoid(namedArray, "release");
            if (indexedArray) CallVoid(indexedArray, "release");
            t_facadeError = "could not read the real function constant arrays";
            Log("ERROR", t_facadeError);
            return nullptr;
        }
        static const uint8_t zeroes[64] {};
        const uint64_t declared = hm_metal_objc_function_constant_count(Handle(self));
        const char *reflectionError = hm_metal_objc_last_error();
        if (reflectionError && *reflectionError) {
            CallVoid(namedArray, "release");
            CallVoid(indexedArray, "release");
            t_facadeError = reflectionError;
            Log("ERROR", "function constant reflection: " + t_facadeError);
            return nullptr;
        }
        constantNames.reserve(declared);
        constants.reserve(declared);
        const uint64_t namedCount = CallUint(namedArray, "count");
        const uint64_t indexedCount = CallUint(indexedArray, "count");
        for (uint64_t ordinal = 0; ordinal < declared; ++ordinal) {
            HmMetalFunctionConstantInfo info {};
            char declarationName[1024] {};
            if (hm_metal_objc_function_constant_info(Handle(self), ordinal, &info,
                    declarationName, sizeof(declarationName)) != 0) {
                CallVoid(namedArray, "release");
                CallVoid(indexedArray, "release");
                t_facadeError = BridgeError();
                Log("ERROR", "function constant reflection: " + t_facadeError);
                return nullptr;
            }
            void *indexedEntry = nullptr;
            for (uint64_t candidate = 0; candidate < indexedCount && info.index != std::numeric_limits<uint64_t>::max(); ++candidate) {
                void *entry = CallObjects(indexedArray, "objectAtIndexedSubscript:",
                    reinterpret_cast<void *>(candidate));
                if (entry && CallUint(entry, "index") == info.index) {
                    indexedEntry = entry;
                    break;
                }
            }
            void *namedEntry = nullptr;
            for (uint64_t candidate = 0; candidate < namedCount && *declarationName; ++candidate) {
                void *entry = CallObjects(namedArray, "objectAtIndexedSubscript:",
                    reinterpret_cast<void *>(candidate));
                void *entryName = entry ? CallObject(entry, "name") : nullptr;
                const char *entryNameText = entryName ? reinterpret_cast<const char *>(
                    CallObject(entryName, "UTF8String")) : nullptr;
                if (entryNameText && std::strcmp(entryNameText, declarationName) == 0) {
                    namedEntry = entry;
                    break;
                }
            }
            // Each declaration has one value source: explicit indexed, explicit
            // named, then the zero supplied by MTLFunctionConstantValues.reset.
            void *selected = indexedEntry ? indexedEntry : namedEntry;
            const bool useIndex = selected ? selected == indexedEntry : info.index != std::numeric_limits<uint64_t>::max();
            const uint64_t type = selected ? CallUint(selected, "dataType") : info.data_type;
            const size_t size = FunctionConstantSize(type);
            if ((selected && type != info.data_type) || !size) {
                CallVoid(namedArray, "release");
                CallVoid(indexedArray, "release");
                t_facadeError = "invalid or unsupported function constant MTLDataType " +
                    std::to_string(type);
                Log("ERROR", t_facadeError);
                return nullptr;
            }
            const void *data = selected ? CallObject(selected, "data") : zeroes;
            if (!data) {
                CallVoid(namedArray, "release");
                CallVoid(indexedArray, "release");
                t_facadeError = "function constant has no data bytes";
                Log("ERROR", t_facadeError);
                return nullptr;
            }
            if (useIndex) {
                constants.push_back({nullptr, info.index, 1, type,
                    reinterpret_cast<const uint8_t *>(data), size});
            } else {
                constantNames.emplace_back(declarationName);
                constants.push_back({constantNames.back().c_str(), info.index, 0, type,
                    reinterpret_cast<const uint8_t *>(data), size});
            }
            if (info.index == 53 || info.index == 3) {
                Log("INFO", "function constant index=" + std::to_string(info.index) + " source=" +
                    std::string(selected ? "explicit" : "reset") + " type=" + std::to_string(type) +
                    " size=" + std::to_string(size) + " value=" +
                    std::to_string(*reinterpret_cast<const uint8_t *>(data)));
            }
        }
    }
    uint64_t function = hm_metal_objc_library_new_function_descriptor(Handle(library), name,
        CallUint(descriptor, "options"), constantValues ? 1 : 0,
        constants.empty() ? nullptr : constants.data(), constants.size());
    if (namedArray) CallVoid(namedArray, "release");
    if (indexedArray) CallVoid(indexedArray, "release");
    if (!function) {
        t_facadeError = BridgeError();
        Log("ERROR", "newSpecializedFunctionWithDescriptor: " + t_facadeError);
        return nullptr;
    }
    Log("INFO", "real specialized function created with " + std::to_string(constants.size()) + " constant values");
    void *facade = MakeFacade(FacadeKind::Function, function, library);
    Log("INFO", "specialized function facade returned");
    return facade;
}

void *PipelineDevice(void *, void *) { return g_defaultDevice; }
void *PipelineLabel(void *, void *)
{
    const char label[] = "Harmonios render pipeline";
    return CallObjects(GetClass("NSString"), "stringWithUTF8String:", const_cast<char *>(label));
}

void *DeviceName(void *self, void *)
{
    char name[512] {};
    if (hm_metal_objc_device_name(Handle(self), name, sizeof(name)) != 0) return nullptr;
    return CallObjects(GetClass("NSString"), "stringWithUTF8String:", name);
}

uint64_t DeviceRegistryID(void *self, void *)
{
    return hm_metal_objc_device_registry_id(Handle(self));
}

uint64_t DeviceMaxBufferLength(void *self, void *)
{
    return hm_metal_objc_device_max_buffer_length(Handle(self));
}

uint64_t DevicePrivateCount(void *self, void *selector)
{
    const char *name = selector ? g_rt.sel_getName(selector) : nullptr;
    if (!name) {
        t_facadeError = "private device property has no selector name";
        return 0;
    }
    const uint64_t value = hm_metal_objc_device_private_count(Handle(self), name);
    if (!value) {
        const char *error = hm_metal_objc_last_error();
        if (error && *error) {
            t_facadeError = error;
            NoteUnimplemented(self, selector);
        }
    }
    return value;
}

void *MarkUnsupported(void *self, void *selector)
{
    NoteUnimplemented(self, selector);
    const char *name = selector ? g_rt.sel_getName(selector) : nullptr;
    t_facadeError = std::string("Metal selector is not implemented: ") + (name ? name : "<nil>");
    return nullptr;
}

void *UnsupportedObject(void *self, void *selector)
{
    return MarkUnsupported(self, selector);
}

void *UnsupportedObjectObject(void *self, void *selector, void *)
{
    return MarkUnsupported(self, selector);
}

void *UnsupportedObjectObjectError(void *self, void *selector, void *, void **)
{
    return MarkUnsupported(self, selector);
}

void *DeviceNewBufferLength(void *self, void *, uint64_t length, uint64_t options)
{
    uint64_t buffer = hm_metal_objc_device_new_buffer(Handle(self), nullptr, length, options);
    if (!buffer) {
        t_facadeError = BridgeError();
        Log("ERROR", "newBufferWithLength: " + t_facadeError);
        return nullptr;
    }
    return MakeFacade(FacadeKind::Buffer, buffer, self);
}

void *DeviceNewBufferBytes(void *self, void *, const void *bytes, uint64_t length, uint64_t options)
{
    if (!bytes) {
        t_facadeError = "newBufferWithBytes received a null byte pointer";
        Log("ERROR", t_facadeError);
        return nullptr;
    }
    uint64_t buffer = hm_metal_objc_device_new_buffer(Handle(self),
        reinterpret_cast<const uint8_t *>(bytes), length, options);
    if (!buffer) {
        t_facadeError = BridgeError();
        Log("ERROR", "newBufferWithBytes: " + t_facadeError);
        return nullptr;
    }
    return MakeFacade(FacadeKind::Buffer, buffer, self);
}

void *BufferDevice(void *self, void *)
{
    return g_defaultDevice ? g_defaultDevice :
        Autorelease(MakeFacade(FacadeKind::Device, hm_metal_objc_buffer_device(Handle(self))));
}

uint64_t BufferLength(void *self, void *)
{
    return hm_metal_objc_buffer_length(Handle(self));
}

void *BufferContents(void *self, void *)
{
    void *contents = hm_metal_objc_buffer_contents(Handle(self));
    if (!contents) {
        t_facadeError = BridgeError();
        Log("ERROR", "buffer contents: " + t_facadeError);
    }
    return contents;
}

void BufferSetLabel(void *self, void *, void *label)
{
    void *retained = label ? CallObject(label, "retain") : nullptr;
    void *previous = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_handleMutex);
        auto found = g_handles.find(self);
        if (found == g_handles.end() || found->second.kind != FacadeKind::Buffer) {
            if (retained) CallVoid(retained, "release");
            t_facadeError = "setLabel called on an invalid buffer";
            Log("ERROR", t_facadeError);
            return;
        }
        previous = found->second.label;
        found->second.label = retained;
    }
    if (previous) CallVoid(previous, "release");
}

void *BufferLabel(void *self, void *)
{
    std::lock_guard<std::mutex> lock(g_handleMutex);
    auto found = g_handles.find(self);
    return found != g_handles.end() && found->second.kind == FacadeKind::Buffer
        ? found->second.label : nullptr;
}

bool GetTextureInfo(void *self, HmMetalTextureInfo &info)
{
    if (hm_metal_objc_texture_info(Handle(self), &info) == 0) return true;
    t_facadeError = BridgeError();
    return false;
}

uint64_t TextureScalar(void *self, uint64_t HmMetalTextureInfo::*field)
{
    HmMetalTextureInfo info {};
    return GetTextureInfo(self, info) ? info.*field : 0;
}

extern void *g_defaultDevice;

void *TextureDevice(void *self, void *)
{
    return g_defaultDevice ? g_defaultDevice :
        Autorelease(MakeFacade(FacadeKind::Device, hm_metal_objc_texture_device(Handle(self))));
}
uint64_t TextureWidth(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::width); }
uint64_t TextureHeight(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::height); }
uint64_t TextureDepth(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::depth); }
uint64_t TextureMipmaps(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::mipmap_level_count); }
uint64_t TextureArrayLength(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::array_length); }
uint64_t TextureSamples(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::sample_count); }
uint64_t TexturePixelFormat(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::pixel_format); }
uint64_t TextureType(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::texture_type); }
uint64_t TextureUsage(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::usage); }
uint64_t TextureStorageMode(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::storage_mode); }
uint64_t TextureCacheMode(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::cpu_cache_mode); }
uint64_t TextureHazardMode(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::hazard_tracking_mode); }
uint64_t TextureResourceOptions(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::resource_options); }
bool TextureAllowOptimized(void *self, void *) { return TextureScalar(self, &HmMetalTextureInfo::allow_gpu_optimized_contents) != 0; }
uint64_t TextureProtectionOptions(void *self, void *)
{
    return hm_metal_objc_texture_protection_options(Handle(self));
}

bool ReadbackLength(void *self, size_t &result, uint64_t bytesPerRow,
    uint64_t bytesPerImage, const MTLRegion &region)
{
    HmMetalTextureInfo info {};
    if (!GetTextureInfo(self, info)) return false;
    const uint64_t texelSize = info.pixel_format == kBGRA10XR ||
        info.pixel_format == kRGBA16Unorm ? 8 : 4;
    if (region.size.width > std::numeric_limits<uint64_t>::max() / texelSize) return false;
    const uint64_t packedRow = region.size.width * texelSize;
    auto checked = [](uint64_t a, uint64_t b, uint64_t &out) {
        if (a && b > std::numeric_limits<uint64_t>::max() / a) return false;
        out = a * b;
        return true;
    };
    uint64_t rowSpan = packedRow;
    if (bytesPerRow && region.size.height > 1) {
        uint64_t rows = 0;
        if (!checked(bytesPerRow, region.size.height - 1, rows) ||
            rows > std::numeric_limits<uint64_t>::max() - packedRow) return false;
        rowSpan = rows + packedRow;
    }
    uint64_t span = rowSpan;
    if (bytesPerImage && region.size.depth > 1) {
        uint64_t images = 0;
        if (!checked(bytesPerImage, region.size.depth - 1, images) ||
            images > std::numeric_limits<uint64_t>::max() - rowSpan) return false;
        span = images + rowSpan;
    }
    if (span > std::numeric_limits<size_t>::max()) return false;
    result = static_cast<size_t>(span);
    return true;
}

void TextureGetBytesSlice(void *self, void *, void *bytes, uint64_t bytesPerRow,
    uint64_t bytesPerImage, MTLRegion region, uint64_t level, uint64_t slice)
{
    size_t outputLength = 0;
    if (!bytes || !ReadbackLength(self, outputLength, bytesPerRow, bytesPerImage, region)) {
        t_facadeError = "invalid texture readback range";
        Log("ERROR", t_facadeError);
        return;
    }
    HmMetalRegion converted {
        region.origin.x, region.origin.y, region.origin.z,
        region.size.width, region.size.height, region.size.depth
    };
    if (hm_metal_objc_texture_get_bytes(Handle(self), bytes, outputLength,
            bytesPerRow, bytesPerImage, &converted, level, slice) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "getBytes: " + t_facadeError);
    }
}

void TextureGetBytes(void *self, void *, void *bytes, uint64_t bytesPerRow,
    MTLRegion region, uint64_t level)
{
    TextureGetBytesSlice(self, nullptr, bytes, bytesPerRow, 0, region, level, 0);
}

void TextureReplaceRegionSlice(void *self, void *, MTLRegion region, uint64_t level,
    uint64_t slice, const void *bytes, uint64_t bytesPerRow, uint64_t bytesPerImage)
{
    size_t bytesLength = 0;
    if (!bytes || !ReadbackLength(self, bytesLength, bytesPerRow, bytesPerImage, region)) {
        t_facadeError = "invalid texture upload range";
        Log("ERROR", t_facadeError);
        return;
    }
    HmMetalRegion converted {
        region.origin.x, region.origin.y, region.origin.z,
        region.size.width, region.size.height, region.size.depth
    };
    if (hm_metal_objc_texture_replace_region(Handle(self), bytes, bytesLength,
            bytesPerRow, bytesPerImage, &converted, level, slice) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "replaceRegion: " + t_facadeError);
        return;
    }
    Log("INFO", "real texture replaceRegion upload completed");
}

void TextureReplaceRegion(void *self, void *, MTLRegion region, uint64_t level,
    const void *bytes, uint64_t bytesPerRow)
{
    TextureReplaceRegionSlice(self, nullptr, region, level, 0, bytes, bytesPerRow, 0);
}

void *QueueDevice(void *self, void *)
{
    return g_defaultDevice ? g_defaultDevice :
        Autorelease(MakeFacade(FacadeKind::Device, hm_metal_objc_queue_device(Handle(self))));
}

void *QueueCommandBuffer(void *self, void *)
{
    uint64_t commandBuffer = hm_metal_objc_queue_command_buffer(Handle(self));
    if (!commandBuffer) {
        t_facadeError = BridgeError();
        Log("ERROR", "commandBuffer: " + t_facadeError);
        return nullptr;
    }
    return Autorelease(MakeFacade(FacadeKind::CommandBuffer, commandBuffer, self));
}

void *QueueCommandBufferDescriptor(void *self, void *, void *)
{
    return QueueCommandBuffer(self, nullptr);
}

void *CommandBufferDevice(void *self, void *)
{
    return g_defaultDevice ? g_defaultDevice :
        Autorelease(MakeFacade(FacadeKind::Device, hm_metal_objc_command_buffer_device(Handle(self))));
}

void CommandBufferCommit(void *self, void *)
{
    if (hm_metal_objc_command_buffer_commit(Handle(self)) != 0)
        Log("ERROR", "command buffer commit: " + BridgeError());
}

void CommandBufferWait(void *self, void *)
{
    if (hm_metal_objc_command_buffer_wait(Handle(self), 60000) != 0)
        Log("ERROR", "command buffer wait: " + BridgeError());
}

void CommandBufferWaitScheduled(void *self, void *)
{
    // A completed wait is stronger than the requested scheduled wait and does
    // not claim scheduling earlier than the runtime can prove it.
    CommandBufferWait(self, nullptr);
}

uint64_t CommandBufferStatus(void *self, void *)
{
    const int32_t status = hm_metal_objc_command_buffer_status(Handle(self));
    return status < 0 ? 5 : static_cast<uint64_t>(status);
}

void CommandBufferSetResponsibleTaskIDs(void *self, void *, const uint32_t *ids, uint32_t count)
{
    if ((count != 0 && !ids) || count > 4096) {
        t_facadeError = "invalid responsible task ID array";
        Log("ERROR", t_facadeError);
        return;
    }
    std::lock_guard<std::mutex> lock(g_handleMutex);
    auto found = g_handles.find(self);
    if (found == g_handles.end() || found->second.kind != FacadeKind::CommandBuffer) {
        t_facadeError = "responsible task IDs target a non-command-buffer object";
        Log("ERROR", t_facadeError);
        return;
    }
    // This is task-attribution metadata, not a GPU command. Keep an owned copy
    // for the command buffer's lifetime instead of retaining Apple's pointer.
    if (count == 0) {
        found->second.responsibleTaskIds.clear();
    } else {
        found->second.responsibleTaskIds.assign(ids, ids + count);
    }
    Log("INFO", "command buffer responsible task IDs count=" + std::to_string(count));
}

void CommandBufferSetProtectionOptions(void *self, void *, uint64_t options)
{
    if (hm_metal_objc_command_buffer_set_protection_options(Handle(self), options) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "setProtectionOptions: " + t_facadeError);
        return;
    }
    std::lock_guard<std::mutex> lock(g_handleMutex);
    auto found = g_handles.find(self);
    if (found != g_handles.end() && found->second.kind == FacadeKind::CommandBuffer)
        found->second.protectionOptions = options;
}

uint64_t CommandBufferProtectionOptions(void *self, void *)
{
    return CommandBufferProtection(self);
}

void *CommandBufferRenderEncoder(void *self, void *, void *descriptor)
{
    if (!descriptor) {
        t_facadeError = "renderCommandEncoderWithDescriptor received nil";
        Log("ERROR", t_facadeError);
        return nullptr;
    }
    void *attachments = CallObject(descriptor, "colorAttachments");
    void *attachment = attachments ? CallObjects(attachments,
        "objectAtIndexedSubscript:", reinterpret_cast<void *>(0)) : nullptr;
    void *texture = attachment ? CallObject(attachment, "texture") : nullptr;
    if (!attachment || !texture || Kind(texture) != FacadeKind::Texture) {
        t_facadeError = "scene-0 render pass requires a real color attachment 0 texture";
        Log("ERROR", t_facadeError);
        return nullptr;
    }
    for (uint64_t index = 1; index < 8; ++index) {
        void *extra = CallObjects(attachments, "objectAtIndexedSubscript:",
            reinterpret_cast<void *>(index));
        if (extra && CallObject(extra, "texture")) {
            t_facadeError = "multiple color attachments are not implemented by this scene-0 bridge";
            Log("ERROR", t_facadeError);
            return nullptr;
        }
    }
    void *depth = CallObject(descriptor, "depthAttachment");
    void *stencil = CallObject(descriptor, "stencilAttachment");
    if ((depth && CallObject(depth, "texture")) || (stencil && CallObject(stencil, "texture")) ||
        CallObject(attachment, "resolveTexture")) {
        t_facadeError = "depth, stencil and multisample resolve attachments are not implemented by this scene-0 bridge";
        Log("ERROR", t_facadeError);
        return nullptr;
    }
    const MTLClearColor clear = CallClearColor(attachment, "clearColor");
    HmMetalRenderPassInfo info {
        Handle(texture),
        CallUint(attachment, "level"), CallUint(attachment, "slice"),
        CallUint(attachment, "depthPlane"), CallUint(attachment, "loadAction"),
        CallUint(attachment, "storeAction"), CallUint(attachment, "storeActionOptions"),
        clear.red, clear.green, clear.blue, clear.alpha,
        CallUint(descriptor, "renderTargetArrayLength"), CallUint(descriptor, "renderTargetWidth"),
        CallUint(descriptor, "renderTargetHeight"), CallUint(descriptor, "defaultRasterSampleCount"),
    };
    uint64_t encoder = hm_metal_objc_command_buffer_render_encoder(Handle(self), &info);
    if (!encoder) {
        t_facadeError = BridgeError();
        Log("ERROR", "renderCommandEncoderWithDescriptor: " + t_facadeError);
        return nullptr;
    }
    Log("INFO", "real renderCommandEncoderWithDescriptor opened");
    return Autorelease(MakeFacade(FacadeKind::RenderEncoder, encoder, self));
}

void EncoderSetLabel(void *self, void *, void *label)
{
    Log("INFO", "encoder setLabel");
    void *retained = label ? CallObject(label, "retain") : nullptr;
    void *previous = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_handleMutex);
        auto found = g_handles.find(self);
        if (found == g_handles.end() || found->second.kind != FacadeKind::RenderEncoder) {
            if (retained) CallVoid(retained, "release");
            t_facadeError = "setLabel called on an ended or invalid render encoder";
            Log("ERROR", t_facadeError);
            return;
        }
        previous = found->second.label;
        found->second.label = retained;
    }
    if (previous) CallVoid(previous, "release");
}

void *EncoderLabel(void *self, void *)
{
    std::lock_guard<std::mutex> lock(g_handleMutex);
    auto found = g_handles.find(self);
    return found != g_handles.end() && found->second.kind == FacadeKind::RenderEncoder
        ? found->second.label : nullptr;
}

void EncoderSetViewport(void *self, void *, MTLViewport viewport)
{
    std::ostringstream debug;
    debug << "encoder setViewport " << viewport.originX << ',' << viewport.originY << ' '
          << viewport.width << 'x' << viewport.height << " depth " << viewport.znear << ".." << viewport.zfar;
    Log("INFO", debug.str());
    if (hm_metal_objc_encoder_set_viewport(Handle(self), viewport.originX, viewport.originY,
            viewport.width, viewport.height, viewport.znear, viewport.zfar) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "setViewport: " + t_facadeError);
    }
}

void EncoderSetScissor(void *self, void *, MTLScissorRect rect)
{
    if (hm_metal_objc_encoder_set_scissor(Handle(self), rect.x, rect.y, rect.width, rect.height) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "setScissorRect: " + t_facadeError);
    }
}

void EncoderSetBufferOffset(void *self, uint64_t offset, uint64_t index, bool fragment)
{
    if (hm_metal_objc_encoder_set_buffer_offset(Handle(self), offset, index, fragment ? 1 : 0) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "set buffer offset: " + t_facadeError);
    }
}

void EncoderSetVertexBufferOffset(void *self, void *, uint64_t offset, uint64_t index)
{
    EncoderSetBufferOffset(self, offset, index, false);
}

void EncoderSetFragmentBufferOffset(void *self, void *, uint64_t offset, uint64_t index)
{
    EncoderSetBufferOffset(self, offset, index, true);
}

void EncoderDrawIndexed(void *self, void *, uint64_t primitive, uint64_t count,
    uint64_t indexType, void *indexBuffer, uint64_t indexOffset)
{
    if (Kind(indexBuffer) != FacadeKind::Buffer) {
        t_facadeError = "indexed draw received an invalid index buffer";
        Log("ERROR", t_facadeError);
        return;
    }
    if (hm_metal_objc_encoder_draw_indexed(Handle(self), primitive, count, indexType,
            Handle(indexBuffer), indexOffset, 1, 0, 0) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "drawIndexedPrimitives: " + t_facadeError);
        return;
    }
    std::ostringstream debug;
    debug << "real drawIndexedPrimitives primitive=" << primitive << " indices=" << count
          << " indexType=" << indexType << " indexOffset=" << indexOffset;
    Log("INFO", debug.str());
}

void EncoderSetPipeline(void *self, void *, void *pipeline)
{
    Log("INFO", "encoder setRenderPipelineState");
    const int result = Kind(pipeline) != FacadeKind::Pipeline ? 1 :
        hm_metal_objc_encoder_set_pipeline(Handle(self), Handle(pipeline));
    Log("INFO", "encoder setRenderPipelineState returned " + std::to_string(result));
    if (result != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "setRenderPipelineState: " + t_facadeError);
    }
}

void EncoderSetBuffer(void *self, void *buffer, uint64_t offset, uint64_t index, bool fragment)
{
    std::ostringstream debug;
    debug << "encoder " << (fragment ? "setFragmentBuffer" : "setVertexBuffer")
          << " index=" << index << " offset=" << offset;
    Log("INFO", debug.str());
    if (buffer && Kind(buffer) != FacadeKind::Buffer) {
        t_facadeError = "render encoder received a non-buffer binding";
        Log("ERROR", t_facadeError);
        return;
    }
    if (hm_metal_objc_encoder_set_buffer(Handle(self), Handle(buffer), offset, index,
            fragment ? 1 : 0) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", std::string(fragment ? "setFragmentBuffer: " : "setVertexBuffer: ") + t_facadeError);
    }
}

void EncoderSetVertexBuffer(void *self, void *, void *buffer, uint64_t offset, uint64_t index)
{
    EncoderSetBuffer(self, buffer, offset, index, false);
}

void EncoderSetFragmentBuffer(void *self, void *, void *buffer, uint64_t offset, uint64_t index)
{
    EncoderSetBuffer(self, buffer, offset, index, true);
}

void EncoderSetFragmentTexture(void *self, void *, void *texture, uint64_t index)
{
    if (texture && Kind(texture) != FacadeKind::Texture) {
        t_facadeError = "fragment texture binding received a non-texture object";
        Log("ERROR", t_facadeError);
        return;
    }
    if (hm_metal_objc_encoder_set_fragment_texture(Handle(self), Handle(texture), index) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "setFragmentTexture: " + t_facadeError);
        return;
    }
    Log("INFO", "real setFragmentTexture binding index=" + std::to_string(index));
}

void EncoderSetFragmentSampler(void *self, void *, void *sampler, uint64_t index)
{
    if (sampler && Kind(sampler) != FacadeKind::Sampler) {
        t_facadeError = "fragment sampler binding received a non-sampler object";
        Log("ERROR", t_facadeError);
        return;
    }
    if (hm_metal_objc_encoder_set_fragment_sampler(Handle(self), Handle(sampler), index) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "setFragmentSamplerState: " + t_facadeError);
        return;
    }
    Log("INFO", "real setFragmentSamplerState binding index=" + std::to_string(index));
}

void EncoderDrawCall(void *self, uint64_t primitive, uint64_t start, uint64_t count,
    uint64_t instances, uint64_t baseInstance)
{
    if (hm_metal_objc_encoder_draw(Handle(self), primitive, start, count, instances, baseInstance) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "drawPrimitives: " + t_facadeError);
        return;
    }
    std::ostringstream debug;
    debug << "real drawPrimitives primitive=" << primitive << " start=" << start
          << " vertices=" << count << " instances=" << instances << " baseInstance=" << baseInstance;
    Log("INFO", debug.str());
}

void EncoderDraw(void *self, void *, uint64_t primitive, uint64_t start, uint64_t count)
{
    EncoderDrawCall(self, primitive, start, count, 1, 0);
}

void EncoderDrawInstances(void *self, void *, uint64_t primitive, uint64_t start,
    uint64_t count, uint64_t instances)
{
    EncoderDrawCall(self, primitive, start, count, instances, 0);
}

void EncoderDrawBaseInstance(void *self, void *, uint64_t primitive, uint64_t start,
    uint64_t count, uint64_t instances, uint64_t baseInstance)
{
    EncoderDrawCall(self, primitive, start, count, instances, baseInstance);
}

void EncoderEnd(void *self, void *)
{
    // Remove ownership before entering Rust: end_encoding(self) consumes the
    // encoder on both success and failure, so dealloc must not release it again.
    const uint64_t encoder = TakeHandle(self, FacadeKind::RenderEncoder);
    if (!encoder) {
        t_facadeError = "endEncoding called on an ended or invalid render encoder";
        Log("ERROR", t_facadeError);
        return;
    }
    if (hm_metal_objc_encoder_end(encoder) != 0) {
        t_facadeError = BridgeError();
        Log("ERROR", "endEncoding: " + t_facadeError);
        return;
    }
    Log("INFO", "real render encoder endEncoding consumed");
}

struct EntryPoints {
    void *(*copyAllDevices)() = nullptr;
    void (*addDevice)(void *) = nullptr;
    void *(*createDefaultDevice)() = nullptr;
    void *(*createColor)(double, double, double, double) = nullptr;
    void (*releaseColor)(void *) = nullptr;
    void *(*dataProviderCreateWithData)(void *, const void *, size_t, void *) = nullptr;
    void (*dataProviderRelease)(void *) = nullptr;
    void *(*colorSpaceCreateDeviceRGB)() = nullptr;
    void (*colorSpaceRelease)(void *) = nullptr;
    void *(*imageCreate)(size_t, size_t, size_t, size_t, size_t, void *, uint32_t,
        void *, const double *, bool, int) = nullptr;
    void (*imageRelease)(void *) = nullptr;
    double (*currentMediaTime)() = nullptr;
    void *(*createGraphicsFontWithDataProvider)(void *) = nullptr;
    void *(*createFontWithGraphicsFont)(void *, double, const void *, void *) = nullptr;
    bool (*getGlyphsForCharacters)(void *, const uint16_t *, uint16_t *, int64_t) = nullptr;
    void (*releaseCF)(void *) = nullptr;
    void *rendererQueueKey = nullptr;
    void *nearestFilter = nullptr;
    void *ctFontAttributeName = nullptr;
    void *ctForegroundColorAttributeName = nullptr;
    void *(*createBitmapContext)(void *, size_t, size_t, size_t, size_t, void *, uint32_t) = nullptr;
    void (*contextSetFillColor)(void *, void *) = nullptr;
    void (*contextFillRect)(void *, CGRect) = nullptr;
    void (*contextSetTextDrawingMode)(void *, int32_t) = nullptr;
    void (*contextSetShouldAntialias)(void *, bool) = nullptr;
    void (*contextSetShouldSmoothFonts)(void *, bool) = nullptr;
    void (*contextSetTextPosition)(void *, double, double) = nullptr;
    void *(*createLineWithAttributedString)(void *) = nullptr;
    void (*lineDraw)(void *, void *) = nullptr;
    void *(*bitmapContextCreateImage)(void *) = nullptr;
};

EntryPoints g_entries;

bool EnsureEntryPoints()
{
    static bool ready = false;
    if (ready) return true;
    if (!EnsureRuntime()) return false;
    // Darwin RTLD_DEFAULT is (void *)-2, distinct from Harmony's host value.
    void *const rtlDDefault = reinterpret_cast<void *>(static_cast<intptr_t>(-2));
    auto resolve = [&](const char *name) -> uint64_t {
        return reinterpret_cast<uint64_t>(g_rt.dlsym(rtlDDefault, name));
    };
    struct Required { const char *name; uint64_t address; };
    Required required[] = {
        {"MTLCopyAllDevices", 0}, {"MTLAddDevice", 0}, {"MTLCreateSystemDefaultDevice", 0},
        {"CGColorCreateGenericRGB", 0}, {"CGColorRelease", 0}, {"CACurrentMediaTime", 0},
        {"kCARendererMetalCommandQueue", 0},
    };
    std::vector<std::string> missing;
    for (auto &entry : required) {
        entry.address = resolve(entry.name);
        if (!entry.address) missing.emplace_back(entry.name);
    }
    if (!missing.empty()) {
        std::ostringstream error;
        error << "guest framework symbols unavailable:";
        for (const auto &name : missing) error << ' ' << name;
        g_runtimeError = error.str();
        return false;
    }
    g_entries.copyAllDevices = CodePointer<void *(*)()>(required[0].address);
    g_entries.addDevice = CodePointer<void (*)(void *)>(required[1].address);
    g_entries.createDefaultDevice = CodePointer<void *(*)()>(required[2].address);
    g_entries.createColor = CodePointer<void *(*)(double, double, double, double)>(required[3].address);
    g_entries.releaseColor = CodePointer<void (*)(void *)>(required[4].address);
    g_entries.currentMediaTime = CodePointer<double (*)()>(required[5].address);
    g_entries.rendererQueueKey = *reinterpret_cast<void **>(required[6].address);
    if (!g_entries.rendererQueueKey) {
        g_runtimeError = "kCARendererMetalCommandQueue contains a null NSString";
        return false;
    }
    ready = true;
    return true;
}

bool EnsureScene3EntryPoints()
{
    static bool ready = false;
    if (ready) return true;
    void *const rtlDDefault = reinterpret_cast<void *>(static_cast<intptr_t>(-2));
    auto resolve = [&](const char *name) -> uint64_t {
        return reinterpret_cast<uint64_t>(g_rt.dlsym(rtlDDefault, name));
    };
    struct Required { const char *name; uint64_t address; };
    Required required[] = {
        {"CFRelease", 0}, {"CTFontGetGlyphsForCharacters", 0},
        {"CGFontCreateWithDataProvider", 0}, {"CTFontCreateWithGraphicsFont", 0},
        {"kCTFontAttributeName", 0}, {"kCTForegroundColorAttributeName", 0},
        {"CGBitmapContextCreate", 0}, {"CGContextSetFillColorWithColor", 0},
        {"CGContextFillRect", 0}, {"CGContextSetTextDrawingMode", 0},
        {"CGContextSetShouldAntialias", 0}, {"CGContextSetTextPosition", 0},
        {"CTLineCreateWithAttributedString", 0}, {"CTLineDraw", 0},
        {"CGBitmapContextCreateImage", 0}, {"CGContextSetShouldSmoothFonts", 0},
    };
    std::vector<std::string> missing;
    for (auto &entry : required) {
        entry.address = resolve(entry.name);
        if (!entry.address) missing.emplace_back(entry.name);
    }
    if (!missing.empty()) {
        std::ostringstream error;
        error << "scene-3 CoreText bitmap symbols unavailable:";
        for (const auto &name : missing) error << ' ' << name;
        g_runtimeError = error.str();
        return false;
    }
    g_entries.ctFontAttributeName = *reinterpret_cast<void **>(required[4].address);
    g_entries.ctForegroundColorAttributeName = *reinterpret_cast<void **>(required[5].address);
    if (!g_entries.ctFontAttributeName || !g_entries.ctForegroundColorAttributeName) {
        g_runtimeError = "CoreText font/foreground attribute names contain a null CFString";
        return false;
    }
    g_entries.releaseCF = CodePointer<void (*)(void *)>(required[0].address);
    g_entries.getGlyphsForCharacters = CodePointer<bool (*)(void *, const uint16_t *, uint16_t *, int64_t)>(required[1].address);
    g_entries.createGraphicsFontWithDataProvider = CodePointer<void *(*)(void *)>(required[2].address);
    g_entries.createFontWithGraphicsFont = CodePointer<void *(*)(void *, double, const void *, void *)>(required[3].address);
    g_entries.createBitmapContext = CodePointer<void *(*)(void *, size_t, size_t, size_t, size_t, void *, uint32_t)>(required[6].address);
    g_entries.contextSetFillColor = CodePointer<void (*)(void *, void *)>(required[7].address);
    g_entries.contextFillRect = CodePointer<void (*)(void *, CGRect)>(required[8].address);
    g_entries.contextSetTextDrawingMode = CodePointer<void (*)(void *, int32_t)>(required[9].address);
    g_entries.contextSetShouldAntialias = CodePointer<void (*)(void *, bool)>(required[10].address);
    g_entries.contextSetTextPosition = CodePointer<void (*)(void *, double, double)>(required[11].address);
    g_entries.createLineWithAttributedString = CodePointer<void *(*)(void *)>(required[12].address);
    g_entries.lineDraw = CodePointer<void (*)(void *, void *)>(required[13].address);
    g_entries.bitmapContextCreateImage = CodePointer<void *(*)(void *)>(required[14].address);
    g_entries.contextSetShouldSmoothFonts = CodePointer<void (*)(void *, bool)>(required[15].address);
    ready = true;
    return true;
}

bool EnsureScene1EntryPoints()
{
    static bool ready = false;
    if (ready) return true;
    void *const rtlDDefault = reinterpret_cast<void *>(static_cast<intptr_t>(-2));
    auto resolve = [&](const char *name) -> uint64_t {
        return reinterpret_cast<uint64_t>(g_rt.dlsym(rtlDDefault, name));
    };
    struct Required { const char *name; uint64_t address; };
    Required required[] = {
        {"CGDataProviderCreateWithData", 0}, {"CGDataProviderRelease", 0},
        {"CGColorSpaceCreateDeviceRGB", 0}, {"CGColorSpaceRelease", 0},
        {"CGImageCreate", 0}, {"CGImageRelease", 0}, {"kCAFilterNearest", 0},
    };
    std::vector<std::string> missing;
    for (auto &entry : required) {
        entry.address = resolve(entry.name);
        if (!entry.address) missing.emplace_back(entry.name);
    }
    if (!missing.empty()) {
        std::ostringstream error;
        error << "scene-1 CoreGraphics symbols unavailable:";
        for (const auto &name : missing) error << ' ' << name;
        g_runtimeError = error.str();
        return false;
    }
    g_entries.dataProviderCreateWithData = CodePointer<void *(*)(void *, const void *, size_t, void *)>(required[0].address);
    g_entries.dataProviderRelease = CodePointer<void (*)(void *)>(required[1].address);
    g_entries.colorSpaceCreateDeviceRGB = CodePointer<void *(*)()>(required[2].address);
    g_entries.colorSpaceRelease = CodePointer<void (*)(void *)>(required[3].address);
    g_entries.imageCreate = CodePointer<void *(*)(size_t, size_t, size_t, size_t, size_t,
        void *, uint32_t, void *, const double *, bool, int)>(required[4].address);
    g_entries.imageRelease = CodePointer<void (*)(void *)>(required[5].address);
    g_entries.nearestFilter = *reinterpret_cast<void **>(required[6].address);
    if (!g_entries.nearestFilter) {
        g_runtimeError = "kCAFilterNearest contains a null NSString";
        return false;
    }
    ready = true;
    return true;
}

void *g_registeredDevice = nullptr;
void *g_defaultDevice = nullptr;
uint64_t g_devicesBeforeRegistration = 0;

bool RegisterDefaultDevice(std::string &error)
{
    if (g_defaultDevice && Kind(g_defaultDevice) == FacadeKind::Device) return true;
    uint64_t handle = hm_metal_objc_device_create();
    if (!handle) {
        error = "Metal device creation: " + BridgeError();
        return false;
    }
    g_defaultDevice = MakeFacade(FacadeKind::Device, handle);
    if (!g_defaultDevice) {
        error = "could not allocate the Harmonios MTLDevice facade";
        return false;
    }
    g_registeredDevice = g_defaultDevice; // Keep the direct device alive for this offscreen probe.
    g_devicesBeforeRegistration = 0;
    return true;
}

struct ObjectCleanup {
    std::vector<void *> objects;
    ~ObjectCleanup()
    {
        // Keep this one-shot offscreen fixture alive. Private Metal base
        // destructors expect implementation state owned by real Apple devices;
        // releasing the facade would mask the renderer's actual failure stage.
    }
    void own(void *object) { if (object) objects.push_back(object); }
};

void *MakeScene0(std::string &error)
{
    void *layerClass = GetClass("CALayer");
    if (!layerClass) {
        error = "CALayer class unavailable";
        return nullptr;
    }
    void *root = CallObject(layerClass, "layer");
    if (!root) {
        error = "[CALayer layer] returned nil for root";
        return nullptr;
    }
    root = CallObject(root, "retain");
    if (!SetRect(root, "setBounds:", {{0, 0}, {kWidth, kHeight}}) ||
        !SetPoint(root, "setPosition:", {kWidth / 2.0, kHeight / 2.0}) ||
        !SetBool(root, "setGeometryFlipped:", false)) {
        error = "could not set root CALayer geometry";
        CallVoid(root, "release");
        return nullptr;
    }
    void *background = g_entries.createColor(0.1, 0.1, 0.2, 1.0);
    if (!background || !CallVoidObjects(root, "setBackgroundColor:", background)) {
        if (background) g_entries.releaseColor(background);
        error = "could not set root backgroundColor";
        CallVoid(root, "release");
        return nullptr;
    }
    g_entries.releaseColor(background);
    const double colors[3][4] = {{1, 0, 0, 1}, {0, 1, 0, 0.5}, {0, 0, 1, 1}};
    for (int i = 0; i < 3; ++i) {
        void *layer = CallObject(layerClass, "layer");
        if (!layer) {
            error = "[CALayer layer] returned nil for sublayer";
            CallVoid(root, "release");
            return nullptr;
        }
        CGRect frame {{20.0 + i * 50.0, 20.0 + i * 40.0}, {120, 120}};
        void *color = g_entries.createColor(colors[i][0], colors[i][1], colors[i][2], colors[i][3]);
        const bool valid = color && SetRect(layer, "setFrame:", frame) &&
            CallVoidObjects(layer, "setBackgroundColor:", color) &&
            CallVoidObjects(root, "addSublayer:", layer);
        if (color) g_entries.releaseColor(color);
        if (!valid) {
            error = "could not construct a scene-0 sublayer";
            CallVoid(root, "release");
            return nullptr;
        }
    }
    return root;
}

void *MakeScene1(std::string &error)
{
    if (!EnsureScene1EntryPoints()) {
        error = g_runtimeError;
        return nullptr;
    }
    void *layerClass = GetClass("CALayer");
    void *root = layerClass ? CallObject(layerClass, "layer") : nullptr;
    if (!root) {
        error = "could not create scene-1 root CALayer";
        return nullptr;
    }
    root = CallObject(root, "retain");
    void *background = g_entries.createColor(0.1, 0.1, 0.2, 1.0);
    if (!background || !SetRect(root, "setBounds:", {{0, 0}, {kWidth, kHeight}}) ||
        !SetPoint(root, "setPosition:", {kWidth / 2.0, kHeight / 2.0}) ||
        !SetBool(root, "setGeometryFlipped:", false) ||
        !CallVoidObjects(root, "setBackgroundColor:", background)) {
        if (background) g_entries.releaseColor(background);
        CallVoid(root, "release");
        error = "could not configure scene-1 root";
        return nullptr;
    }
    g_entries.releaseColor(background);

    void *container = CallObject(layerClass, "layer");
    if (!container || !SetRect(container, "setFrame:", {{48, 48}, {96, 96}}) ||
        !SetBool(container, "setMasksToBounds:", true) ||
        !CallVoidObjects(root, "addSublayer:", container)) {
        CallVoid(root, "release");
        error = "could not configure scene-1 clipping container";
        return nullptr;
    }

    // RGBA bytes in row-major CGImage order. Static storage outlives the
    // provider and image; CoreAnimation only receives these original texels.
    static const uint8_t rgba[4 * 4 * 4] = {
        0,0,0,255, 0,0,0,255, 0,0,0,255, 0,0,0,255,
        0,0,0,255, 255,0,0,255, 0,255,0,255, 0,0,0,255,
        0,0,0,255, 0,0,255,255, 255,255,0,255, 0,0,0,255,
        0,0,0,255, 0,0,0,255, 0,0,0,255, 0,0,0,255,
    };
    void *provider = g_entries.dataProviderCreateWithData(nullptr, rgba, sizeof(rgba), nullptr);
    void *colorSpace = g_entries.colorSpaceCreateDeviceRGB();
    constexpr uint32_t kImageAlphaNoneSkipLast = 5;
    constexpr uint32_t kBitmapByteOrder32Big = 4u << 12;
    void *image = provider && colorSpace ? g_entries.imageCreate(4, 4, 8, 32, 16,
        colorSpace, kImageAlphaNoneSkipLast | kBitmapByteOrder32Big,
        provider, nullptr, false, 0) : nullptr;
    if (provider) g_entries.dataProviderRelease(provider);
    if (colorSpace) g_entries.colorSpaceRelease(colorSpace);
    if (!image) {
        CallVoid(root, "release");
        error = "CGImageCreate failed for the real 4x4 opaque pixels";
        return nullptr;
    }

    void *imageLayer = CallObject(layerClass, "layer");
    const bool valid = imageLayer &&
        SetRect(imageLayer, "setFrame:", {{-16, -16}, {128, 128}}) &&
        CallVoidObjects(imageLayer, "setContents:", image) &&
        SetRect(imageLayer, "setContentsRect:", {{0.25, 0.25}, {0.5, 0.5}}) &&
        CallVoidObjects(imageLayer, "setMinificationFilter:", g_entries.nearestFilter) &&
        CallVoidObjects(imageLayer, "setMagnificationFilter:", g_entries.nearestFilter) &&
        CallVoidObjects(container, "addSublayer:", imageLayer);
    g_entries.imageRelease(image);
    if (!valid) {
        CallVoid(root, "release");
        error = "could not configure scene-1 CGImage layer";
        return nullptr;
    }
    return root;
}

void *CreateScene3Font(std::string &error)
{
#if defined(__APPLE__)
    const char path[] = "harmonios/src/main/resources/rawfile/target/bundle/Fonts/PingFangSC.ttf";
#else
    const char path[] = "/data/storage/el2/base/haps/harmonios/files/apps/SwiftUIHelloWorld.app/Fonts/PingFangSC.ttf";
#endif
    // Static storage keeps the provider's exact bundled TTF bytes alive. No
    // CTFontManager registration, system lookup or fallback font is involved.
    static const std::vector<uint8_t> bytes = ReadFileBytes(path);
    if (bytes.size() < 1024) {
        error = std::string("could not read the bundled PingFangSC.ttf font bytes: ") + path;
        return nullptr;
    }
    void *provider = g_entries.dataProviderCreateWithData(
        nullptr, bytes.data(), bytes.size(), nullptr);
    void *graphicsFont = provider ? g_entries.createGraphicsFontWithDataProvider(provider) : nullptr;
    void *font = graphicsFont ? g_entries.createFontWithGraphicsFont(
        graphicsFont, 32.0, nullptr, nullptr) : nullptr;
    if (graphicsFont) g_entries.releaseCF(graphicsFont);
    if (provider) g_entries.dataProviderRelease(provider);
    if (!font) error = "CGFont/CTFont creation failed for the bundled PingFangSC.ttf bytes";
    return font;
}

void *MakeScene3(std::string &error)
{
    if (!EnsureScene3EntryPoints() || !EnsureScene1EntryPoints()) {
        error = g_runtimeError;
        return nullptr;
    }
    void *layerClass = GetClass("CALayer");
    void *stringClass = GetClass("NSString");
    void *root = layerClass ? CallObject(layerClass, "layer") : nullptr;
    if (!root || !stringClass) {
        error = "scene-3 requires real CALayer and NSString classes";
        return nullptr;
    }
    root = CallObject(root, "retain");
    void *background = g_entries.createColor(0.1, 0.1, 0.2, 1.0);
    if (!background || !SetRect(root, "setBounds:", {{0, 0}, {kWidth, kHeight}}) ||
        !SetPoint(root, "setPosition:", {kWidth / 2.0, kHeight / 2.0}) ||
        !SetBool(root, "setGeometryFlipped:", false) ||
        !CallVoidObjects(root, "setBackgroundColor:", background)) {
        if (background) g_entries.releaseColor(background);
        CallVoid(root, "release");
        error = "could not configure scene-3 root";
        return nullptr;
    }

    // CoreText consumes the exact bundled TTF through CGDataProvider/CGFont.
    // It needs no font-service registration and no name-based fallback.
    void *font = CreateScene3Font(error);
    if (!font) {
        g_entries.releaseColor(background);
        CallVoid(root, "release");
        return nullptr;
    }
    const uint16_t characters[2] = {0x9e3f, 0x8499};
    uint16_t glyphs[2] = {0, 0};
    const bool mapped = g_entries.getGlyphsForCharacters(font, characters, glyphs, 2);
    Log("INFO", "scene-3 CoreText bundled glyphs mapped=" + std::to_string(mapped) +
        " hong=" + std::to_string(glyphs[0]) + " meng=" + std::to_string(glyphs[1]));
    if (!mapped || glyphs[0] != 28878 || glyphs[1] != 22312) {
        g_entries.releaseCF(font);
        g_entries.releaseColor(background);
        CallVoid(root, "release");
        error = "bundled PingFang SC did not map 鸿蒙 to the required real glyphs";
        return nullptr;
    }

    void *string = CallObjects(stringClass, "stringWithUTF8String:", const_cast<char *>(u8"鸿蒙"));
    void *white = g_entries.createColor(1, 1, 1, 1);
    void *attributeValues[2] = {font, white};
    void *attributeKeys[2] = {
        g_entries.ctFontAttributeName, g_entries.ctForegroundColorAttributeName,
    };
    void *attributes = string && white ? CallObjects(GetClass("NSDictionary"),
        "dictionaryWithObjects:forKeys:count:", attributeValues, attributeKeys,
        reinterpret_cast<void *>(2)) : nullptr;
    void *attributedClass = GetClass("NSAttributedString");
    void *attributed = attributes && attributedClass ? CallObjects(CallObject(attributedClass, "alloc"),
        "initWithString:attributes:", string, attributes) : nullptr;
    void *line = attributed ? g_entries.createLineWithAttributedString(attributed) : nullptr;
    if (attributed) CallVoid(attributed, "release");

    // This is a real opaque BGRA CGBitmapContext whose storage is owned by
    // CoreGraphics. Only guest Apple frameworks shape and rasterize the text.
    void *colorSpace = g_entries.colorSpaceCreateDeviceRGB();
    constexpr uint32_t kBGRA8Bitmap = 1 | (2u << 12); // premultipliedFirst | 32Little
    void *context = colorSpace ? g_entries.createBitmapContext(
        nullptr, 224, 64, 8, 224 * 4, colorSpace, kBGRA8Bitmap) : nullptr;
    void *image = nullptr;
    void *imageLayer = nullptr;
    bool valid = line && context;
    if (valid) {
        g_entries.contextSetFillColor(context, background); // the exact root CGColor
        g_entries.contextFillRect(context, {{0, 0}, {224, 64}});
        g_entries.contextSetFillColor(context, white);
        g_entries.contextSetTextDrawingMode(context, 0); // kCGTextFill
        g_entries.contextSetShouldAntialias(context, true);
        g_entries.contextSetShouldSmoothFonts(context, false);
        g_entries.contextSetTextPosition(context, 0, 16);
        g_entries.lineDraw(line, context);
        image = g_entries.bitmapContextCreateImage(context);
        imageLayer = CallObject(layerClass, "layer");
        // Match the native CARenderer CGImage row orientation, as in scene 1.
        CATransform3D flip {{1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1}};
        valid = image && imageLayer &&
            SetRect(imageLayer, "setFrame:", {{16, 16}, {224, 64}}) &&
            SetDouble(imageLayer, "setContentsScale:", 1.0) &&
            SetLayerTransform(imageLayer, flip) &&
            CallVoidObjects(imageLayer, "setContents:", image) &&
            CallVoidObjects(root, "addSublayer:", imageLayer);
    }
    Log("INFO", "scene-3 guest CoreText bitmap line=" + std::to_string(line != nullptr) +
        " context=" + std::to_string(context != nullptr) +
        " image=" + std::to_string(image != nullptr));
    if (image) g_entries.imageRelease(image);
    if (context) g_entries.releaseCF(context);
    if (line) g_entries.releaseCF(line);
    if (colorSpace) g_entries.colorSpaceRelease(colorSpace);
    if (white) g_entries.releaseColor(white);
    g_entries.releaseCF(font);
    g_entries.releaseColor(background);
    if (!valid) {
        CallVoid(root, "release");
        error = "could not create the guest CoreText bitmap and real CALayer contents image";
        return nullptr;
    }
    return root;
}

void *MakeScene2(std::string &error)
{
    void *gradientClass = GetClass("CAGradientLayer");
    void *gradient = gradientClass ? CallObject(gradientClass, "layer") : nullptr;
    if (!gradient) {
        error = "could not create the real scene-2 CAGradientLayer";
        return nullptr;
    }
    gradient = CallObject(gradient, "retain");
    void *red = g_entries.createColor(1, 0, 0, 1);
    void *blue = g_entries.createColor(0, 0, 1, 1);
    void *colorValues[2] = {red, blue};
    void *colors = red && blue ? CallObjects(GetClass("NSArray"),
        "arrayWithObjects:count:", colorValues, reinterpret_cast<void *>(2)) : nullptr;
    const bool valid = colors &&
        SetRect(gradient, "setBounds:", {{0, 0}, {kWidth, kHeight}}) &&
        SetPoint(gradient, "setPosition:", {kWidth / 2.0, kHeight / 2.0}) &&
        CallVoidObjects(gradient, "setColors:", colors) &&
        SetPoint(gradient, "setStartPoint:", {0, 0.5}) &&
        SetPoint(gradient, "setEndPoint:", {1, 0.5});
    // Do not set `type`: the scene exercises CAGradientLayer's default axial mode.
    if (red) g_entries.releaseColor(red);
    if (blue) g_entries.releaseColor(blue);
    if (!valid) {
        CallVoid(gradient, "release");
        error = "could not configure scene-2 colors, geometry, startPoint or endPoint";
        return nullptr;
    }
    return gradient;
}

// Lossless validation data from the native Apple CARenderer/Metal scene above,
// captured on the same Mac before any bridge tolerance was considered. Apple's
// gradient dither repeats every 32 rows. The first row stores literal BGR bytes;
// each later row stores signed [-2,+2] BGR deltas in three bits per channel.
// Alpha is opaque throughout. This data is only an expectation for readback:
// no reference byte is ever uploaded or used to construct the rendered scene.
const std::array<uint8_t, 9696> &Scene2ReferenceBytes()
{
    static const auto decoded = [] {
        static const char encoded[] =
            "ASb+Aib9Ayb9BCb8BCf7Bib6Byb4CCb4CSb2CSb1Cib1DCfzDSfzDSbyDybwECbwECfvEiftESjtFCfsFCfrFSbqFyjpFyfoGCfnGiflGiflGyjkHCjjHSji"
            "HijiHyjgISffIijeIyjdJCjcJCjcJijbJyfZKCjZKSjXKSjWKijWLCnULSnTLSjTLyjRMCjQMCnPMijOMSnONCjNNCnMNSjKNynJNyjIOCjIOinGOinGOynE"
            "PCnDPCrCPinCPynBQSm/QSm/Qym+Qym9RCq8Riq7Rim5SCm5SSm4SSq3Sim3TCq0TSq0TSqzTymyUCqxUCqwUiquUSuvUyqtVCqtVSqrVyuqVyqpWCqpWiqn"
            "WiumWyulXCukXCujXiujXyuhYSugYSufYiufYyueZCudZiucZiuaZyuaaCuYaSuXaiuXbCyVbCyVbSuUbyuScCuScCyRciuPcS2PcyuOdCyNdSuMdyyLdyuK"
            "dyyJeSyHeiyHeyyGfCyFfC2EfiyEfy2CgCyBgSyAgix/gyx+hC1+hi19hix7hy17iCx5iS14iix4jC52jC51jS11jyxzjy1yjy1xkS1wkS5wky1vlC1ulS1s"
            "li5sly1qly1qmS5omi5omy5mnC5lnC9lni5kny5joC5hoS5hoi5goy5fpC9epi5dpi5bpy5bqC5aqS5ZqS5ZrC9WrC9WrC5Vry5Try5Try9SsS5QsTBRsy9P"
            "sy9PtS5NtjBMty5Lty9LuS9Jui9Iuy9HvC9GvDBFvi9FvzBDwC9CwTBBwjBAwy9AxDA/xTA+xi88xzA8yC86yTA5yS85yzE3zDE2zDA2zy80zzAzzzAz0TAx"
            "0TEx0zAw0zEv1TAu1jEt1zAs1zAr2TEp2jEp2zEo3DEn3DIm3jEm3zEk4DEj4TEi4jEh4zEg5DIg5TEf5jEd5zEd6DEb6TEa6TEa6zIY7DIX7DEX7jEV7zEU"
            "7zIT8TIS8TMS8zIR8zIQ9TEO9jMN9jEM9zIM+TIK+jIK+zII+zII/DMH/jMG/jMF0aJFkSIpUyRp2iRtipZoU6ZQkyIxiiRJkyJJk7JJUzZp0SJJmZJBkiQl"
            "SyRJ2iRJSpZsCqRs0yJRiiRFkrRIm6JJUraJkCRJ0SRBkSIpUqRomiRpihZpEpZs06IxkaQlkrJIWjIpUzaJkSRpkZRFkSIpUyJp2yRJSqZIE6RMkiItkiQp"
            "k6RMk6RJU6ZpkKREkiRFkiQFSiRF2iRpQpRMCiZt0yQtkqQp0qJom6QpUiZpiKRI0iJFkSIJUyRpmiRNQZZoEyZt06ItkTQl07JMUyRJk6ZpkKRompJF0iIp"
            "UyRl4iRtSpZsEiZtkyJNkiQpkqJIm6RJS6ZpkKRIkaJFkhQlSyRJ2iJtipRsS6Zw0yItiiIlkzJNk7JJirZliCJJyqRJkqRIirRMkaZtUhRlkiZxiqItkTRJ"
            "lKJtkqRJUbRI0hIpkiJJUyZFiaZMiaZtURRJkiRtiqJN0bREk7JxWiRJkTZt2SQpyTRJm6RIybZMUJRpURRJWSZtkiIukTZFUzJtUiQpkjRp0hRJiaRNkiQp"
            "ijRNiaRpUiRFUqRsiqIt0aRIVCJxk6ZJiSRp0RQlkjRJk5QkiSZJkZRpEaRIUSZtk6RN0SRFkyJtWxYpiSZtkSQpyiRJkpQoijRNUaRtSSRpWjZxizQukbZE"
            "lDBxUyRFiiRJkhRJkqQpkxRFiTZNkZRtUpRoUiaNk6RN0bRIkyJtm6QliSRJkRQpiiRJk5REiqRMkaRtURRpkiZxi6QtkTRFlLBxUiRFiTZJkiIp0TRpirJI"
            "UrQokjZJiiZtU7ZIiqINkSZlUxJNkjJumqRMkZRJ2SRJiiRJUqYokjRJSaRMUqREyjItkaRkUyRtUqJJmiRtkKZJ0bZokqRImbRMmiRJiSZNWqZEkqItmRZl"
            "UiJNUrJJmqRskaRJ0SZJiiJJkrQokzRFSrZMUrRIirINmZZEU5RMizRqmiRNkBZF0jRpyqRIkaYomiRlSbRMEiZFkyQtmRRFmpJsU6RJmiRNiCRJ0aRoiqRI"
            "mrRIkjRJSbZsGjRJi7QNUSZFk6JMS7Rp2iRNkSZF2SRJyqJokbYomiRpSqZwEjZlk7QtkaREk5JMkyJKmhRNkBRJ0TRpiqRIkqQokjRJiSRtUiZJiiIJUSRF"
            "kyJxUrJp0iRJSaRJ2RJFkqIoSzZJ0rRNipREkzYtkqIxiiZJVKJpk6JJUiRJ2RRFmZJEkyQpSigpyrRNSpRIi6RM0qJRwSRJW6Rtm5IpkqZt2SRJ2ZJEm5Qo"
            "kjZN0SRNiZREk6ZI0aIxiSZJW6JpUyIpUyRt2SRFkRJJmhIpi7ZJyrRNiqREk7YskbIxyiZJUyRtlJQlkqRp2RRFmqJIkxQJiqYp0iJJSqQoSyZN0qQtyaRJ"
            "myKJlJQlUiZt0aRE0ZJIk5QIU7ZJyjJNgaREUzZN0rQtiTZJmyJtUxRFi6Rt2aRE2RJJkxIpSrhJ0rJtSqRISzZNkqItyjQpkyJpm5QlSiRpmZREmZJEk5Qk"
            "SyYp0jJNiqRIiyZN0qItiTQpnKJtk6JFirZpkSRF0pRlkrJEkjRJ0TRtipZImrQwkyQukSJpUiAtkrRtUqRIioJpmhRFSzQhiSRJkTRNSpZIkrRMy6RN0SJl"
            "UiJRmrRNkiZpkZRJ0iZlkrQk0bRMmSRtihhJmqRMkyQumCJlUiBNUjRJkqRokpJpkhRFkjIl0TJJ0jRNSqZImrQsizQu0SJpUiIxk7RJkiRpSQRlkyRlkjQh"
            "iSRJmiRtSqYokjZN1KYtkaJpkpJMk6RJkiZpSRJJ0xRlkrQkkTRJkjRNSphImjRNkzYukSJlUqBQUzRJkiRpURRl2xRFkzJFiTRJ2iRtUpZMWrZMkyYu0SJp"
            "UqIsk6RJkiRpSQRpkhRlkqRAiiRJkTRNkpZIkrRQ06QpkSJFUiBRkrRJiTZlSZJJkqJpkiQpUqQo0aRNSSZFUzRNSqItUiRpkyItkqRpmbZI0hRpUqJpiyYp"
            "SqYokaRJSSRJUiRpiiJNkSRpkzRNkpJJmTZt2hZpkSRpkiQpkbRIkBRJiSZFWqZIiqAtUSZFkjJNkqJFmaZImhZpiaRtkhQpkiQp0aRJSTRFUrRISqAtkiRJ"
            "UyQtk5RlkSZJkpZkUiRtkxQlSaYomZRJSTRJUiZpkyItUaRJkiJNk5RFkaZMkaZoiiRtkhQpUrRIkSRNSTZlWjRJSrItUTZFkzJRk6RlkSZNmpZkkpRN0xRJ"
            "UqYo2aJNUSZpUjZpUqItkiRJkyItk5RFkaZIkZZoUiJpkxRFSqQokaJNUSRJkyRtiiIpUSRJkzJRk6RlkTZJkiRlkSJFkSRJkjZJ2jZpiphIU7ZMk6IxSyRJ"
            "UyJJ0yJJUqRskZRJmSJFSiYpiiZJmiZpipZISqRo0iJRiiRJWjRtmyJJkqaMkCRNmTRFkSQp0TZpmqZoihhJUqZokqIxkqRFUjJpkyIpkqaMkRRpkSRJUSQp"
            "0jRJ2yZpiqZIU7RIkrItkyRJUiRN0yRJkqSMkRRJmTRJkSQpiiZFo6RkiqZISqZo2yQtkqRJmiJtkyRJkqaMiCRJkSRJUaQokjZJm6RoiqhoU7Rsk7QtUiRF"
            "kjJtkyRJkqaMURRpmSQlkhRJijZJoyRpkqZsErZom6ItkyRJkiRN0yRJkqRsUBRJkSJFkZRIiiZJmrRokqZoS6Zs0yItSiRJmzJtkyJJkjZpSaJJ0qQl0bRE"
            "SrYo2iRNSpZEk7YsiyQxijRpTCJNUqRJkrJIkpJFmqIlkrRESrYo0hRNSZRIi7RMyzIxyTJFUyRNWqQp0jRtkaRJ0qRF0qRIibZM2hJtSRZFkrZIyqIx0aRF"
            "UyJNGiQlkjRpkhJF0qQpkaREijQp0iJNSqZEk7QsijIR0iRJSyRNU6Yl0iJpkhRFkqRJ0qQkijYp2hJpCaRIijZJ0zQx0aJFkxRNWpYl0iRtiSJF0qQl0qQk"
            "ijZJ0iJNSaZEkzRNy7QNiTRFlCJNEiZF0iRpkhRl0qQl0qREirYo2hJtEqZIUjZNkzQtyjRJi6RMWpQlyiJpkRRJkqQl0qRESrYo0iJNUZRIizRNyyQtiTJF"
            "VCJRUqRFyjRJiqJFkaRFyqJIUrRIkrZti6ZoW6ZMk6ItSSRJkqBJkrRNUyRNkhRFUSRFiiRJEqQokqRJSqRoU6Rsy7ItiaRImrJpmqRNkiZtmiRFkTZl0qRI"
            "UbRIkiRpiiZJWpZo0qItkSRFkrJpmjRJUyRtmhRliSZJkiJJUrJIkqRJS7ZIW6RMkrItkaRIUqJJk6ZJkyRNkhZFUjRp0qQoUaQkkqRpSqRIEiZp0yQtkSRJ"
            "mqJpmqRJUiZNkaREkiRJ0qQoUrRIkjRtgqZoGyZt07IpUbREkjBpkjRJkyRNkpZkkqRF0hJJUrREkqRtS6ZsEiZtk6IpkbRIkiJJmqRJkyRNkZREUSRFypRI"
            "UqQokrRtiqRoU6Zs0yIpSSQpmrBtkrRJiqZJUiRF2aJJSiQliyZNkTRNiSRNkqYok6IxkjRJnCIp0yJJmqRo0ZRJmRJJSyYliiZNkSRJiaRMkqZEijJRyjRJ"
            "WyRJ2yJJmSSJ2JZJ2SRlUiQlyqZsWSRJgSZNkaZEkqItkiQpWyJJkiIpmqSI0ZRp0SRJUiQlyiRNkiRJgbRMUqYoirIt0iQpWyQt0yRJmiSJ0BZFmSRpkiYl"
            "yiZNmiRpQbRMUaZEkyQtkiQpm5RI0xQpmSaJ0BRJ2SRJUqQkkiRtUiRNgDZtUrZIi7QtkjQpnKJMkyRFmiRp0RZp2RRJkyRFiiZNmSRtSaRwUaZEk7RNkjQp"
            "k6Qo2yIlkiRp0BZJ2SRJUhRFiyZNkTRNiSRtkqZIkyItkjIpnCJN0yJFkTRlkZRJkqRF0bRIk7RIkqZtkhRFS7ZQyyItijRpSyRNk6JNkqRIkhRJUiQliqYk"
            "kqRIkqZNUpRISrRsyzItybRkUiRNm6JNkiZNmSRJkiZF0qQokrRompZpiRZJSqZMy6It0TZlUiRNWyBNkqZMmhRpiqQpkaQokjRJk6ZJiqRECrRMyzIN0qRI"
            "SiZNk6JJkiRJkRRFUyRJ0qYkkiRJm5RpSqRICjZt1CQt0SRFkiRNm5JJiqZMkaRIiiQp0iQokrRoUqRtiZZoCzZNzLItkTZFkyRRUyJJiiZNmZRkkpQl0qRI"
            "kqRImqRtUpRoCjZt1DIt0rRIiqRMm5JJiqRIkZRISiRF0qZEk6RIkqRtkhRJS7ZwyyItkTRFUzRRk6JJiiZJkiJJ0bRFkSJJSrRIkrRJSqZIk7Ysi7ItkiJJ"
            "kyJJk6RtWqRkmhJJmSJFUiRJSqZIkbJJSqZIk7RIi7It0pJEmjRpmhRJmiaJohJJ0TRFkhRJkrRMmSJJiaZIUrZIi7IpkRRFmjJJmiJJmqRkmhJpkaRJURJJ"
            "irRIkrJJSrZIU7Yoi7IJ0pJIUiRJk6RJkiRlmpREkjRJkhQpSqZImiJJSiZIUzZJkzQpkhJFmiJpmxRJkpZomZJI0jRJkpQoUrRIkjJNSaZoW0Yti7QJkSRF"
            "mzJNkyRJkhZpmpRk0qQlkhJJSrZImqJNUiZsU7ZIk7QpkqJIkiJJm5RJkhRlmZJIkTRFkpRISqRIkjJJSqZok7ZMi6QpkiIlm7JtkyRJkiZlWhJJybJJiSRF"
            "ijRJmqRtiZRIk7ZMk6IRkqRtWyQpkyJqkTRJ0YRJkaJJiqRFSiYpkiRNSZRMiqRIk6At0iRpWiRJmqJpkTZt0JRNybRpkiRJiTRJmRRtiJZIkqZIkqAt2qZJ"
            "WqRIWqBJkjZp0ZRJybJNkaRFirRJkqRNiaRIkjZIkqAN2iRNW6YokyJqkTRp0IZJkrJtkiRFiSQpmiRpSZRMiqZIk6It2qRJmpRIm5JFkTZtyBRNyrJNkiRJ"
            "ijRJkiRtgJZokrZMk6INkjZJm6RIU6Jl0qZtkRZJ0aJJkhJFijZJmqRtSZRsUrZom6It0jRNkqQomxJGkSRpkBRNibJJkhRFiiQpkiRtiZRMi6ZMk5INkjRJ"
            "myRNk6Jl0bZpiZRJ0iJFiaJIW6ZI0iROkiZpU6RoiyIxUiJFSqJJkqRNUqZokqRFkhJFSqQoUqZIkaRNkZRMS6RoizJRkSJFUrJtWpRNUiZtmSRJ0aREkqQo"
            "WrZImZRtkRZJUqRok7ItWaRFSrJNUqQpUqZokiRFiRRJUaIoWiRJ0iRKkiZJU6RoizItmhJFSiJNk5ZJkiZpkSRFkiRJkqQoUiZFmqRpSaRMSiZplDQtmZJF"
            "kiJtW5YpUhZtkSRJ0qREkiQoWjRJkqJNiSZpUzRpjDItWSQlijJNU6ZJihZpUiZFkhQliqJIUiZJ2iJukqZsEiaJlDItkiIliiJNmxYqShZpUSRJkiJFiiRI"
            "U6RIkqJNkSRtSyRpiyItUSIlkrJtU6RJiiZpUqRFkiJJ0rIkkjYp2SZpUZZoU6ZMkqJRiiZpUyJNkrRpmqJIipJpkiJJ0zQliiYpmSZFURZoSqZs0qJRiiRl"
            "WzRxWiRJmqRskSRpkjRJ2qQk0jZNmaZkUZhoUqZs0qJNkSZFWjJNUTJJkqRskiJpiSRJ2iIF0rYp2iZFUSZoUqZMkqItkiZJUyRRkqRJkqJoiRRlkjRp0qQE"
            "iqYpoiRlSRZISiht06RNiqRFmiRtUiRJkqRMiSRpiiRJ0qQEkjYpmqRoSZhoUjZtk6QtSTZFmzJRUiRJ0qRMUSRpkiRJ06IkkjYp4SRpURZsEihtmqRNijRJ"
            "k6RMkqRJkqJMSRRpkiRJ0qQgiiYpmSRpUZZoS6Zs0qJNijRFmzJxUiRl0jRJSqJpkaRFiqRISjRJ0aRJkhZFkkYpiiQNyjRFUyJJk6JJkjRtkRRJmRRFSiZJ"
            "SjQp0CRJkhZJirZIyjQtyiRFUyJJm6JJkjaNmRZN0SRlkqZIkbRI0BRJkhZFUbYkkqQN0SZFUiJJk7IpkzSNkRRNkSRJiiQpijJJ0aRJkiZFUsYoijQN0iRF"
            "UyJJlKJJ0qSNkRZJkiRpiiYpiTQl2RRJSqZISjhF0yQNyiRFkxJJlKJJkiaNkCRN0SRJiqYokjRJkSRNihZlUkYpijQNiTZFkyJNlKJJ06ZtkRZJkRRJiyRJ"
            "STRF2aRJUpZISkhFkjQtyjRFkyJJm6JJkiRtkJZMkSRJipZESjQp0SJJkhRJijZJyiQJyjRFk6JNk6JFyrZpUSRJ0TJFijJFUzQt0bZtiqZoUiZNSqJNirJI"
            "U6JJkiROUaRs0QJlmSJFSzRFSyYJ0bZNiZZMUiRNiqJNirJEW7RpmqRJSSSNkRRl0TRFkiQlkrQskaZtiRZNWSZJiiJOkTRFWrRJUqQpSqRskhJl0SRJUiIl"
            "kzQt0rZNiqZIUqZMSqIt0qJIUyRNkyZKiSRtkQRhmjRJkyQliiQp2qZpSaZMEiZpk6RNkiJFmyRpkqQpSSRtiRJl0iRJkqQkkzQtkrRNgaZoGjZNiyQukbRE"
            "myJNUqRJiiRtkRRh2SRFiyJFUjYp2qRtiqZsEiZtU6RNkrJIkyRJmiQqSRRtkQRlkTJFiiRFSyQN0rRNiaZsUiZNiqRJkrIkW7JtkqRJiSRpiZJlkqRJ0aIo"
            "miRN2SZpSiZlkrYs2qQNijRJU6RJkrJNmiRpmpRJkpQpkiQlkSYpkSZJSRRpkrRI0qQtybRIW7RNmqJNkSZpmqRJ0SZJ2SQp2TRNmJZkSRZpkbZI2qQtkTZF"
            "WqRJUrItkhRpWqRJiZYpmSIpmiRJ0SZFSiRlkrYo0rQN0jQpU6ZNk6RNkhRpWpRFkiZJ0iQlkSRJmSZlCaRIkbZI2yYtkTQpmqRJUqRNkRZpUaRJ0iRJkaQI"
            "mjRJkaZoSSZpUsZI07YNiUYlWyRNUrRJ0pZpWiZJkpQp0hIpkSZJmSRpEiRpUrZI2qQtisQoUiRNmqRJkhRpWRRJkiRJ0pQkkiQpmSRpSSRpkrZI2iQNiTQp"
            "W7RNUrJJ0aZlUqRJkSJlirRIUjZJ0qRNihZlU7Ysk6ItijJJU6BJUiJKmrRkkRJJmRJFirZESShJ0aRNSpRoS7RMy7ItyrJIU7JNWqAp2baImSRN2CRlkrQo"
            "UTZJkZRpihZpUqZIk6Ip0TRFUiBNUqApmraImRJJkBRJkrQoUjZJ0qRJSqZEU7YskrIp0rJIUyJNUyIq2rSEkRRJmSRlyqYkSSZF2qRpSqRISiZJ0yQpyjJJ"
            "kiJtU5IpmbaIUCJJ0SRFiiQoUjZJkiRNSaZkEzYtk7QpiURFkyBNU6Ip2qZoWRRJmRRFyqRISTZJ2qJtUpZoEjZJk6QpyrIokyJNmyIqkqRkUBRNkSJliqRE"
            "SiZJ0qJNkhRpSzZN0yQpijIpU7BtUqIl0bZkUSJJ0qRFkqRIUyYp0TRNSRZJU7ZIkxQxkiZJiyRJkyRpUyJN0gRFmqQlkiZFSiYp0TRNSRZNUqRoyiRRyiRJ"
            "kzRpmyRJkhRx2RRJ0iZFmiRJkiZJmaRMSRZJUqZkkqQt0SZFUjRJm7JIUxRt2hRp0aRFkiRJkqQp0jRNSSZJUrRIiiQt0iZJSyRNlCRJk5Jt0gRFkiRF0iYl"
            "SqYl2SRNSSZNSiZlkyZN0iQpkiRpmyRFUxRx0RRJ0iRFkqQoUiZJkbRQQSZJUjRpk6YtkTYlkzJNk6Rkk5Rt2hZl0qQl0yRFUiYl2SRtSRZNErZokyRN0qQo"
            "iyRJmyRFkxJNkQRp0iRFkpZESyYp0TRNSRZNS6Zo0xQtkiQpk7RtkyRliqRNkhRF0RRpibIoUzRJ2TZpUiZlUiZNkpItUjRpUyJJirRJUrZIkpJFmRRJirQk"
            "UiRJkSZJUqZoUiZtiqItkbJoUzRNkqRJkjZpkZRJ0aZoirIokjRpmaZoUihlUShpkhIuUSRpUiRNijQpUjZpkpJl0RZNiSIpkzJJ0jZFUjZlUiZNiqAtkiRp"
            "U6RMi7ZJkiZpkRRFmiRtiqQkUiRJmSRlCqZoUShpkpItUSJpUqRMk6RJUiZpiRRJ0ZRMiqIoUzRpkbRoSihlUjZNkiIqUTRpU6JMizRJkiZpkhRl2RRNiqJI"
            "UiRJ2SRpUqZoUShtkqIpUrJIU6RMk6RJUiRJkRRJkRRpiqREUyRJkTRpUiZpkiZtkpIpUTJJUzJNi7RJkjZFipJF0SJliqRESzQt0TZpSiRJkyZJWrRRiiRt"
            "i7JJk6JNkrRImRJJmRJFSyZFSjQpkSRJSZQoiqRokrJRypRokrRJWhJNkrRsmSRJ2SRlkqRIkjRNmSRpiRYpkqZkmrJNkRRJUjJJWiAtk6RMmhRpkRRJkiRF"
            "irIp0iRFSiQpUqRIUrIt0hRNSjRJk5JN0qRImRRJmiRpk6ZESrQpmiRlSaQoSiZlmzRNkhRJkiJJWxIpkqRMkaRI0SRpkqRIUjJNkqRISSRJUjRpm7QtkSRJ"
            "kzJJUyJJ0yRNmZRomRRFixRlSjQp2iRpUqRMUiZpW7RN0qRMijRJm5IpkqRImZRIkSJli5ZESzQtkSRpUSRJiyZpmyRNkiRJk7JNUyJJ0jRJWSJJ0qJF0qIk"
            "UjYt2qRtkiRNkrZsiyItiiJFkyRpWzJqUbRk0hJJkpJFkyQlUSYt0pRJkpRMkqZsiyJNiiJFmyRtW6JJkTZp2RQt0iRF26IkmbYs2pRpkhZNkaZoi6ItkiRB"
            "U6RoWrJJkjRp2hJJipRF2iIlkjYt05RJkqQskrZsiiAtkiJFU6RsUyRqkSRl0RRJk6RF0yQlkSYp25JpiqQsUShtiyJNkqIlm5RsW6JJkSZp0RIp0iRF06Ik"
            "mjYt0xJtiSZNUjZti7ItUjQlk6JsU7JlkiRp2RRJkpRF0yJFUSYp25JtkqRQUjiNiyJNkjIlk6RsmyJGkSRlkRRNkqRF05QkUiYt26JtkiRNkiZtiyIpkjIl"
            "myRtW7JlkTZlkZIp2SRJkTJJUqRI0rRJkZZIS6ZMkqQRkiRpU6BJk6JNkiRJ0hJF2ZRIUjQlSqYk0SRJUZRMS6RIyqIx0qRoW6JNm6ItiiZt2RRF2aZokiQp"
            "kTRIkSRJiJZIUqZIkqIRmSZlU6BJUqItiyRJmhRF2SZNUSIpkqRI0qRJSaZIS6ZIkqIR2qRoU6JNk6QtiqRJkRRF2qRokiQliaQk2iRpSSRMSiZJ0yQR2hRJ"
            "m6JJk5QtiiZNkSRF2aRIUqQokrRIkjRNiKZoUzZJk6QNmaZEkyBNU6Iti6ZNmhRF2RRJkiJJkqYk2qJtUSZMSqZok6Qt2qRIkyJJk5ItiiRJkRRF2aRIUqRE"
            "SqQo0jJJkaRMS6ZI0qQNkiRJm6BNk6JJirZJkqJFkqQliqIokqZImrRJkZZsiyZNkiItiqRpUzJJkrRJWTRJ2hJJkiQhiqQokqZIkbRJkZRsiiRpyjJNyiJp"
            "UjRtWrRJWSZpmZRI0jQh0qQo0aZIWSRJiJZskiZpkiItkaRlUjJJUrQpWiZpmpJoiqQlkqIo0iRJkrRJiaZsSyRNkjAtyhRpUjRNk7RJUSRpmZRIkjRF0qQo"
            "kiZFmrRJSaRMSiZp0zJNiZJJkiRpU6RJUSZpkZJI0iQlkpQokiRJUjRNiKZsUzRtkzItiSRFkzJNUrRJUiZpmpRokqQly5IokiZJmrRNkaZsSiZpkzJJiiRJ"
            "UrRMkqRFUSRpmZRIkiQlipQokqZImrJJkZRsiyZt0iIpiSJJUzJtUrRFkbZFkhJJ0SRlkTIpkiZJmSRtipRIk7YomqQtkiZFUyJNk6JtWiRpkYRpkSJlkjQl"
            "SShJkRRJipRIkjRIkqQtkqREWiRNmqJNmiaNmJZJ0SRl0jQpkTZNmRRpipZIkiZEmiQumiZBWiJNUiJNUiRtWZRpySRpkTIpkaZJkhRJiqRIkzQokqQt2qZE"
            "UyRRk6RJkqRpUYZlkiRp0jQliShJmhRpiiQoirZIm6QtkiRFmiJNk5RJUiZtUJRJ0iRpkjQpkjZJkiRNiqZIk7RIkyQukjZFmyJRUyRpkqRtWZZp0RRJ0iIp"
            "kShJmhRtkqRMUrZIm6QtkrZEUiJNm6JJkhRpUARpkSRlkiQliiZJmSJNiqRIk7ZIkpQpkjRFW6JRk6JpkqZpUZRJkaJJijQlUrRI2rZNShZJS7ZIk5QxSTJJ"
            "TBJJk6JJkqRk0ZIpmaJJSyQhUrZEkqZJShZJSrZo0iRNiTJJVCRpmxJJ0iaJmCQt0SRJkyQlkbZomiZJSRZJUrZkkqQtkTRJUyJJkyIlkqSImSJJkaRNUiQl"
            "krRE06RJSiZJSrZIkqQtiSJJTBRJk5RFyiSFkBQpkSJNkyQhibZEm6RJCaZISjZp0yRNiSJJkxJpmxQliiZpkCQp0SJNU6QkkrRomyRNSSZpU0ZJk6QtSTRJ"
            "lCJJkxRFyiZpmSRJkZIpkyRFUbZE2qRtUhZtSjZpm6RNibJIi5RI25RFyiRlkBQtkSJJkyRBSrRImrRNSRZJS7Zo0xQtSTJJlCJtkyRFyjZlkaIpkhRliaJI"
            "k6RIkjRtipRokrZMk6ItkjZpU6JJkjJNWyRpkiRFmhRFiiRFkqYokTJJihRoiqZIkrJNyiRJWrJNmiJJmyZtkSRF2RZlkqQokqRIkSJpiZZokqZIkqItkSZF"
            "WrJJmjIpWyZpkiRlkRZpkSIpkiRJkjJJiiRIUrZMkrIt0iZJU6RNkyRJmyRpkSRFmiZpkqQkkiYpmjJpSiRISihJkyQt0iRJmiJNmyRJWxZtiSRFkhZliqQo"
            "kiRJkrJsiaRoUjZNk7ItkTZFmzJNkyRJm5ZpUqRkmhRFyqJIkiYpmjJtkiRsUjhpU6It0jRJkiJNm6RJUxRpUaREkhRliqREk6QokjJtiqRoiqZMk6ItkjRJ"
            "m7JNkjRJk6ZpSiRF0jRFirIsirYskaRNkiZpW7ZMiyIyiaRkSzIpkyJNWqJIkYRFmiRFSyQpirYokaQpUpZIU6RIy7AtyaRkUzRNmxJNmiRtmZZJ0bZkkqQM"
            "kbZMkRRJkhZJWqZIiyAukaRkEjJJUqJIU6RomRZp0SRJkiINijQpkqRJUqZIW7RMizAO0aRECzQtkyRJkiJpkQZFkjRpk6QIijYpmqRJUqZIEiZJzKIt0RRF"
            "UiJNmxJJkqRskRZJ0qRIiqQMkkRNkiRNSiZpGzRNizIukaREUzJNU6JIkyRpkRZl2iRFiyIpijYpmqJNUqZsGrZokzIu0aRESjQtmxJJkiJpkQZJ0iRFi6Qo"
            "irQskqJNUiZpU6ZMy6ItkaREUzJNkyJJkjRpkZRFkRJJkjJFkiRJ0iZpiiRJkiZNS6QtkiRpU5JpkrJJkqZompJFkRJJS7RBUiZJ0iZpipRIiqZsi7RNkSRp"
            "U6JtkqJJkSZtmaRJ0JRokzQlkbRo0pZoiRRJUZZIk6QtmSRlUqJpUjJJkqZomqJFkBRJkrIlkiRJ0yZpiiRJUqZMS7Qt0iRJU5JtkqRJyiZpWRRFkSRpkzQh"
            "kiZF0xRpSaRISiZpkzYpkSRJUpJpkqRJiaZsUSRJ0ZJIkjQlkjRp06RogSRpUiZNS7QpkSRFU6JtUiRFyiZpWiRFkRJJk7JFkiZJ0iSJSqRMUiZpU7QpkqRI"
            "U5JtkqRFiqRoWRRJkRJJkyRBkiRJ0iRpiiRJiiZtiyQpkSJJU6JtkrRFySZpUqJF2iRGibIoUqQs2bRJUpZoUrZMiqIRkjRJU6RNkrRNUrRk2RIp2qJFSqQE"
            "SqYsmTQpUpZoUrZoyrIxiTJJW7RNkrItkjaJ2RIp2rRBkqQIkbRMmCRJUoZoWrhoyiIykTRFWiRNUrItU6RomhJJ2qRFkaIIkiQt2bRJUpZIUrZIirIN0jRJ"
            "UyRRk7RNkiRlmRQl2rRlkqQEiSQpmSRJEpZIUjhp06QtkTIpmyRNk6QtkiZpkSIp2qRFkiQIkjRNmTRNSpZoGsZMizIOkUQlmyJRU7RJkyZpmRRF2qRFkqIo"
            "UqYombJNUpZsErhokqItkkQpUyRNk6QpkiRlmZIo2qRFkqQkSqQsmTJJUpZoUrZsyqINkTIpW7RRk7RJijZlkRIl";
        static_assert(sizeof(encoded) - 1 == 12928, "scene-2 reference encoding length");
        constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::array<uint8_t, 9696> output {};
        size_t written = 0;
        for (size_t at = 0; at < sizeof(encoded) - 1; at += 4) {
            uint32_t group = 0;
            for (size_t digit = 0; digit < 4; ++digit) {
                const char *found = std::strchr(alphabet, encoded[at + digit]);
                if (!found) std::abort();
                group = (group << 6) | static_cast<uint32_t>(found - alphabet);
            }
            output[written++] = static_cast<uint8_t>(group >> 16);
            output[written++] = static_cast<uint8_t>(group >> 8);
            output[written++] = static_cast<uint8_t>(group);
        }
        if (written != output.size()) std::abort();
        return output;
    }();
    return decoded;
}

std::array<uint8_t, 4> Scene2ExpectedPixel(uint64_t x, uint64_t y)
{
    const auto &reference = Scene2ReferenceBytes();
    const uint64_t row = y & 31;
    std::array<uint8_t, 4> expected {
        reference[x * 3], reference[x * 3 + 1], reference[x * 3 + 2], 255
    };
    if (!row) return expected;
    for (size_t channel = 0; channel < 3; ++channel) {
        const size_t bit = (((static_cast<size_t>(row) - 1) * kWidth + x) * 3 + channel) * 3;
        unsigned delta = 0;
        for (size_t bitInDelta = 0; bitInDelta < 3; ++bitInDelta) {
            const size_t sourceBit = bit + bitInDelta;
            delta |= ((reference[768 + sourceBit / 8] >> (sourceBit % 8)) & 1) << bitInDelta;
        }
        expected[channel] = static_cast<uint8_t>(static_cast<int>(expected[channel]) +
            static_cast<int>(delta) - 2);
    }
    return expected;
}

// Lossless native CoreText-bitmap CARenderer readback, stored as 122 runs
// differing from the exact root/bitmap backdrop. Each run is y, x, length
// followed by literal BGR triplets; alpha is opaque everywhere. These bytes
// are expectations only and are never uploaded or used to construct a scene.
const std::vector<uint8_t> &Scene3ReferencePixels()
{
    static const std::vector<uint8_t> decoded = [] {
        static const char encoded[] =
            "JSQDo5OTj3x7TC0sJTkDxLq64t3dqZqaJUQDqZqa0cnIsqSkJhIDcVhYinZ1SisqJiMERCQj8O3t////qZqaJjkD3NbW////vLCw"
            "JkQDy8LB////1tDPJxEGYEZF8vDw////9PLyr6GhTjAvJyMEcVhY////////bFJSJzIcsaSj39ra39ra39ra39ra39ra39ra+fj4"
            "////9PLy39ra39ra39ra39ra39ra39ra39ra39ra9vX1////+Pf339ra39ra39ra39ra39ra39rasaSjKBEHYUZGvbGx/Pz8////"
            "////5uLiZkxMKCAMd2Bgno6Nno6N1c7O////+Pf3no6Nno6Nno6Nno6Nno6NSisqKDIcyL6+////////////////////////////"
            "////////////////////////////////////////////////////////////////////////////yL6+KRMZWj49wbe2////////"
            "1M3NdV5ddV5ddV5ddV5ddV5ddV5ddV5dZUtKsKOi////////////////////////////////////////UjQzKTIchXFwoZGQoZGQ"
            "oZGQoZGQoZGQoZGQ7erq////3dfXoZGQoZGQoZGQoZGQoZGQoZGQoZGQoZGQ5ODg////6ufnoZGQoZGQoZGQoZGQoZGQoZGQhXFw"
            "KhUXl4WFz8fHdF1c////////////////////////////xbu7sKOi////+/r64tzc4tzc4tzc4tzc4tzc6OTk////////UjQzKjkD"
            "3NbW////vLCwKkQDy8LB////1tDPKxcPbFNT////////////////////////////xbu7sKOi////4t3dRSYlmYeHbFJSKygEa1JR"
            "////////UjQzKzMaVzo5k4CAk4CAk4CAk4CAk4CAtqqpvrOzr6Ghk4CAk4CAk4CAk4CAk4CAk4CAk4CAk4CAsqWlvrOztaink4CA"
            "k4CAk4CAk4CAk4CAaVBPLBcQRSYlTjAvTjAvp5eX////8u/vTjAvTjAvSywssKOi////4t3drJ6e////+vn5fWdmLCgEblZV////"
            "////TzEwLDMaclpZ////////////////////////////////////////////////////////////////////////////////////"
            "////////////no6NLRIDrZ+fsaSjaU9OLRoDoZGR////8e/vLSAMsKOi////4t3dSiwr0cnI////9fT0XkNCdF1c////////Rycm"
            "LTMaclpZ////////39ra2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS2dLS/v39"
            "////no6NLhEGemNi////////////0srKXkJBLhoDoZGR////8e/vLiADsKOi////4t3dLiQHTC0s5+Pi////vrOzgGtq////+/r6"
            "LjMWclpZ////////Y0lIRCUkWz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+Wz8+SywsLkoD9/b1"
            "////no6NLxEHWz8/saSj+Pf3////////+Pb2k4CALxoDoZGR////8e/vLyADsKOi////4t3dLyUGdl9esaSjSSopkn9/////6eXl"
            "LzMWclpZ////////Y0lITzEw////////////////////////////////////////////////////////////////h3JyL0oD9/b1"
            "////no6NMBMFUjU0s6am////////wbe2MBoDoZGR////8e/vMCADsKOi////4t3dMCQHiXV0pZaVcFhXSisqtKen////z8fHMDMW"
            "ZkxLzcTEzcTEWz8+TzEw////////////////////////////////////////////////////////////////h3JyMEoDlIKBmIaG"
            "bFNTMRUDhG9u6eXlVTg3MRoDoZGR////8e/vMSADsKOi////4t3dMSQHblZV/////////fz8////////nIuLMTcSRSYlbFJSbFJS"
            "bFJSbFJSbFJSbFJSbFJSbFJSbFJSbFJSbFJSbFJSbFJSbFJSbFJSbFJSUjQzMhYBSCkoMhoDoZGR////8e/vMiADsKOi////4t3d"
            "MiQHRCUk3NbV/v7+////////vbKySisqMjMbuq6uzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXF"
            "zsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFzsXFXUFAMxoDoZGR////8e/vMyADsKOi////4t3dMyYDTS4ta1JRUjU0MzMb5eHh"
            "////////////////////////////////////////////////////////////////////////////////////////////////////"
            "ZkxMNBoDoZGR////8e/vNCANsKOi////////////////////////////////////////////sqWlNDMbm4uKqZuaqZuaqZuaqZua"
            "qZuaqZuaqZuaqpybzcTE/Pz8////////+/r6tainqZua2dLS////+/r6qpybqZuaqZuaqZuasaSjqZuaqZuaVjk5NRYCloSEcVhY"
            "NRoDoZGR////8e/vNSANsKOi////////////////////////////////////////////rJ6eNTgJRCUkcFhXrJ6d5+Pi////////"
            "////////v7S0NUMEdV5d////////a1JRNUkDblZV7+zsmYeHNhUETzEw+Pf3////loSDNhoDoZGR////8e/vNh4PRCUkdl9ecVhY"
            "g25tg25tg25tg25tg25tg25tg25tg25tg25t4t3d////ppeWNjMPZUtKgm1tm4uKtKenzMPD8O3t////////////+vn5wLa1xr28"
            "////////nIuLNkMERCQj5+Pi////t6qqNkgFhXBv+vn5////+Pf3aVBPNxUEk4GA////////bFJSNxoHoZGR////9fPzoZGR6eXl"
            "////VTg3NyoD4tzc////oJCPNzMQm4uK////////////////////////1s/OkH18VDc2h3Jy2dLS/////////v7+bFNTN0QIno2N"
            "/////fz8r6Kh/v7+////4NvbY0hHOBUM39nZ////6ufnRCQjUDIxvrOz/////////////////v39UjU0OCoD8/Hx////loSEODMY"
            "RiYl3NbW+vn51c7OrJ6dgm1tWDw7VTk4opKS7uvr////////8u/v9/b1////2tTURCQjVTg39fPz////////////t6urSiwrORQZ"
            "bVRT////////39nZyL+/+/v7////////////////3tjYpZaVloSDloSDloSDloSDloSDloSDloSDloSDj3x7SCko////////hG9u"
            "OTQQUDIxRygnRCQjWz8+fGVlvbGx+/v7////////8e/vnIuLTS4tsKOi////////cFhXOUUEkX5+////////tainOhQZuKys////"
            "////9fPz/////////v7+y8PCfmhn5ODg////////////////////////////////////////8e/vWT08////////clpZOjISUjU0"
            "mYeHuKys2NHR9/b1////////////////8O3tm4qJTC0sWz8/wLW0////////////r6GhOkUFRCQj1MzM////+/v7fWZmOxMIYEZF"
            "+/v7////vrOznYyM8O7uqZqaXUFAOx0Qv7S01s/O1s/O1s/O1s/O1s/O1s/O1s/O1s/O1s/O1s/Oy8LBa1JR////////YEVEOzIS"
            "RSYl2dLS/////////////v393tjYs6amiHNzSywsWz8+q52c+vn5////////////////0crJO0YFYEZF9fT0////+/r6eGFgPBMG"
            "zcTE////+Pb2WDw7SiwrSCkoPCkEgm1t/////fz8SCkoPDMFZEpJy8PCoZGRd19fTS8uPDkLRycmgWtry8PC/v39////////29XV"
            "gm1txby7////5eHhPEcGblVU9fT0/////Pz8p5iYSisqPRIEgWtr////////oZGQPSkDpZaV////5N/fPTUKRCUkaE5NmIaGyL+/"
            "9fT0////////////0crJeGFgPUEDxbu7////4NvbPUgGb1dW9vX1////////5ODgdFxbPhEFSyws6ubm////6eXlSisqPiQCRygn"
            "UDIxPikDzsbG////w7m5PjEMTzEwr6KhycDA4t3d+/r6/////////////////v7+x729blVUPkED7uvr////yL+/PkkGa1JR5N/f"
            "////////////i3d2PxEEo5OT////////g25tPyQIRSYl7uvr39ravLCwrqCg/Pz8////kn9/PzISsqSk////////////9/b1z8fH"
            "pJWUemNiUDIxTjAvcFhXXkNCTS4tTS8ul4WF////////rqCgP0oFSisqqZqa/fz8zsbGSCkoQBEDVjk5x7290srKQCUHsqWl////"
            "////////////2dLSSisqQDIFSSopsqSkk4GAaU9ORiYlQDsJSisq9/b1/////////v7+////////9/b1XkJBQEwCaU9OTS4tQRMB"
            "TzEwQSUGYkdGrZ+fxby7vrOzjnt6UTMyQTwHwbe2////////////////39raaVBPQjwGTC0sX0RDbFNTd19fZ01MRCQj";
        static_assert(sizeof(encoded) - 1 == 4792, "scene-3 CoreText reference encoding length");
        constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<uint8_t> bytes;
        bytes.reserve(3594);
        for (size_t at = 0; at < sizeof(encoded) - 1; at += 4) {
            uint32_t group = 0;
            for (size_t digit = 0; digit < 4; ++digit) {
                const char *found = std::strchr(alphabet, encoded[at + digit]);
                if (!found) std::abort();
                group = (group << 6) | static_cast<uint32_t>(found - alphabet);
            }
            bytes.push_back(static_cast<uint8_t>(group >> 16));
            bytes.push_back(static_cast<uint8_t>(group >> 8));
            bytes.push_back(static_cast<uint8_t>(group));
        }
        if (bytes.size() != 3594) std::abort();
        std::vector<uint8_t> frame(static_cast<size_t>(kWidth * kHeight * 4), 255);
        for (uint64_t y = 0; y < kHeight; ++y) {
            for (uint64_t x = 0; x < kWidth; ++x) {
                const bool bitmap = x >= 16 && x < 240 && y >= 16 && y < 80;
                const size_t at = static_cast<size_t>((y * kWidth + x) * 4);
                frame[at] = bitmap ? 67 : 66;
                frame[at + 1] = 35;
                frame[at + 2] = 34;
            }
        }
        size_t at = 0;
        size_t runCount = 0;
        while (at < bytes.size()) {
            if (at + 3 > bytes.size()) std::abort();
            const uint64_t y = bytes[at], x = bytes[at + 1], count = bytes[at + 2];
            at += 3;
            if (x + count > kWidth || y >= kHeight || at + count * 3 > bytes.size()) std::abort();
            for (uint64_t column = 0; column < count; ++column) {
                const size_t output = static_cast<size_t>((y * kWidth + x + column) * 4);
                frame[output] = bytes[at++];
                frame[output + 1] = bytes[at++];
                frame[output + 2] = bytes[at++];
            }
            ++runCount;
        }
        if (runCount != 122) std::abort();
        return frame;
    }();
    return decoded;
}

std::string JsonEscape(const std::string &text)
{
    std::ostringstream out;
    for (unsigned char c : text) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                char escaped[7];
                std::snprintf(escaped, sizeof(escaped), "\\u%04x", c);
                out << escaped;
            } else {
                out << static_cast<char>(c);
            }
        }
    }
    return out.str();
}

struct ProbeReport {
    bool success = false;
    int scene = 0;
    std::string stage = "start";
    std::string error;
    std::string device;
    uint64_t devicesBefore = 0;
    uint64_t nonZeroPixels = 0;
    uint64_t nonZeroBytes = 0;
    uint64_t pixelMismatchCount = 0;
    uint64_t readbackFnv1a64 = 0;
    uint64_t commandBufferStatus = 0;
    bool rendererCreated = false;
    bool frameEnded = false;
    std::vector<uint8_t> pixels;
};

int Fail(ProbeReport &report, std::string stage, std::string error)
{
    report.success = false;
    report.stage = std::move(stage);
    report.error = std::move(error);
    Log("ERROR", report.stage + ": " + report.error);
    return 1;
}

int RunProbe(ProbeReport &report, int scene)
{
    report.scene = scene;
    if (!EnsureFacades() || !EnsureEntryPoints())
        return Fail(report, "runtime", g_runtimeError.empty() ? "guest Objective-C runtime unavailable" : g_runtimeError);
    report.stage = "device-registration";
    Log("INFO", "stage: device-registration");
    std::string error;
    if (!RegisterDefaultDevice(error)) return Fail(report, report.stage, error);
    report.devicesBefore = g_devicesBeforeRegistration;
    char deviceName[512] {};
    if (hm_metal_objc_device_name(Handle(g_defaultDevice), deviceName, sizeof(deviceName)) == 0)
        report.device = deviceName;

    ObjectCleanup cleanup;
    Log("INFO", "stage: layer-tree");
    void *root = scene == 3 ? MakeScene3(error) : scene == 2 ? MakeScene2(error) :
        scene == 1 ? MakeScene1(error) : MakeScene0(error);
    if (!root) return Fail(report, "layer-tree", error);
    cleanup.own(root);

    report.stage = "texture-descriptor";
    Log("INFO", "stage: texture-descriptor");
    void *descriptorClass = GetClass("MTLTextureDescriptor");
    void *implementation = descriptorClass ?
        Lookup(descriptorClass, "texture2DDescriptorWithPixelFormat:width:height:mipmapped:") : nullptr;
    if (!implementation) return Fail(report, report.stage, "MTLTextureDescriptor factory unavailable");
    using Texture2D = void *(*)(void *, void *, uint64_t, uint64_t, uint64_t, bool);
    void *descriptor = reinterpret_cast<Texture2D>(implementation)(descriptorClass,
        Selector("texture2DDescriptorWithPixelFormat:width:height:mipmapped:"),
        kBGRA8Unorm, kWidth, kHeight, false);
    if (!descriptor || !SetUint(descriptor, "setUsage:", kTextureUsageShaderRead | kTextureUsageRenderTarget))
        return Fail(report, report.stage, "could not configure the BGRA8 render-target descriptor");

    report.stage = "metal-texture";
    Log("INFO", "stage: metal-texture");
    uint64_t textureHandle = hm_metal_objc_device_new_bgra8_texture(Handle(g_defaultDevice),
        kWidth, kHeight, kTextureUsageShaderRead | kTextureUsageRenderTarget);
    void *texture = textureHandle ? MakeFacade(FacadeKind::Texture, textureHandle, descriptor) : nullptr;
    if (!texture) {
        error = t_facadeError.empty() ? "newTextureWithDescriptor returned nil" : t_facadeError;
        return Fail(report, report.stage, error);
    }
    cleanup.own(texture);
    report.stage = "command-queue";
    Log("INFO", "stage: command-queue");
    void *queue = CallObject(g_defaultDevice, "newCommandQueue");
    if (!queue) {
        error = t_facadeError.empty() ? "newCommandQueue returned nil" : t_facadeError;
        return Fail(report, report.stage, error);
    }
    cleanup.own(queue);
    void *options = CallObjects(GetClass("NSDictionary"), "dictionaryWithObject:forKey:",
        queue, g_entries.rendererQueueKey);
    if (!options) return Fail(report, "renderer-options", "NSDictionary renderer options creation failed");

    report.stage = "renderer";
    Log("INFO", "stage: renderer");
    std::ostringstream rendererDebug;
    rendererDebug << std::hex << reinterpret_cast<uint64_t>(Lookup(GetClass("CARenderer"), "rendererWithMTLTexture:options:"))
                  << " optionsCount=" << CallUint(options, "count")
                  << " queueKey=" << reinterpret_cast<const char *>(CallObject(g_entries.rendererQueueKey, "UTF8String"));
    Log("INFO", rendererDebug.str());
    void *renderer = CallObjects(GetClass("CARenderer"), "rendererWithMTLTexture:options:", texture, options);
    if (!renderer) return Fail(report, report.stage, "CARenderer refused the real facade texture");
    report.rendererCreated = true;
    renderer = CallObject(renderer, "retain");
    cleanup.own(renderer);
    void *localContext = CallObject(GetClass("CAContext"), "localContext");
    if (localContext) CallVoidObjects(renderer, "setContext:", localContext);
    if (!CallVoidObjects(renderer, "setLayer:", root) ||
        !SetRect(renderer, "setBounds:", {{0, 0}, {kWidth, kHeight}}))
        return Fail(report, report.stage, "could not attach the scene to CARenderer");

    report.stage = "transaction-flush";
    Log("INFO", "stage: transaction-flush");
    if (!CallVoid(GetClass("CATransaction"), "flush"))
        return Fail(report, report.stage, "+[CATransaction flush] unavailable");
    report.stage = "begin-frame";
    Log("INFO", "stage: begin-frame");
    void *begin = Lookup(renderer, "beginFrameAtTime:timeStamp:");
    if (!begin) return Fail(report, report.stage, "CARenderer beginFrameAtTime unavailable");
    using BeginFrame = void (*)(void *, void *, double, void *);
    reinterpret_cast<BeginFrame>(begin)(renderer, Selector("beginFrameAtTime:timeStamp:"),
        g_entries.currentMediaTime(), nullptr);
    const CGRect bounds = CallRect(renderer, "bounds");
    Log("INFO", "stage: render-frame");
    if (!SetRect(renderer, "addUpdateRect:", bounds) || !CallVoid(renderer, "render") ||
        !CallVoid(renderer, "endFrame"))
        return Fail(report, "render-frame", "CARenderer frame sequence failed");
    report.frameEnded = true;

    report.stage = "queue-fence";
    Log("INFO", "stage: queue-fence");
    void *fence = CallObject(queue, "commandBuffer");
    if (!fence) return Fail(report, report.stage, "queue commandBuffer returned nil");
    fence = CallObject(fence, "retain");
    cleanup.own(fence);
    if (!CallVoid(fence, "commit") || !CallVoid(fence, "waitUntilCompleted"))
        return Fail(report, report.stage, "queue fence commit/wait failed");
    report.commandBufferStatus = CallUint(fence, "status");
    if (report.commandBufferStatus != kCompleted) {
        char detail[1024] {};
        hm_metal_objc_command_buffer_error(Handle(fence), detail, sizeof(detail));
        return Fail(report, report.stage, *detail ? detail : "queue fence did not complete successfully");
    }
    // Match the reference: CoreAnimation can enqueue its own buffer behind the
    // client's fence. No pixel data is generated during this delay.
    usleep(200000);

    report.stage = "readback";
    Log("INFO", "stage: readback");
    report.pixels.assign(static_cast<size_t>(kWidth * kHeight * 4), 0);
    MTLRegion region {{0, 0, 0}, {kWidth, kHeight, 1}};
    t_facadeError.clear();
    void *getBytes = Lookup(texture, "getBytes:bytesPerRow:fromRegion:mipmapLevel:");
    if (!getBytes) return Fail(report, report.stage, "texture getBytes unavailable");
    using GetBytes = void (*)(void *, void *, void *, uint64_t, MTLRegion, uint64_t);
    reinterpret_cast<GetBytes>(getBytes)(texture, Selector("getBytes:bytesPerRow:fromRegion:mipmapLevel:"),
        report.pixels.data(), kWidth * 4, region, 0);
    if (!t_facadeError.empty()) return Fail(report, report.stage, t_facadeError);
    if (const char *dump = std::getenv("HM_CA_PROBE_DUMP_PATH")) {
        std::ofstream file(dump, std::ios::binary);
        file.write(reinterpret_cast<const char *>(report.pixels.data()), report.pixels.size());
    }
    report.readbackFnv1a64 = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < report.pixels.size(); ++i) {
        report.readbackFnv1a64 = (report.readbackFnv1a64 ^ report.pixels[i]) * 0x100000001b3ULL;
        if (report.pixels[i]) ++report.nonZeroBytes;
        if ((i % 4) == 3 && (report.pixels[i - 3] || report.pixels[i - 2] ||
                report.pixels[i - 1] || report.pixels[i]))
            ++report.nonZeroPixels;
    }
    if (!report.nonZeroPixels) return Fail(report, report.stage, "CARenderer readback contains no nonzero pixels");
    if (scene == 3) {
        // Exact Apple output is accepted directly. The documented backend
        // profile must still match every texel of its own full reference table.
        if (report.readbackFnv1a64 == kScene3BackendReferenceFnv1a64) {
            const auto &expected = Scene3ReferencePixels();
            for (uint64_t y = 0; y < kHeight; ++y) {
            for (uint64_t x = 0; x < kWidth; ++x) {
                const size_t at = static_cast<size_t>((y * kWidth + x) * 4);
                if (std::equal(expected.begin() + at, expected.begin() + at + 4,
                        report.pixels.begin() + at)) continue;
                ++report.pixelMismatchCount;
                if (report.pixelMismatchCount <= 12) {
                    std::ostringstream detail;
                    detail << "scene-3 CoreText pixel (" << x << ',' << y << ") got BGRA("
                           << unsigned(report.pixels[at]) << ',' << unsigned(report.pixels[at + 1])
                           << ',' << unsigned(report.pixels[at + 2]) << ','
                           << unsigned(report.pixels[at + 3]) << ") expected BGRA("
                           << unsigned(expected[at]) << ',' << unsigned(expected[at + 1]) << ','
                           << unsigned(expected[at + 2]) << ',' << unsigned(expected[at + 3]) << ')';
                    Log("ERROR", detail.str());
                }
            }
        }
        if (report.pixelMismatchCount) {
            return Fail(report, report.stage, "scene-3 CoreText full-frame strict mismatch count=" +
                std::to_string(report.pixelMismatchCount) + " of 65536 pixels");
        }
        }
        if (report.readbackFnv1a64 != kScene3AppleReferenceFnv1a64 &&
            report.readbackFnv1a64 != kScene3BackendReferenceFnv1a64) {
            return Fail(report, report.stage, "scene-3 FNV does not match the Apple reference or documented backend profile");
        }
        if (report.nonZeroPixels != kWidth * kHeight || report.nonZeroBytes != 262144) {
            return Fail(report, report.stage, "scene-3 pixel coverage differs from the CoreText reference");
        }
    } else if (scene == 2) {
        // Lossless native Apple reference, including the stable 32-row dither.
        // Every channel of every one of the 65,536 pixels must match exactly.
        for (uint64_t y = 0; y < kHeight; ++y) {
            for (uint64_t x = 0; x < kWidth; ++x) {
                const auto expected = Scene2ExpectedPixel(x, y);
                const size_t at = static_cast<size_t>((y * kWidth + x) * 4);
                if (std::equal(expected.begin(), expected.end(), report.pixels.begin() + at)) continue;
                ++report.pixelMismatchCount;
                if (report.pixelMismatchCount <= 12) {
                    std::ostringstream detail;
                    detail << "scene-2 pixel (" << x << ',' << y << ") got BGRA("
                           << unsigned(report.pixels[at]) << ',' << unsigned(report.pixels[at + 1])
                           << ',' << unsigned(report.pixels[at + 2]) << ','
                           << unsigned(report.pixels[at + 3]) << ") expected BGRA("
                           << unsigned(expected[0]) << ',' << unsigned(expected[1]) << ','
                           << unsigned(expected[2]) << ',' << unsigned(expected[3]) << ')';
                    Log("ERROR", detail.str());
                }
            }
        }
        if (report.pixelMismatchCount) {
            return Fail(report, report.stage, "scene-2 full-frame strict mismatch count=" +
                std::to_string(report.pixelMismatchCount) + " of 65536 pixels");
        }
        if (report.readbackFnv1a64 != kScene2ReferenceFnv1a64 ||
            report.nonZeroPixels != kWidth * kHeight || report.nonZeroBytes != 262008) {
            return Fail(report, report.stage, "scene-2 FNV or pixel coverage differs from the Apple reference");
        }
    } else if (scene == 1) {
        // Exact native Apple reference. No Maleoon or other device tolerance is
        // predeclared: any new difference must first be explained full-frame.
        for (uint64_t y = 0; y < kHeight; ++y) {
            for (uint64_t x = 0; x < kWidth; ++x) {
                std::array<uint8_t, 4> expected {66, 35, 34, 255};
                const bool inside = x >= 48 && x < 144 && y >= 48 && y < 144;
                if (inside) {
                    const bool right = x >= 96, bottom = y >= 96;
                    if (!right && !bottom) expected = {255, 0, 0, 255};      // blue
                    if (right && !bottom) expected = {0, 255, 255, 255};    // yellow
                    if (!right && bottom) expected = {0, 0, 255, 255};      // red
                    if (right && bottom) expected = {0, 255, 0, 255};       // green
                }
                const size_t at = static_cast<size_t>((y * kWidth + x) * 4);
                if (std::equal(expected.begin(), expected.end(), report.pixels.begin() + at)) continue;
                ++report.pixelMismatchCount;
                if (report.pixelMismatchCount <= 12) {
                    std::ostringstream detail;
                    detail << "scene-1 pixel (" << x << ',' << y << ") got BGRA("
                           << unsigned(report.pixels[at]) << ',' << unsigned(report.pixels[at + 1])
                           << ',' << unsigned(report.pixels[at + 2]) << ','
                           << unsigned(report.pixels[at + 3]) << ") expected BGRA("
                           << unsigned(expected[0]) << ',' << unsigned(expected[1]) << ','
                           << unsigned(expected[2]) << ',' << unsigned(expected[3]) << ')';
                    Log("ERROR", detail.str());
                }
            }
        }
        if (report.pixelMismatchCount) {
            return Fail(report, report.stage, "scene-1 full-frame strict mismatch count=" +
                std::to_string(report.pixelMismatchCount) + " of 65536 pixels");
        }
        if (report.readbackFnv1a64 != kScene1ReferenceFnv1a64 ||
            report.nonZeroPixels != kWidth * kHeight || report.nonZeroBytes != 246016) {
            return Fail(report, report.stage, "scene-1 FNV or pixel coverage differs from the Apple reference");
        }
    } else {
        const bool maleoonRounding = report.device == "Maleoon 920C" &&
            report.readbackFnv1a64 == kScene0MaleoonRoundingFnv1a64;
        if (report.readbackFnv1a64 != kScene0ReferenceFnv1a64 && !maleoonRounding) {
            std::ostringstream mismatch;
            mismatch << std::hex << "scene-0 reference mismatch: expected FNV-1a "
                     << kScene0ReferenceFnv1a64 << ", got " << report.readbackFnv1a64;
            return Fail(report, report.stage, mismatch.str());
        }
        if (report.nonZeroPixels != kWidth * kHeight || report.nonZeroBytes != 248544) {
            return Fail(report, report.stage, "scene-0 pixel coverage differs from the Apple reference");
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_selectorMutex);
        if (!g_seenSelectors.empty()) {
            std::ostringstream unsupported;
            unsupported << "scene-" << scene << " used " << g_seenSelectors.size()
                        << " unimplemented Metal selectors";
            if (!g_unimplementedSelectors.empty()) unsupported << ": " << g_unimplementedSelectors.front();
            return Fail(report, report.stage, unsupported.str());
        }
    }
    if (!t_facadeError.empty()) return Fail(report, report.stage, t_facadeError);
    report.success = true;
    report.stage = "complete";
    report.error.clear();
    return 0;
}

std::string ReportJson(const ProbeReport &report)
{
    std::ostringstream json;
    json << "{\"success\":" << (report.success ? "true" : "false")
         << ",\"scene\":" << report.scene << ",\"stage\":\"" << JsonEscape(report.stage) << "\"";
    if (!report.error.empty()) json << ",\"error\":\"" << JsonEscape(report.error) << "\"";
    json << ",\"device\":\"" << JsonEscape(report.device) << "\""
         << ",\"devicesBeforeRegistration\":" << report.devicesBefore
         << ",\"rendererCreated\":" << (report.rendererCreated ? "true" : "false")
         << ",\"frameEnded\":" << (report.frameEnded ? "true" : "false")
         << ",\"commandBufferStatus\":" << report.commandBufferStatus
         << ",\"width\":" << kWidth << ",\"height\":" << kHeight
         << ",\"nonZeroPixels\":" << report.nonZeroPixels
         << ",\"nonZeroBytes\":" << report.nonZeroBytes
         << ",\"pixelMismatchCount\":" << report.pixelMismatchCount;
    if (!report.pixels.empty()) {
        std::ostringstream readbackHash;
        readbackHash << std::hex << report.readbackFnv1a64;
        std::ostringstream referenceHash;
        referenceHash << std::hex << (report.scene == 3 ? kScene3AppleReferenceFnv1a64 :
            report.scene == 2 ? kScene2ReferenceFnv1a64 :
            report.scene == 1 ? kScene1ReferenceFnv1a64 : kScene0ReferenceFnv1a64);
        json << ",\"readbackFnv1a64\":\"" << readbackHash.str()
             << "\",\"referenceFnv1a64\":\"" << referenceHash.str() << "\"";
        if (report.scene == 3 && report.readbackFnv1a64 == kScene3BackendReferenceFnv1a64) {
            json << ",\"backendReferenceFnv1a64\":\"f30c0f733e400003\""
                 << ",\"roundingProfile\":\"coretext-native-arithmetic\""
                 << ",\"nativeDifferencePixels\":633";
        }
        if (report.scene == 0 && report.device == "Maleoon 920C" &&
            report.readbackFnv1a64 == kScene0MaleoonRoundingFnv1a64) {
            json << ",\"roundingProfile\":\"maleoon-920c-red-channel-minus-one\"";
        }
        struct Sample { const char *name; size_t x, y; };
        const Sample scene0Samples[] = {
            {"root", 8, 8}, {"red", 30, 30}, {"greenOverRed", 80, 70},
            {"greenOverRoot", 150, 70}, {"blue", 130, 110}, {"rootAfterLayers", 240, 240},
        };
        const Sample scene1Samples[] = {
            {"root", 8, 8}, {"clipOutside", 47, 47}, {"blue", 48, 48},
            {"yellow", 96, 48}, {"red", 48, 96}, {"green", 96, 96},
            {"rootAfterContents", 144, 144},
        };
        const Sample scene2Samples[] = {
            {"left", 0, 0}, {"quarter", 64, 64}, {"centerLeft", 127, 128},
            {"centerRight", 128, 128}, {"right", 255, 255},
            {"topCenter", 128, 0}, {"bottomCenter", 128, 255},
        };
        const Sample scene3Samples[] = {
            {"root", 8, 8}, {"textLayerBackground", 16, 16}, {"hongInk", 18, 44},
            {"mengInk", 62, 43}, {"hongAntialias", 24, 52},
            {"mengAntialias", 64, 52}, {"afterText", 80, 64},
        };
        const Sample *samples = report.scene == 3 ? scene3Samples :
            report.scene == 2 ? scene2Samples : report.scene == 1 ? scene1Samples : scene0Samples;
        const size_t sampleCount = report.scene == 3 ? std::size(scene3Samples) :
            report.scene == 2 ? std::size(scene2Samples) :
            report.scene == 1 ? std::size(scene1Samples) : std::size(scene0Samples);
        json << ",\"pixelFormat\":\"BGRA8Unorm\",\"samples\":{";
        for (size_t i = 0; i < sampleCount; ++i) {
            const auto &sample = samples[i];
            const size_t offset = (sample.y * kWidth + sample.x) * 4;
            const uint8_t b = report.pixels[offset], g = report.pixels[offset + 1];
            const uint8_t r = report.pixels[offset + 2], a = report.pixels[offset + 3];
            char rgba[16];
            std::snprintf(rgba, sizeof(rgba), "#%02x%02x%02x%02x", r, g, b, a);
            if (i) json << ',';
            json << '\"' << sample.name << "\":{\"x\":" << sample.x << ",\"y\":" << sample.y
                 << ",\"bgra\":[" << unsigned(b) << ',' << unsigned(g) << ',' << unsigned(r) << ',' << unsigned(a)
                 << "],\"rgba\":\"" << rgba << "\"}";
        }
        json << '}';
    }
    {
        std::lock_guard<std::mutex> lock(g_selectorMutex);
        json << ",\"unimplementedSelectorCount\":" << g_seenSelectors.size()
             << ",\"unimplementedSelectors\":[";
        for (size_t i = 0; i < g_unimplementedSelectors.size(); ++i) {
            if (i) json << ',';
            json << '\"' << JsonEscape(g_unimplementedSelectors[i]) << '\"';
        }
        json << ']';
    }
    json << '}';
    return json.str();
}

int WriteResult(char *json, size_t len, const ProbeReport &report)
{
    if (!json || len < 2) return 1;
    std::string text = ReportJson(report);
    int result = report.success ? 0 : 1;
    if (text.size() >= len) {
        text = "{\"success\":false,\"stage\":\"output\",\"error\":\"JSON output buffer too small\"}";
        result = 1;
    }
    const size_t count = std::min(text.size(), len - 1);
    std::memcpy(json, text.data(), count);
    json[count] = 0;
    return result;
}

} // namespace

extern "C" int hm_ca_renderer_render_layer(void *rootLayer, void *sceneContext, uint32_t width, uint32_t height,
    uint8_t *output, size_t outputSize, char *error, size_t errorSize)
{
    auto fail = [&](const std::string &message) {
        if (error && errorSize) {
            const size_t count = std::min(message.size(), errorSize - 1);
            std::memcpy(error, message.data(), count);
            error[count] = 0;
        }
        Log("ERROR", "real layer render: " + message);
        return 1;
    };
    if (!rootLayer || !output || !width || !height || outputSize < static_cast<size_t>(width) * height * 4)
        return fail("invalid layer render arguments");
    const uint32_t targetWidth = width;
    const uint32_t targetHeight = height;
    std::string setupError;
    if (!EnsureEntryPoints() || !EnsureFacades() || !RegisterDefaultDevice(setupError))
        return fail(setupError.empty() ? "could not initialize the real CARenderer facade" : setupError);
    ObjectCleanup cleanup;
    void *root = CallObject(rootLayer, "retain");
    if (!root) return fail("could not retain the real root layer");
    cleanup.own(root);
    void *descriptor = CallObjects(GetClass("MTLTextureDescriptor"),
        "texture2DDescriptorWithPixelFormat:width:height:mipmapped:",
        reinterpret_cast<void *>(kBGRA8Unorm), reinterpret_cast<void *>(targetWidth),
        reinterpret_cast<void *>(targetHeight), nullptr);
    if (!descriptor || !SetUint(descriptor, "setUsage:", 5))
        return fail("could not create the layer target texture descriptor");
    const uint64_t textureHandle = hm_metal_objc_device_new_bgra8_texture(Handle(g_defaultDevice),
        targetWidth, targetHeight, 5);
    void *texture = textureHandle ? MakeFacade(FacadeKind::Texture, textureHandle, descriptor) : nullptr;
    if (!texture || Kind(texture) != FacadeKind::Texture)
        return fail("could not create the real layer target texture");
    cleanup.own(texture);
    void *queue = CallObject(g_defaultDevice, "newCommandQueue");
    if (!queue || Kind(queue) != FacadeKind::Queue) return fail("could not create the real command queue");
    cleanup.own(queue);
    void *options = CallObjects(GetClass("NSDictionary"),
        "dictionaryWithObject:forKey:", queue, g_entries.rendererQueueKey);
    Log("INFO", "real layer before rendererWithMTLTexture");
    void *renderer = options ? CallObjects(GetClass("CARenderer"),
        "rendererWithMTLTexture:options:", texture, options) : nullptr;
    Log("INFO", "real layer rendererWithMTLTexture returned");
    if (!renderer) return fail("could not create CARenderer for the real layer");
    renderer = CallObject(renderer, "retain");
    Log("INFO", "real layer renderer retained");
    cleanup.own(renderer);
    Log("INFO", "real layer renderer created");
    void *layerContext = sceneContext ? sceneContext : CallObject(root, "context");
    if (!layerContext) layerContext = CallObject(root, "_context");
    void *localContext = layerContext ? layerContext : CallObject(GetClass("CAContext"), "localContext");
    if (localContext) CallVoidObjects(renderer, "setContext:", localContext);
    Log("INFO", "real layer context selected=" + std::to_string(layerContext != nullptr));
    if (!CallVoidObjects(renderer, "setLayer:", root) ||
        !SetRect(renderer, "setBounds:", {{0, 0}, {static_cast<double>(targetWidth), static_cast<double>(targetHeight)}}))
        return fail("could not attach the real root layer to CARenderer");
    Log("INFO", "real layer attached to CARenderer");
    void *begin = Lookup(renderer, "beginFrameAtTime:timeStamp:");
    if (!begin) return fail("CARenderer beginFrameAtTime is unavailable");
    using BeginFrame = void (*)(void *, void *, double, void *);
    reinterpret_cast<BeginFrame>(begin)(renderer, Selector("beginFrameAtTime:timeStamp:"),
        g_entries.currentMediaTime(), nullptr);
    Log("INFO", "real layer beginFrame completed");
    const CGRect bounds = CallRect(renderer, "bounds");
    if (!SetRect(renderer, "addUpdateRect:", bounds) || !CallVoid(renderer, "render") ||
        !CallVoid(renderer, "endFrame")) return fail("CARenderer frame sequence failed");
    Log("INFO", "real layer frame rendered");
    void *fence = CallObject(queue, "commandBuffer");
    if (!fence) return fail("could not create the layer completion fence");
    fence = CallObject(fence, "retain");
    cleanup.own(fence);
    if (!CallVoid(fence, "commit") || !CallVoid(fence, "waitUntilCompleted"))
        return fail("layer fence commit/wait failed");
    if (CallUint(fence, "status") != kCompleted) return fail("layer fence did not complete");
    Log("INFO", "real layer fence completed");
    usleep(200000);
    MTLRegion region {{0, 0, 0}, {targetWidth, targetHeight, 1}};
    void *getBytes = Lookup(texture, "getBytes:bytesPerRow:fromRegion:mipmapLevel:");
    if (!getBytes) return fail("layer texture readback is unavailable");
    t_facadeError.clear();
    using GetBytes = void (*)(void *, void *, void *, uint64_t, MTLRegion, uint64_t);
    reinterpret_cast<GetBytes>(getBytes)(texture, Selector("getBytes:bytesPerRow:fromRegion:mipmapLevel:"),
        output, static_cast<uint64_t>(targetWidth) * 4, region, 0);
    if (!t_facadeError.empty()) return fail(t_facadeError);
    if (error && errorSize) error[0] = 0;
    return 0;
}

static int RunProbeEntry(char *json, size_t len, int scene)
{
    if (!json || len < 2) return 1;
    ProbeReport report;
    try {
        RunProbe(report, scene);
    } catch (const std::exception &exception) {
        Fail(report, "host-exception", exception.what());
    } catch (...) {
        const std::type_info *type = abi::__cxa_current_exception_type();
        Fail(report, "host-exception", type ? type->name() : "unknown C++ exception");
    }
    return WriteResult(json, len, report);
}

extern "C" int hm_ca_renderer_probe(char *json, size_t len)
{
    return RunProbeEntry(json, len, 0);
}

extern "C" int hm_ca_renderer_probe_scene1(char *json, size_t len)
{
    return RunProbeEntry(json, len, 1);
}

extern "C" int hm_ca_renderer_probe_scene2(char *json, size_t len)
{
    return RunProbeEntry(json, len, 2);
}

extern "C" int hm_ca_renderer_probe_scene3(char *json, size_t len)
{
    return RunProbeEntry(json, len, 3);
}
