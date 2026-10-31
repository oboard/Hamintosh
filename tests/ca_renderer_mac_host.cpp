// Build the same CARenderer/Metal facade used on Harmony as a macOS host probe.
// Apple CoreText/CoreGraphics own scene 3's bitmap and QuartzCore owns frame
// submission; the Harmonios facade owns Metal objects and uses metal2vulkan.
// Argument 3 continues to dispatch hm_ca_renderer_probe_scene3 unchanged.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <dlfcn.h>
#include <vector>
#if defined(__aarch64__)
#include <ptrauth.h>
#endif

extern "C" uint64_t hm_pac_sign_pointer(uint64_t pointer, uint64_t modifier, uint32_t key)
{
#if defined(__aarch64__)
    const void *value = reinterpret_cast<const void *>(pointer);
    switch (key) {
    case 0: return reinterpret_cast<uint64_t>(ptrauth_sign_unauthenticated(value, ptrauth_key_asia, modifier));
    case 1: return reinterpret_cast<uint64_t>(ptrauth_sign_unauthenticated(value, ptrauth_key_asib, modifier));
    case 2: return reinterpret_cast<uint64_t>(ptrauth_sign_unauthenticated(value, ptrauth_key_asda, modifier));
    default: return reinterpret_cast<uint64_t>(ptrauth_sign_unauthenticated(value, ptrauth_key_asdb, modifier));
    }
#else
    return pointer;
#endif
}

extern "C" uint64_t hm_pac_strip_instruction(uint64_t pointer)
{
#if defined(__aarch64__)
    return reinterpret_cast<uint64_t>(ptrauth_strip(reinterpret_cast<const void *>(pointer), ptrauth_key_asia));
#else
    return pointer;
#endif
}

extern "C" uint64_t hm_pac_strip_data(uint64_t pointer)
{
#if defined(__aarch64__)
    return reinterpret_cast<uint64_t>(ptrauth_strip(reinterpret_cast<const void *>(pointer), ptrauth_key_asda));
#else
    return pointer;
#endif
}

uint64_t HmGuestObjcRuntimeSymbol(const char *name)
{
    static bool loaded = [] {
        const char *const frameworks[] = {
            "/System/Library/Frameworks/Foundation.framework/Foundation",
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
            "/System/Library/Frameworks/CoreText.framework/CoreText",
            "/System/Library/Frameworks/Metal.framework/Metal",
            "/System/Library/Frameworks/QuartzCore.framework/QuartzCore",
        };
        for (const char *path : frameworks) {
            if (!dlopen(path, RTLD_NOW | RTLD_GLOBAL)) {
                std::fprintf(stderr, "macOS host dlopen failed for %s: %s\n", path, dlerror());
                return false;
            }
        }
        return true;
    }();
    const char *hostName = name && name[0] == '_' ? name + 1 : name;
    void *symbol = loaded && hostName ? dlsym(RTLD_DEFAULT, hostName) : nullptr;
    if (!symbol) std::fprintf(stderr, "macOS host symbol missing: %s (frameworks loaded=%d)\n",
        name ? name : "<null>", loaded ? 1 : 0);
    return reinterpret_cast<uint64_t>(symbol);
}

extern "C" int hm_ca_renderer_probe(char *json, size_t len);
extern "C" int hm_ca_renderer_probe_scene1(char *json, size_t len);
extern "C" int hm_ca_renderer_probe_scene2(char *json, size_t len);
extern "C" int hm_ca_renderer_probe_scene3(char *json, size_t len);

int main(int argc, char **argv)
{
    const bool validScene = argc == 1 || (argc == 2 &&
        (argv[1][0] == '1' || argv[1][0] == '2' || argv[1][0] == '3') && argv[1][1] == '\0');
    if (!validScene) {
        std::fprintf(stderr, "usage: %s [1|2|3]\n", argv[0]);
        return 64;
    }
    std::vector<char> report(16384, 0);
    const int result = argc == 2 && argv[1][0] == '3'
        ? hm_ca_renderer_probe_scene3(report.data(), report.size())
        : argc == 2 && argv[1][0] == '2'
        ? hm_ca_renderer_probe_scene2(report.data(), report.size())
        : argc == 2 ? hm_ca_renderer_probe_scene1(report.data(), report.size())
                    : hm_ca_renderer_probe(report.data(), report.size());
    std::fprintf(stdout, "%s\n", report.data());
    return result;
}
