#include "code_signature.h"
#include "cache_image.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr uint32_t MachMagic64 = 0xfeedfacf;
constexpr uint32_t CodeSignatureCommand = 0x1d;
constexpr uint32_t EmbeddedSignatureMagic = 0xfade0cc0;
constexpr uint32_t XmlEntitlementsMagic = 0xfade7171;
constexpr uint32_t DerEntitlementsMagic = 0xfade7172;
constexpr uint32_t MaxCommandBytes = 16 * 1024 * 1024;
constexpr uint32_t MaxSignatureBytes = 4 * 1024 * 1024;

uint32_t Le32(const uint8_t *p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
uint32_t Be32(const uint8_t *p) { return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3]; }

bool ReadAt(int fd, uint64_t offset, void *bytes, size_t size)
{
    auto *out = static_cast<uint8_t *>(bytes);
    while (size) {
        const auto n = pread(fd, out, size, static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        out += n; offset += n; size -= n;
    }
    return true;
}
}

std::string hm_prepare_code_signature(HmCacheImage &image)
{
    image.entitlementsXml.clear();
    image.entitlementsDer.clear();
    if (!image.executable || !*image.executable) return "code-signature-executable-missing";
    const int fd = open(image.executable, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return "code-signature-open-failed";
    struct stat info {};
    uint8_t header[32] {};
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 32 || !ReadAt(fd, 0, header, sizeof(header)) ||
        Le32(header) != MachMagic64) {
        close(fd); return "code-signature-mach-o-header-invalid";
    }
    const uint32_t commands = Le32(header + 16), commandBytes = Le32(header + 20);
    if (commands == 0 || commands > 4096 || commandBytes > MaxCommandBytes || commandBytes > uint64_t(info.st_size) - 32) {
        close(fd); return "code-signature-load-command-limit";
    }
    std::vector<uint8_t> loadCommands(commandBytes);
    if (!ReadAt(fd, 32, loadCommands.data(), loadCommands.size())) {
        close(fd); return "code-signature-load-command-read-failed";
    }
    uint32_t signatureOffset = 0, signatureSize = 0;
    for (uint32_t i = 0, at = 0; i < commands; ++i) {
        if (at > loadCommands.size() - 8) { close(fd); return "code-signature-load-command-overflow"; }
        const uint32_t command = Le32(loadCommands.data() + at), size = Le32(loadCommands.data() + at + 4);
        if (size < 8 || size > loadCommands.size() - at) { close(fd); return "code-signature-load-command-size-invalid"; }
        if (command == CodeSignatureCommand) {
            if (size < 16 || signatureOffset || signatureSize) { close(fd); return "code-signature-command-invalid"; }
            std::memcpy(&signatureOffset, loadCommands.data() + at + 8, 4);
            std::memcpy(&signatureSize, loadCommands.data() + at + 12, 4);
        }
        at += size;
    }
    if (!signatureOffset || signatureSize < 12 || signatureSize > MaxSignatureBytes ||
        signatureSize > uint64_t(info.st_size) || signatureOffset > uint64_t(info.st_size) - signatureSize) {
        close(fd); return "code-signature-range-invalid";
    }
    std::vector<uint8_t> signature(signatureSize);
    if (!ReadAt(fd, signatureOffset, signature.data(), signature.size())) {
        close(fd); return "code-signature-read-failed";
    }
    close(fd);
    // LC_CODE_SIGNATURE.datasize includes zero padding after the embedded
    // superblob. The superblob's own length is therefore the authoritative
    // bound for every index and blob entry.
    const uint32_t embeddedSize = Be32(signature.data() + 4);
    if (Be32(signature.data()) != EmbeddedSignatureMagic || embeddedSize < 12 || embeddedSize > signature.size()) {
        return "code-signature-superblob-invalid";
    }
    const uint32_t count = Be32(signature.data() + 8);
    if (count > 256 || 12 + count * 8 > embeddedSize) return "code-signature-index-overflow";
    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t type = Be32(signature.data() + 12 + i * 8);
        const uint32_t offset = Be32(signature.data() + 16 + i * 8);
        if (type != 5 && type != 7) continue;
        if (offset > embeddedSize - 8) return "code-signature-blob-offset-invalid";
        const uint32_t magic = Be32(signature.data() + offset), length = Be32(signature.data() + offset + 4);
        if (length < 8 || length > embeddedSize - offset ||
            (type == 5 && magic != XmlEntitlementsMagic) || (type == 7 && magic != DerEntitlementsMagic) ||
            length > 64 * 1024) return "code-signature-entitlements-invalid";
        auto &blob = type == 5 ? image.entitlementsXml : image.entitlementsDer;
        blob.assign(signature.begin() + offset, signature.begin() + offset + length);
    }
    if (image.entitlementsXml.empty() && image.entitlementsDer.empty()) return "code-signature-entitlements-missing";
    return {};
}
