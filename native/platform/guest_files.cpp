#include "guest_files.h"
#include "cache_image.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace {
uint32_t DarwinError(int error)
{
    switch (error) {
        case ENOENT: return 2;
        case EINTR: return 4;
        case EBADF: return 9;
        case ENOMEM: return 12;
        case EACCES: return 13;
        case EFAULT: return 14;
        case ENOTDIR: return 20;
        case EINVAL: return 22;
        case ENFILE: return 23;
        case EMFILE: return 24;
        case ELOOP: return 62;
        case ENAMETOOLONG: return 63;
        default: return 5;
    }
}

template <typename T>
void Store(uint8_t *output, size_t at, T value)
{
    std::memcpy(output + at, &value, sizeof(value));
}

uint32_t OpenConfined(const HmCacheImage *image, const char *guest, int *descriptor)
{
    if (!image || !image->executable || !image->sysroot) return 2;
    int fd = -1;
    if (!std::strcmp(guest, image->executable)) {
        fd = open(guest, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    } else if (guest[0] == '/') {
        fd = open(image->sysroot, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return DarwinError(errno);
        const char *part = guest + 1;
        while (*part) {
            while (*part == '/') ++part;
            if (!*part) break;
            const char *end = part;
            while (*end && *end != '/') ++end;
            const size_t count = end - part;
            if ((count == 1 && part[0] == '.') ||
                (count == 2 && part[0] == '.' && part[1] == '.') ||
                count >= 1024) {
                const int error = count >= 1024 ? ENAMETOOLONG : EACCES;
                close(fd);
                return DarwinError(error);
            }
            char component[1024] {};
            std::memcpy(component, part, count);
            const int next = openat(fd, component, *end ?
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW :
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            const int error = errno;
            close(fd);
            if (next < 0) return DarwinError(error == ELOOP ? EACCES : error);
            fd = next;
            part = end;
        }
    } else {
        return 2;
    }
    if (fd < 0) return DarwinError(errno);
    *descriptor = fd;
    return 0;
}

void FillDarwinStat(const struct stat &info, uint8_t *output)
{
    std::memset(output, 0, 144);
    Store<uint32_t>(output, 0, static_cast<uint32_t>(info.st_dev));
    Store<uint16_t>(output, 4, static_cast<uint16_t>(info.st_mode));
    Store<uint16_t>(output, 6, static_cast<uint16_t>(info.st_nlink));
    Store<uint64_t>(output, 8, static_cast<uint64_t>(info.st_ino));
    Store<uint32_t>(output, 16, static_cast<uint32_t>(info.st_uid));
    Store<uint32_t>(output, 20, static_cast<uint32_t>(info.st_gid));
    Store<uint32_t>(output, 24, static_cast<uint32_t>(info.st_rdev));
    // OHOS uses 64-bit seconds. Nanoseconds remain zero unless its stat ABI
    // provides a portable field across every supported host.
    Store<int64_t>(output, 32, static_cast<int64_t>(info.st_atime));
    Store<int64_t>(output, 48, static_cast<int64_t>(info.st_mtime));
    Store<int64_t>(output, 64, static_cast<int64_t>(info.st_ctime));
    Store<int64_t>(output, 80, static_cast<int64_t>(info.st_ctime));
    Store<int64_t>(output, 96, static_cast<int64_t>(info.st_size));
    Store<int64_t>(output, 104, static_cast<int64_t>(info.st_blocks));
    Store<int32_t>(output, 112, static_cast<int32_t>(info.st_blksize));
}
}

extern "C" uint32_t hm_guest_open(const void *context, int32_t parent, const uint8_t *bytes, size_t length,
    uint32_t flags, uint32_t, int32_t *descriptor)
{
    const auto *image = static_cast<const HmCacheImage *>(context);
    char path[1024] {};
    if (length >= sizeof(path)) return 63;
    if (length) std::memcpy(path, bytes, length);
    if (!image || !image->executable) return 2;
    if (parent >= 0) {
        struct stat info {};
        if (fstat(parent, &info)) return DarwinError(errno);
        if (!S_ISDIR(info.st_mode)) return 20;
    }
    if (flags & ~0x21100100U) return 45;
    int nativeFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
    if (flags & 0x00100000U) nativeFlags |= O_DIRECTORY;
    int fd = -1;
    if (!std::strcmp(path, image->executable)) {
        fd = open(path, nativeFlags);
    } else if (path[0] == '/' && image->sysroot) {
        // Walk beneath the guest root one component at a time. Neither parent
        // traversal nor symlinks can escape into another host directory.
        fd = open(image->sysroot, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return DarwinError(errno);
        const char *part = path + 1;
        while (*part) {
            while (*part == '/') ++part;
            if (!*part) break;
            const char *end = part;
            while (*end && *end != '/') ++end;
            const size_t count = end - part;
            if ((count == 1 && part[0] == '.') || (count == 2 && part[0] == '.' && part[1] == '.')) {
                close(fd); return 13;
            }
            char component[1024] {};
            std::memcpy(component, part, count);
            const int next = openat(fd, component, *end ?
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW : nativeFlags);
            const int error = errno;
            close(fd);
            if (next < 0) return DarwinError(error == ELOOP ? EACCES : error);
            fd = next;
            part = end;
        }
    } else return 2;
    if (fd < 0) return DarwinError(errno);
    *descriptor = fd;
    return 0;
}

extern "C" uint32_t hm_guest_close(const void *, int32_t descriptor)
{
    return close(descriptor) ? DarwinError(errno) : 0;
}

extern "C" uint32_t hm_guest_duplicate(const void *, int32_t descriptor, int32_t *output)
{
    const int fd = fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) return DarwinError(errno);
    *output = fd;
    return 0;
}

extern "C" uint32_t hm_guest_file_stat(const void *context, int32_t parent,
    const uint8_t *bytes, size_t length, uint32_t flags, uint8_t *output, size_t outputSize)
{
    const auto *image = static_cast<const HmCacheImage *>(context);
    if (!output || outputSize < 144) return 14;
    if (flags) return 22;
    struct stat info {};
    if (!bytes || length == 0) {
        if (parent < 0) return 9;
        return fstat(parent, &info) ? DarwinError(errno) : (FillDarwinStat(info, output), 0);
    }
    if (length >= 1024 || !image || !image->executable) return length >= 1024 ? 63 : 2;
    char guest[1024] {};
    std::memcpy(guest, bytes, length);
    int descriptor = -1;
    const uint32_t error = OpenConfined(image, guest, &descriptor);
    if (error) return error;
    const int result = fstat(descriptor, &info);
    const int statError = errno;
    close(descriptor);
    if (result) return DarwinError(statError);
    FillDarwinStat(info, output);
    return 0;
}
