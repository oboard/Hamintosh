#include "guest_files.h"
#include "cache_image.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#if !defined(__APPLE__)
#include <sys/syscall.h>
#else
extern "C" ssize_t __getdirentries64(int, char *, size_t, off_t *);
#endif

extern "C" void hm_guest_console(const void *, uint32_t, const uint8_t *, size_t);

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
        case EISDIR: return 21;
        case ESPIPE: return 29;
        case EOVERFLOW: return 84;
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

uint32_t OpenBelow(const char *root, const char *relative, int flags, int *descriptor)
{
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return DarwinError(errno);
    const char *part = relative;
    while (*part) {
        while (*part == '/') ++part;
        if (!*part) break;
        const char *end = part;
        while (*end && *end != '/') ++end;
        const size_t count = end - part;
        if ((count == 1 && part[0] == '.') ||
            (count == 2 && part[0] == '.' && part[1] == '.')) {
            close(fd);
            return 13;
        }
        char component[1024] {};
        std::memcpy(component, part, count);
        const int next = openat(fd, component, *end ?
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW : flags);
        const int error = errno;
        close(fd);
        if (next < 0) return DarwinError(error == ELOOP ? EACCES : error);
        fd = next;
        part = end;
    }
    *descriptor = fd;
    return 0;
}

uint32_t OpenConfined(const HmCacheImage *image, const char *guest, int flags, int *descriptor)
{
    if (!image || !image->executable || !image->sysroot || guest[0] != '/') return 2;
    if (!std::strcmp(guest, image->executable)) {
        const int fd = open(guest, flags);
        if (fd < 0) return DarwinError(errno);
        *descriptor = fd;
        return 0;
    }

    const char *slash = std::strrchr(image->executable, '/');
    if (!slash) return 2;
    const size_t bundleLength = static_cast<size_t>(slash - image->executable);
    if (bundleLength && bundleLength < 1024 &&
        !std::strncmp(guest, image->executable, bundleLength) &&
        (guest[bundleLength] == '\0' || guest[bundleLength] == '/')) {
        char bundle[1024] {};
        std::memcpy(bundle, image->executable, bundleLength);
        return OpenBelow(bundle, guest + bundleLength + (guest[bundleLength] == '/'),
            flags, descriptor);
    }
    return OpenBelow(image->sysroot, guest + 1, flags, descriptor);
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
    const uint32_t error = OpenConfined(image, path, nativeFlags, &fd);
    if (error) {
        const char prefix[] = "[open failed] ";
        hm_guest_console(context, 2, reinterpret_cast<const uint8_t *>(prefix), sizeof(prefix) - 1);
        hm_guest_console(context, 2, reinterpret_cast<const uint8_t *>(path), std::strlen(path));
        hm_guest_console(context, 2, reinterpret_cast<const uint8_t *>("\n"), 1);
        return error;
    }
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
    const uint32_t error = OpenConfined(image, guest, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, &descriptor);
    if (error) return error;
    const int result = fstat(descriptor, &info);
    const int statError = errno;
    close(descriptor);
    if (result) return DarwinError(statError);
    FillDarwinStat(info, output);
    return 0;
}

extern "C" uint32_t hm_guest_file_read(const void *, int32_t descriptor,
    uint8_t *output, size_t size, int64_t offset, size_t *count)
{
    if (!count || (!output && size)) return 14;
    if (offset < -1) return 22;
    const ssize_t result = offset == -1 ? read(descriptor, output, size) :
        pread(descriptor, output, size, static_cast<off_t>(offset));
    if (result < 0) return DarwinError(errno);
    *count = static_cast<size_t>(result);
    return 0;
}

extern "C" uint32_t hm_guest_file_seek(const void *, int32_t descriptor,
    int64_t offset, uint32_t whence, int64_t *position)
{
    if (!position) return 14;
    if (whence > 2) return 22;
    const off_t result = lseek(descriptor, static_cast<off_t>(offset), static_cast<int>(whence));
    if (result < 0) return DarwinError(errno);
    *position = static_cast<int64_t>(result);
    return 0;
}

extern "C" uint32_t hm_convert_linux_dirents(const uint8_t *input, size_t inputSize,
    uint8_t *output, size_t capacity, size_t *count, int64_t *cookie)
{
    *count = 0;
    for (size_t at = 0; at < inputSize;) {
        if (inputSize - at < 20) return 5;
        uint16_t length;
        std::memcpy(&length, input + at + 16, 2);
        if (length < 20 || length > inputSize - at) return 5;
        const auto *name = input + at + 19;
        const auto *end = static_cast<const uint8_t *>(std::memchr(name, 0, length - 19));
        if (!end || end - name > 1023) return 5;
        const size_t nameSize = end - name;
        // XNU DIRENT64_LEN includes the structure's tail padding.
        const size_t recordSize = (25 + nameSize + 7) & ~size_t(7);
        if (recordSize > capacity - *count) return *count ? 0 : 22;
        uint64_t inode;
        int64_t next;
        std::memcpy(&inode, input + at, 8);
        std::memcpy(&next, input + at + 8, 8);
        uint8_t *entry = output + *count;
        std::memset(entry, 0, recordSize);
        Store<uint64_t>(entry, 0, inode);
        Store<int64_t>(entry, 8, next);
        Store<uint16_t>(entry, 16, static_cast<uint16_t>(recordSize));
        Store<uint16_t>(entry, 18, static_cast<uint16_t>(nameSize));
        entry[20] = input[at + 18];
        std::memcpy(entry + 21, name, nameSize);
        *cookie = next;
        *count += recordSize;
        at += length;
    }
    return 0;
}

extern "C" uint32_t hm_guest_read_directory(const void *, int32_t descriptor,
    uint8_t *output, size_t size, size_t *count, int64_t *position)
{
    if (!count || !position || (!output && size)) return 14;
    if (size < 32) return 22;
    struct stat info {};
    if (fstat(descriptor, &info)) return DarwinError(errno);
    if (!S_ISDIR(info.st_mode)) return 20;
#if defined(__APPLE__)
    off_t base = 0;
    const auto result = __getdirentries64(descriptor, reinterpret_cast<char *>(output), size, &base);
    if (result < 0) return DarwinError(errno);
    *count = static_cast<size_t>(result);
    *position = base;
    return 0;
#else
    const off_t base = lseek(descriptor, 0, SEEK_CUR);
    if (base < 0) return DarwinError(errno);
    alignas(8) uint8_t input[4096];
    const long result = syscall(SYS_getdents64, descriptor, input, sizeof(input));
    if (result < 0) return DarwinError(errno);
    int64_t cookie = base;
    const uint32_t error = hm_convert_linux_dirents(input, static_cast<size_t>(result),
        output, size, count, &cookie);
    // Conversion can expand records. Rewind to the last emitted entry so the
    // next guest read resumes without silently dropping any directory names.
    if (lseek(descriptor, error ? base : cookie, SEEK_SET) < 0) return DarwinError(errno);
    *position = base;
    return error;
#endif
}

extern "C" uint32_t hm_guest_code_signature_blob(const void *context, uint32_t type,
    uint64_t output, uint64_t outputSize)
{
    const auto *image = static_cast<const HmCacheImage *>(context);
    if (!image) return 14;
    const std::vector<uint8_t> *blob = nullptr;
    if (type == 5) blob = &image->entitlementsXml;
    else if (type == 7) blob = &image->entitlementsDer;
    else return 22;
    if (!blob || blob->empty()) return 85; // Darwin EBADEXEC
    if (outputSize < 8) return 34; // Darwin ERANGE
    if (outputSize < blob->size()) {
        uint8_t header[8] {};
        const uint32_t length = static_cast<uint32_t>(blob->size());
        header[4] = static_cast<uint8_t>(length >> 24);
        header[5] = static_cast<uint8_t>(length >> 16);
        header[6] = static_cast<uint8_t>(length >> 8);
        header[7] = static_cast<uint8_t>(length);
        if (hm_guest_copy_out(context, output, header, sizeof(header)) != 0) return 14;
        return 34;
    }
    if (hm_guest_copy_out(context, output, blob->data(), blob->size()) != 0) return 14;
    return 0;
}
