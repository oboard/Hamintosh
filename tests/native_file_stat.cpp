#include "cache_image.h"
#include "guest_files.h"
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

extern "C" void hm_guest_console(const void *, uint32_t, const uint8_t *, size_t) {}
extern "C" uint32_t hm_guest_copy_out(const void *, uint64_t, const uint8_t *, size_t) { return 14; }

namespace {
uint64_t Load64(const uint8_t *p) { uint64_t value; std::memcpy(&value, p, sizeof(value)); return value; }
uint16_t Load16(const uint8_t *p) { uint16_t value; std::memcpy(&value, p, sizeof(value)); return value; }
uint32_t Stat(const HmCacheImage &image, const std::string &path, uint8_t *output, uint32_t flags = 0)
{
    return hm_guest_file_stat(&image, -1, reinterpret_cast<const uint8_t *>(path.data()),
        path.size(), flags, output, 144);
}
}

int main()
{
    namespace fs = std::filesystem;
    const auto root = fs::temp_directory_path() / ("harmonios-file-stat-" + std::to_string(getpid()));
    const auto directory = root / "usr/lib";
    fs::create_directories(directory);
    const auto file = directory / "fixture";
    const int fd = open(file.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, "hello", 5) == 5 && close(fd) == 0);
    HmCacheImage image;
    image.sysroot = root.c_str();
    image.executable = "/not/the/guest/executable";
    uint8_t output[144] {};
    assert(Stat(image, "/usr/lib/fixture", output) == 0);
    assert(Load64(output + 96) == 5);
    assert((Load16(output + 4) & 0170000) == 0100000);
    const int host = open(file.c_str(), O_RDONLY);
    assert(host >= 0);
    std::memset(output, 0, sizeof(output));
    assert(hm_guest_file_stat(&image, host, nullptr, 0, 0, output, sizeof(output)) == 0);
    assert(Load64(output + 96) == 5);
    uint8_t contents[8] {};
    size_t count = 0;
    assert(hm_guest_file_read(&image, host, contents, 3, -1, &count) == 0);
    assert(count == 3 && !std::memcmp(contents, "hel", 3));
    assert(hm_guest_file_read(&image, host, contents, 2, 1, &count) == 0);
    assert(count == 2 && !std::memcmp(contents, "el", 2));
    int64_t position = -1;
    assert(hm_guest_file_seek(&image, host, 0, 1, &position) == 0 && position == 3);
    assert(hm_guest_file_seek(&image, host, -2, 2, &position) == 0 && position == 3);
    assert(hm_guest_file_read(&image, host, contents, sizeof(contents), -1, &count) == 0);
    assert(count == 2 && !std::memcmp(contents, "lo", 2));
    assert(hm_guest_file_read(&image, host, contents, sizeof(contents), -1, &count) == 0 && count == 0);
    assert(hm_guest_file_seek(&image, host, 0, 3, &position) == 22);
    assert(hm_guest_file_read(&image, host, contents, 1, -2, &count) == 22);
    close(host);
    assert(hm_guest_file_read(&image, host, contents, 1, -1, &count) == 9);
    std::memset(output, 0xff, sizeof(output));
    assert(Stat(image, "/usr/lib/../fixture", output) == 13);
    assert(output[0] == 0xff);
    fs::create_symlink("/etc/passwd", root / "usr/lib/escape");
    assert(Stat(image, "/usr/lib/escape", output) == 13);
    assert(Stat(image, "/usr/lib/fixture", output, 0x20) == 22);
    const auto bundle = root / "apps/Fixture.app";
    fs::create_directories(bundle);
    const auto executable = (bundle / "Fixture").string();
    image.executable = executable.c_str();
    assert(Stat(image, bundle.string(), output) == 0);
    assert((Load16(output + 4) & 0170000) == 0040000);
    assert(Stat(image, bundle.string() + "/", output) == 0);
    int bundleFd = -1;
    const auto bundlePath = bundle.string();
    assert(hm_guest_open(&image, -1, reinterpret_cast<const uint8_t *>(bundlePath.data()),
        bundlePath.size(), 0x00100000, 0, &bundleFd) == 0);
    assert(bundleFd >= 0 && close(bundleFd) == 0);
    const auto info = bundle / "Info.plist";
    const int infoFd = open(info.c_str(), O_CREAT | O_WRONLY, 0600);
    assert(infoFd >= 0 && write(infoFd, "plist", 5) == 5 && close(infoFd) == 0);
    assert(Stat(image, info.string(), output) == 0);
    assert(Load64(output + 96) == 5);
    int plistFd = -1;
    const auto plistPath = info.string();
    assert(hm_guest_open(&image, -1, reinterpret_cast<const uint8_t *>(plistPath.data()),
        plistPath.size(), 0x01000104, 0, &plistFd) == 0);
    assert(plistFd >= 0 && close(plistFd) == 0);
    assert(Stat(image, bundle.string() + "/../", output) == 13);
    fs::create_directories(root / "apps/Fixture.app-sibling");
    assert(Stat(image, (root / "apps/Fixture.app-sibling").string(), output) == 2);
    fs::create_symlink("/etc/passwd", bundle / "escape");
    assert(Stat(image, (bundle / "escape").string(), output) == 13);
    for (int i = 0; i < 40; ++i) {
        const auto entry = bundle / ("item-" + std::to_string(i));
        const int fileFd = open(entry.c_str(), O_CREAT | O_WRONLY, 0600);
        assert(fileFd >= 0 && close(fileFd) == 0);
    }
    const int directoryFd = open(bundle.c_str(), O_RDONLY | O_DIRECTORY);
    assert(directoryFd >= 0);
    std::set<std::string> names;
    uint8_t entries[64] {};
    int64_t base = -1;
    bool eof = false;
    for (int call = 0; call < 100; ++call) {
        assert(hm_guest_read_directory(&image, directoryFd, entries, sizeof(entries), &count, &base) == 0);
        if (!count) { eof = true; break; }
        for (size_t at = 0; at < count;) {
            const auto length = Load16(entries + at + 16);
            const auto nameSize = Load16(entries + at + 18);
            assert(length && !(length & 7) && at + length <= count && nameSize + 22U <= length);
            assert(entries[at + 21 + nameSize] == 0);
            std::string name(reinterpret_cast<char *>(entries + at + 21), nameSize);
            assert(names.insert(name).second);
            at += length;
        }
    }
    assert(eof && names.count("Info.plist"));
    for (int i = 0; i < 40; ++i) assert(names.count("item-" + std::to_string(i)));
    assert(hm_guest_file_seek(&image, directoryFd, 0, 0, &position) == 0);
    assert(hm_guest_read_directory(&image, directoryFd, entries, sizeof(entries), &count, &base) == 0 && count);
    close(directoryFd);

    // A captured Linux dirent64 layout must expand into Darwin records without
    // losing the cookie of the last entry that fits in a smaller output buffer.
    uint8_t linuxEntries[48] {};
    for (size_t at : {size_t(0), size_t(24)}) {
        const uint64_t inode = at ? 11 : 10;
        const int64_t cookie = at ? 200 : 100;
        const uint16_t size = 24;
        std::memcpy(linuxEntries + at, &inode, 8);
        std::memcpy(linuxEntries + at + 8, &cookie, 8);
        std::memcpy(linuxEntries + at + 16, &size, 2);
        linuxEntries[at + 18] = 8;
        std::memcpy(linuxEntries + at + 19, at ? "two" : "one", 4);
    }
    int64_t cookie = 0;
    assert(hm_convert_linux_dirents(linuxEntries, 48, entries, 32, &count, &cookie) == 0);
    assert(count == 32 && cookie == 100 && Load64(entries) == 10);
    assert(Load16(entries + 18) == 3 && entries[20] == 8 && !std::strcmp(reinterpret_cast<char *>(entries + 21), "one"));
    assert(hm_convert_linux_dirents(linuxEntries + 24, 24, entries, 32, &count, &cookie) == 0);
    assert(cookie == 200 && !std::strcmp(reinterpret_cast<char *>(entries + 21), "two"));
    assert(hm_convert_linux_dirents(linuxEntries, 48, entries, 24, &count, &cookie) == 22);
    linuxEntries[16] = 0;
    assert(hm_convert_linux_dirents(linuxEntries, 48, entries, 64, &count, &cookie) == 5);
    fs::remove_all(root);
    std::cout << "file stat: guest root, descriptor and symlink confinement passed\n";
}
