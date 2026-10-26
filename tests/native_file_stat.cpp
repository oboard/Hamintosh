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
    assert(Stat(image, bundle.string() + "/../", output) == 13);
    fs::create_directories(root / "apps/Fixture.app-sibling");
    assert(Stat(image, (root / "apps/Fixture.app-sibling").string(), output) == 2);
    fs::create_symlink("/etc/passwd", bundle / "escape");
    assert(Stat(image, (bundle / "escape").string(), output) == 13);
    fs::remove_all(root);
    std::cout << "file stat: guest root, descriptor and symlink confinement passed\n";
}
