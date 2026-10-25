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
    close(host);
    std::memset(output, 0xff, sizeof(output));
    assert(Stat(image, "/usr/lib/../fixture", output) == 13);
    assert(output[0] == 0xff);
    fs::create_symlink("/etc/passwd", root / "usr/lib/escape");
    assert(Stat(image, "/usr/lib/escape", output) == 13);
    assert(Stat(image, "/usr/lib/fixture", output, 0x20) == 22);
    fs::remove_all(root);
    std::cout << "file stat: guest root, descriptor and symlink confinement passed\n";
}
