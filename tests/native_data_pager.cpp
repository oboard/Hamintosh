#include "data_pager.h"
#include <cassert>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>

namespace {
constexpr uint64_t PAGE = 0x4000, SPAN = 0x20000;
uint64_t lastModifier = 0, lastKey = 0;
uint64_t Sign(uint64_t pointer, uint64_t modifier, uint32_t key) {
    lastModifier = modifier; lastKey = key;
    return pointer ^ 0x0020000000000000ULL;
}
uint64_t Read(const uint8_t *p) { uint64_t value; std::memcpy(&value, p, 8); return value; }
HmDataPager *faultPager = nullptr;
volatile sig_atomic_t dataFaults = 0;
void PageFault(int, siginfo_t *info, void *) {
    if (!faultPager || !faultPager->Fault(reinterpret_cast<uintptr_t>(info->si_addr))) _exit(91);
    ++dataFaults;
}

void TestReadableFileGap(const char *pack) {
    auto *raw = static_cast<uint8_t *>(mmap(nullptr, SPAN + PAGE, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    assert(raw != MAP_FAILED);
    const auto aligned = (reinterpret_cast<uintptr_t>(raw) + PAGE - 1) & ~(PAGE - 1);
    auto *base = reinterpret_cast<uint8_t *>(aligned);
    const auto prefix = base - raw;
    if (prefix) munmap(raw, prefix);
    munmap(base + SPAN, PAGE - prefix);
    auto *file = std::tmpfile();
    assert(file && ftruncate(fileno(file), SPAN) == 0);
    const uint32_t alias[] = {0x5280000f, 0x52800000};
    const uint64_t neighbor = 0x123456789abcdef0ULL;
    assert(pwrite(fileno(file), alias, sizeof(alias), PAGE + 0x100) == sizeof(alias));
    assert(pwrite(fileno(file), &neighbor, sizeof(neighbor), 0) == sizeof(neighbor));
    assert(pwrite(fileno(file), &neighbor, sizeof(neighbor), 2 * PAGE) == sizeof(neighbor));
    // Model musl's initial file mapping before individual ELF PT_LOAD overlays.
    assert(mmap(base, SPAN, PROT_READ, MAP_FIXED | MAP_PRIVATE, fileno(file), 0) != MAP_FAILED);
    uint8_t uuid[16]; std::memset(uuid, 0x11, sizeof(uuid));
    HmDataPager pager;
    assert(pager.Open(pack, base, SPAN, uuid, Sign));
    auto *count = reinterpret_cast<volatile const uint32_t *>(base + PAGE + 0x104);
    assert(*count == 0x52800000 && pager.Pages() == 0);
    assert(Read(base) == neighbor && Read(base + 2 * PAGE) == neighbor);
    // Protect only the reservation gap. Never replace adjacent signed code.
    assert(mprotect(base + PAGE, PAGE, PROT_NONE) == 0);
    struct sigaction action {}, oldSegv {}, oldBus {};
    action.sa_sigaction = PageFault; action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGSEGV, &action, &oldSegv) == 0);
    assert(sigaction(SIGBUS, &action, &oldBus) == 0);
    faultPager = &pager; dataFaults = 0;
    // A real CPU load must fault and retry. Access/copy-in would hide the bug.
    assert(*count == 5);
    faultPager = nullptr;
    assert(sigaction(SIGSEGV, &oldSegv, nullptr) == 0);
    assert(sigaction(SIGBUS, &oldBus, nullptr) == 0);
    assert(dataFaults == 1 && pager.Pages() == 1);
    assert(Read(base) == neighbor && Read(base + 2 * PAGE) == neighbor);
    pager.Reset();
    munmap(base, SPAN);
    std::fclose(file);
}
}

int main(int argc, char **argv) {
    assert(argc == 6);
    TestReadableFileGap(argv[1]);
    auto *raw = static_cast<uint8_t *>(mmap(nullptr, SPAN + PAGE, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    assert(raw != MAP_FAILED);
    const auto aligned = (reinterpret_cast<uintptr_t>(raw) + PAGE - 1) & ~(PAGE - 1);
    auto *base = reinterpret_cast<uint8_t *>(aligned);
    const auto prefix = base - raw;
    if (prefix) munmap(raw, prefix);
    munmap(base + SPAN, PAGE - prefix);
    uint8_t uuid[16]; std::memset(uuid, 0x11, 16);
    HmDataPager pager;
    assert(!pager.Open(argv[1], base, SPAN, uuid, Sign, 0x180004000ULL));
    assert(pager.Open(argv[1], base, SPAN, uuid, Sign, 0x180000000ULL));
    const auto address = reinterpret_cast<uintptr_t>(base + PAGE);
    assert(pager.Contains(address, PAGE));
    assert(!pager.Contains(address, 2 * PAGE)); // Unowned gap remains inaccessible.
    assert(!pager.Contains(address - PAGE, 8));
    assert(!pager.Access(address, 8, 2));
    assert(pager.Pages() == 0);
    assert(pager.Fault(address));
    assert(pager.Pages() == 1);
    assert(Read(base + PAGE) == (reinterpret_cast<uintptr_t>(base + 0x80) ^ 0x0020000000000000ULL));
    assert(Read(base + PAGE + 8) == reinterpret_cast<uintptr_t>(base + 0x90));
    assert(Read(base + PAGE + 8192) == reinterpret_cast<uintptr_t>(base + 0x200));
    assert(lastKey == 2);
    assert(lastModifier == ((address & 0x0000ffffffffffffULL) | (0x1234ULL << 48)));
    assert(!pager.Fault(address));
    assert(pager.Access(address, 16, 1));
    assert(pager.Protect(address, PAGE, 4) == 2); // Never create executable memory.
    assert(pager.Protect(address, PAGE, 3) == 0);
    assert(pager.Access(address, 8, 2));
    std::memcpy(base + PAGE, "changed!", 8);
    assert(!pager.Fault(address));
    assert(std::memcmp(base + PAGE, "changed!", 8) == 0); // No rebase/reset of live data.
    assert(pager.Protect(address, PAGE, 0) == 0);
    assert(!pager.Access(address, 8, 1));
    assert(!pager.Fault(address));
    assert(pager.Protect(address, PAGE, 1) == 0);
    assert(pager.Access(address, 8, 1));
    assert(pager.Pages() == 1);
    assert(pager.Access(reinterpret_cast<uintptr_t>(base + 3 * PAGE), 8, 3));
    assert(std::memcmp(base + 3 * PAGE, "other!!!", 8) == 0);
    assert(pager.Pages() == 2);
    pager.Reset();
    assert(!pager.Contains(address, 1));
    assert(pager.Open(argv[1], base, SPAN, uuid, Sign));
    assert(mmap(base + PAGE, PAGE, PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED);
    std::memcpy(base + PAGE, "already!", 8);
    pager.MarkLoaded(PAGE, PAGE, 3);
    assert(pager.Access(address, 8, 3));
    assert(!pager.Fault(address));
    assert(std::memcmp(base + PAGE, "already!", 8) == 0 && pager.Pages() == 0);
    pager.MarkLoaded(PAGE, PAGE, 5); // A signed code owner must bypass the data pager.
    assert(!pager.Contains(address, 8));
    assert(!pager.Fault(address));
    assert(pager.Open(argv[2], base, SPAN, uuid, Sign));
    assert(!pager.Fault(address));
    assert(std::strcmp(pager.Error(), "cache-data-page-crc-mismatch") == 0);
    assert(!pager.Open(argv[3], base, SPAN, uuid, Sign));
    assert(std::strcmp(pager.Error(), "cache-data-index-crc-mismatch") == 0);
    assert(!pager.Open(argv[4], base, SPAN, uuid, Sign));
    assert(std::strcmp(pager.Error(), "cache-data-mapping-invalid") == 0);
    assert(pager.Open(argv[5], base, SPAN, uuid, Sign));
    assert(!pager.Fault(address));
    assert(std::strcmp(pager.Error(), "cache-data-chain-outside-page") == 0);
    assert(pager.Open(argv[1], base, SPAN, uuid, nullptr));
    assert(!pager.Fault(address));
    assert(std::strcmp(pager.Error(), "cache-data-pac-signer-missing") == 0);
    uuid[0] ^= 1;
    assert(!pager.Open(argv[1], base, SPAN, uuid, Sign));
    pager.Reset();
    munmap(base, SPAN);
    std::cout << "data pager: real CPU fault retry, readable ELF gap, PAC, CRC and protection checks passed\n";
}
