#include "data_pager.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr uint64_t PAGE = 0x4000;
uint64_t Q(const uint8_t *p) { uint64_t value; std::memcpy(&value, p, 8); return value; }
uint32_t W(const uint8_t *p) { uint32_t value; std::memcpy(&value, p, 4); return value; }
bool Read(int fd, uint64_t offset, void *out, size_t size) {
    auto *bytes = static_cast<uint8_t *>(out);
    while (size) {
        const auto n = pread(fd, bytes, size, static_cast<off_t>(offset));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += n; offset += n; size -= n;
    }
    return true;
}
constexpr std::array<uint32_t, 256> CrcTable() {
    std::array<uint32_t, 256> table {};
    for (uint32_t i = 0; i < 256; ++i) {
        auto value = i;
        for (int bit = 0; bit < 8; ++bit) value = (value >> 1) ^ (0xedb88320U & (0U - (value & 1)));
        table[i] = value;
    }
    return table;
}
constexpr auto crcTable = CrcTable();
uint32_t Crc(const uint8_t *bytes, size_t size) {
    uint32_t value = ~0U;
    for (size_t i = 0; i < size; ++i) value = (value >> 8) ^ crcTable[(value ^ bytes[i]) & 255];
    return ~value;
}
}

HmDataPager::~HmDataPager() { if (fd_ >= 0) close(fd_); }

void HmDataPager::Reset() {
    for (const auto &mapping : mappings_) for (size_t i = 0; i < mapping.loaded.size(); ++i) {
        if (mapping.loaded[i] == 2) mmap(base_ + mapping.start + i * PAGE, PAGE,
            PROT_NONE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    mappings_.clear();
    if (fd_ >= 0) close(fd_);
    fd_ = -1; base_ = nullptr; pages_ = 0; error_ = "";
}

bool HmDataPager::Open(const char *path, uint8_t *base, uint64_t span, const uint8_t *uuid, Signer signer,
    uint64_t expectedPreferred) {
    Reset();
    fd_ = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd_ < 0) { error_ = errno == ENOENT ? "cache-data-not-staged" : "cache-data-open-failed"; return false; }
    std::array<uint8_t, 64> header {};
    struct stat stat {};
    if (fstat(fd_, &stat) || !S_ISREG(stat.st_mode) || !Read(fd_, 0, header.data(), header.size()) ||
        std::memcmp(header.data(), "HMDATA01", 8) || std::memcmp(header.data() + 8, uuid, 16) ||
        Q(header.data() + 32) != span || (expectedPreferred && Q(header.data() + 24) != expectedPreferred) ||
        Q(header.data() + 48) != static_cast<uint64_t>(stat.st_size)) {
        error_ = "cache-data-header-invalid"; return false;
    }
    const auto count = Q(header.data() + 40), metadataSize = uint64_t(W(header.data() + 56));
    if (!count || count > 16384 || metadataSize < 64 + count * 80 || metadataSize > 16 * 1024 * 1024 ||
        metadataSize > static_cast<uint64_t>(stat.st_size) || metadataSize % PAGE) {
        error_ = "cache-data-index-invalid"; return false;
    }
    std::vector<uint8_t> metadata(metadataSize - 64);
    if (!Read(fd_, 64, metadata.data(), metadata.size()) || Crc(metadata.data(), metadata.size()) != W(header.data() + 60)) {
        error_ = "cache-data-index-crc-mismatch"; return false;
    }
    std::vector<Mapping> validated;
    for (size_t i = 0; i < count; ++i) {
        const auto *p = metadata.data() + i * 80;
        const auto protection = Q(p + 24), initial = (protection >> 8) & 7;
        Mapping m {Q(p), Q(p + 8), Q(p + 16), protection & 7, Q(p + 32), Q(p + 40),
            Q(p + 48), Q(p + 56), Q(p + 64), {}, {}};
        const auto tableFits = [metadataSize](uint64_t at, uint64_t entries, uint64_t width) {
            return at >= 64 && at <= metadataSize && entries <= (metadataSize - at) / width;
        };
        if (!m.size || m.start % PAGE || m.size % PAGE || m.start >= span || m.size > span - m.start ||
            (i && validated.back().start + validated.back().size > m.start) ||
            protection & ~0x303ULL || initial & ~m.maximum || m.dataOffset < metadataSize || m.dataOffset % PAGE ||
            m.dataOffset > static_cast<uint64_t>(stat.st_size) || m.size > static_cast<uint64_t>(stat.st_size) - m.dataOffset ||
            !tableFits(m.crcOffset, m.size / PAGE, 4) || Q(p + 72) ||
            (m.slidePage != 0 && m.slidePage != 4096 && m.slidePage != PAGE) ||
            (m.slidePage && (m.startsCount > m.size / m.slidePage || !tableFits(m.startsOffset, m.startsCount, 2))) ||
            (!m.slidePage && (m.startsCount || m.startsOffset || m.valueAdd))) {
            error_ = "cache-data-mapping-invalid"; return false;
        }
        m.permissions.assign(m.size / PAGE, initial);
        m.loaded.assign(m.size / PAGE, 0);
        validated.push_back(std::move(m));
    }
    base_ = base; span_ = span; preferred_ = Q(header.data() + 24); signer_ = signer;
    mappings_ = std::move(validated);
    return true;
}

HmDataPager::Mapping *HmDataPager::Find(uint64_t address, uint64_t size) {
    if (!base_ || address < reinterpret_cast<uintptr_t>(base_)) return nullptr;
    const auto offset = address - reinterpret_cast<uintptr_t>(base_);
    auto found = std::upper_bound(mappings_.begin(), mappings_.end(), offset,
        [](uint64_t value, const Mapping &mapping) { return value < mapping.start; });
    if (found == mappings_.begin()) return nullptr;
    auto &m = *--found;
    if (size <= m.size && offset - m.start <= m.size - size) return &m;
    return nullptr;
}

bool HmDataPager::Contains(uint64_t address, uint64_t size) const {
    auto *self = const_cast<HmDataPager *>(this);
    if (!size) return self->Find(address, 0) != nullptr;
    while (size) {
        auto *m = self->Find(address, 1);
        if (!m) return false;
        const auto offset = address - reinterpret_cast<uintptr_t>(base_);
        if (m->loaded[(offset - m->start) / PAGE] == 3) return false; // Signed ELF code retains its own VM policy.
        const auto step = std::min(size, PAGE - offset % PAGE);
        address += step; size -= step;
    }
    return true;
}

void HmDataPager::MarkLoaded(uint64_t offset, uint64_t size, uint8_t protection) {
    if (offset % PAGE || size % PAGE || offset > span_ || size > span_ - offset) return;
    auto begin = std::lower_bound(mappings_.begin(), mappings_.end(), offset,
        [](const Mapping &mapping, uint64_t value) { return mapping.start + mapping.size <= value; });
    for (auto it = begin; it != mappings_.end() && it->start < offset + size; ++it) {
        auto &m = *it;
        const auto start = std::max(offset, m.start), end = std::min(offset + size, m.start + m.size);
        if (end <= start) continue;
        for (auto i = (start - m.start) / PAGE; i < (end - m.start) / PAGE; ++i) {
            m.loaded[i] = protection & 4 ? 3 : 1; m.permissions[i] = protection;
        }
    }
}

bool HmDataPager::Load(Mapping &m, uint64_t index) {
    if (m.loaded[index]) return true;
    auto *page = base_ + m.start + index * PAGE;
    uint8_t crc[4];
    if (!Read(fd_, m.crcOffset + index * 4, crc, 4)) { error_ = "cache-data-crc-read-failed"; return false; }
    if (mmap(page, PAGE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
        error_ = "cache-data-page-map-failed"; return false;
    }
    const auto fail = [&](const char *error) {
        error_ = error;
        mmap(page, PAGE, PROT_NONE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return false;
    };
    if (!Read(fd_, m.dataOffset + index * PAGE, page, PAGE) || Crc(page, PAGE) != W(crc))
        return fail("cache-data-page-crc-mismatch");
    if (m.slidePage) for (uint64_t sub = 0; sub < PAGE; sub += m.slidePage) {
        const auto slideIndex = (index * PAGE + sub) / m.slidePage;
        if (slideIndex >= m.startsCount) continue;
        uint16_t start;
        if (!Read(fd_, m.startsOffset + slideIndex * 2, &start, 2)) return fail("cache-data-chain-read-failed");
        if (start == 0xffff) continue;
        uint64_t at = start;
        while (true) {
            if (at % 8 || at + 8 > m.slidePage) return fail("cache-data-chain-outside-page");
            auto *slot = page + sub + at;
            const auto raw = Q(slot);
            const auto target = raw & ((1ULL << 34) - 1);
            const bool auth = raw >> 63;
            if ((!auth && ((raw >> 42) & 0x3ff)) || m.valueAdd > UINT64_MAX - target ||
                m.valueAdd + target < preferred_ || m.valueAdd + target - preferred_ >= span_)
                return fail("cache-data-rebase-invalid");
            uint64_t value = reinterpret_cast<uintptr_t>(base_) + m.valueAdd + target - preferred_;
            if (auth) {
                if (!signer_) return fail("cache-data-pac-signer-missing");
                const auto diversity = (raw >> 34) & 0xffff;
                const auto modifier = raw & (1ULL << 50) ?
                    ((reinterpret_cast<uintptr_t>(slot) & 0x0000ffffffffffffULL) | (diversity << 48)) : diversity;
                value = signer_(value, modifier, raw & (1ULL << 51) ? 2 : 0);
            } else value |= ((raw >> 34) & 255) << 56;
            std::memcpy(slot, &value, 8);
            const auto next = ((raw >> 52) & 0x7ff) * 8;
            if (!next) break;
            at += next;
        }
    }
    if (mprotect(page, PAGE, m.permissions[index])) return fail("cache-data-page-protection-failed");
    m.loaded[index] = 2; ++pages_;
    return true;
}

bool HmDataPager::Fault(uint64_t address) {
    auto *m = Find(address, 1);
    if (!m) return false;
    const auto index = (address - reinterpret_cast<uintptr_t>(base_) - m->start) / PAGE;
    if (m->loaded[index] || !m->permissions[index]) return false;
    return Load(*m, index);
}

bool HmDataPager::Access(uint64_t address, uint64_t size, uint8_t protection) {
    if (!Contains(address, size)) return false;
    while (size) {
        auto *m = Find(address, 1);
        const auto index = (address - reinterpret_cast<uintptr_t>(base_) - m->start) / PAGE;
        if ((m->permissions[index] & protection) != protection || !Load(*m, index)) return false;
        const auto step = std::min(size, PAGE - (address - reinterpret_cast<uintptr_t>(base_)) % PAGE);
        address += step; size -= step;
    }
    return true;
}

uint32_t HmDataPager::Protect(uint64_t address, uint64_t size, uint32_t protection) {
    if (!Contains(address, size) || address % PAGE || size % PAGE) return 1;
    for (auto at = address; at < address + size; at += PAGE) if (protection & ~Find(at, 1)->maximum) return 2;
    for (auto at = address; at < address + size; at += PAGE) {
        auto *m = Find(at, 1);
        const auto index = (at - reinterpret_cast<uintptr_t>(base_) - m->start) / PAGE;
        if (m->loaded[index] && mprotect(reinterpret_cast<void *>(at), PAGE, protection)) return 2;
        m->permissions[index] = protection;
    }
    return 0;
}
