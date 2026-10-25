#pragma once
#include <cstdint>
#include <vector>

// Only non-executable pages inside the signed ELF's cache reservation are
// admitted. Open/mark/reset run outside guest execution; fault/access/protect
// allocate no memory and take no host allocator locks.
class HmDataPager {
public:
    using Signer = uint64_t (*)(uint64_t, uint64_t, uint32_t);
    ~HmDataPager();
    HmDataPager() = default;
    HmDataPager(const HmDataPager &) = delete;
    HmDataPager &operator=(const HmDataPager &) = delete;
    bool Open(const char *path, uint8_t *base, uint64_t span, const uint8_t *uuid, Signer signer,
        uint64_t expectedPreferred = 0);
    void Reset();
    void MarkLoaded(uint64_t offset, uint64_t size, uint8_t protection);
    bool Contains(uint64_t address, uint64_t size) const;
    bool Fault(uint64_t address);
    bool Access(uint64_t address, uint64_t size, uint8_t protection);
    uint32_t Protect(uint64_t address, uint64_t size, uint32_t protection);
    uint64_t Pages() const { return pages_; }
    const char *Error() const { return error_; }
private:
    struct Mapping {
        uint64_t start, size, dataOffset, maximum, slidePage, valueAdd, startsOffset, startsCount, crcOffset;
        std::vector<uint8_t> permissions, loaded;
    };
    Mapping *Find(uint64_t address, uint64_t size);
    bool Load(Mapping &mapping, uint64_t index);
    int fd_ = -1;
    uint8_t *base_ = nullptr;
    uint64_t span_ = 0, preferred_ = 0, pages_ = 0;
    Signer signer_ = nullptr;
    const char *error_ = "";
    std::vector<Mapping> mappings_;
};
