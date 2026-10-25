#include "cache_image.h"
#include "code_signature.h"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {
void Write32(std::vector<uint8_t> &bytes, size_t at, uint32_t value)
{
    bytes[at] = uint8_t(value >> 24);
    bytes[at + 1] = uint8_t(value >> 16);
    bytes[at + 2] = uint8_t(value >> 8);
    bytes[at + 3] = uint8_t(value);
}

void WriteLe32(std::vector<uint8_t> &bytes, size_t at, uint32_t value)
{
    for (size_t i = 0; i < 4; ++i) bytes[at + i] = uint8_t(value >> (i * 8));
}

std::vector<uint8_t> Fixture(std::vector<uint8_t> &xml, std::vector<uint8_t> &der)
{
    constexpr size_t signatureOffset = 0x1000;
    constexpr size_t signatureSize = 0x200;
    std::vector<uint8_t> file(signatureOffset + signatureSize);
    WriteLe32(file, 0, 0xfeedfacf);
    WriteLe32(file, 4, 0x0100000c);
    WriteLe32(file, 12, 2);
    WriteLe32(file, 16, 1);
    WriteLe32(file, 20, 16);
    WriteLe32(file, 32, 0x1d);
    WriteLe32(file, 36, 16);
    WriteLe32(file, 40, signatureOffset);
    WriteLe32(file, 44, signatureSize);

    xml = {0xfa, 0xde, 0x71, 0x71, 0, 0, 0, 16, 'p', 'l', 'i', 's', 't', 0, 0, 0};
    der = {0xfa, 0xde, 0x71, 0x72, 0, 0, 0, 12, 1, 2, 3, 4};
    constexpr size_t xmlOffset = 0x20;
    const size_t derOffset = xmlOffset + xml.size();
    const size_t embeddedSize = derOffset + der.size();
    auto *signature = file.data() + signatureOffset;
    Write32(file, signatureOffset, 0xfade0cc0);
    Write32(file, signatureOffset + 4, embeddedSize);
    Write32(file, signatureOffset + 8, 2);
    Write32(file, signatureOffset + 12, 5);
    Write32(file, signatureOffset + 16, xmlOffset);
    Write32(file, signatureOffset + 20, 7);
    Write32(file, signatureOffset + 24, derOffset);
    std::memcpy(signature + xmlOffset, xml.data(), xml.size());
    std::memcpy(signature + derOffset, der.data(), der.size());
    return file;
}
}

int main()
{
    namespace fs = std::filesystem;
    const auto path = fs::temp_directory_path() / "harmonios-code-signature-fixture";
    std::vector<uint8_t> xml, der;
    auto file = Fixture(xml, der);
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char *>(file.data()), file.size());
    }
    HmCacheImage image;
    image.executable = path.c_str();
    assert(hm_prepare_code_signature(image).empty());
    assert(image.entitlementsXml == xml);
    assert(image.entitlementsDer == der);

    auto invalidLength = file;
    Write32(invalidLength, 0x1004, 0x300);
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char *>(invalidLength.data()), invalidLength.size());
    }
    assert(hm_prepare_code_signature(image) == "code-signature-superblob-invalid");

    auto invalidMagic = file;
    invalidMagic[0x1000 + 0x20] = 0;
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char *>(invalidMagic.data()), invalidMagic.size());
    }
    assert(hm_prepare_code_signature(image) == "code-signature-entitlements-invalid");
    fs::remove(path);
    std::cout << "code signature: padded superblob and entitlements passed\n";
}
