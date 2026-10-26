#pragma once
#include <cstddef>
#include <cstdint>
// Synthetic zero-filled bytes for native policy tests; no Apple code.
extern "C" const uint8_t hm_objc_image[];
extern "C" uint8_t hm_objc_pool_0[];
extern "C" uint8_t hm_objc_pool_1[];
constexpr uint64_t HM_OBJC_FILESIZE = 64, HM_OBJC_SPAN = 0x14000;
constexpr uint64_t HM_OBJC_TEXTSIZE = 0xc000;
constexpr uint64_t HM_OBJC_SIGNATUREOFFSET = 32, HM_OBJC_SIGNATURESIZE = 32;
constexpr uint64_t HM_OBJC_CODEEND = 0xd000;
constexpr size_t HM_OBJC_POOL_COUNT = 2;
static uint8_t *const HM_OBJC_POOLS[] = {hm_objc_pool_0, hm_objc_pool_1};
