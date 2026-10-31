#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned kSceneWidth = 256;
static const unsigned kSceneHeight = 256;
static const size_t kSceneByteCount = kSceneWidth * kSceneHeight * 4;
static NSString *const kArtifactDirectory = @"artifacts/mac-ca-scene3-bundled";
static NSString *const kBundledFontPath =
    @"harmonios/src/main/resources/rawfile/target/bundle/Fonts/PingFangSC.ttf";
// Independently measured from the actual bundled-font CARenderer readback.
// The matching backend value, if any, is never used to construct this template.
static NSString *const kExpectedReferenceHash = @"3500a6b1fe541d4f";

typedef struct {
    uint8_t b, g, r, a;
} SceneBGRA;

typedef struct {
    const char *name;
    unsigned x, y;
} SceneSample;

typedef struct {
    BOOL found;
    unsigned minX, minY, maxX, maxY;
    size_t pixelCount;
} GlyphBounds;

// These samples are also required in a Harmony hm_ca_renderer_probe report.
// Stable coordinates cover text coverage, antialiasing and background regions.
static const SceneSample kSamples[] = {
    {"root", 8, 8},
    {"textLayerBackground", 16, 16},
    {"hongInk", 18, 44},
    {"mengInk", 62, 43},
    {"hongAntialias", 24, 52},
    {"mengAntialias", 64, 52},
    {"afterText", 80, 64},
};

// Lossless native CARenderer reference measured with the bundled TTF bytes.
// The rectangle is the complete non-background glyph extent, including
// background holes. Bytes are raw Metal readback, never host rasterization.
static const unsigned kGlyphMinX = 17;
static const unsigned kGlyphMinY = 43;
static const unsigned kGlyphMaxX = 78;
static const unsigned kGlyphMaxY = 72;
static const unsigned kGlyphWidth = kGlyphMaxX - kGlyphMinX + 1;
static const unsigned kGlyphHeight = kGlyphMaxY - kGlyphMinY + 1;
static const size_t kGlyphNonBackgroundPixels = 1059;
static const CGGlyph kExpectedGlyphIDs[] = {28878, 22312};
static const char kExpectedGlyphBGRA[] =
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff604545ff857170ff928080ff9c8c8cff8d7a7aff"
    "513433ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff492c2bff"
    "634948ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff735c5bffd3ccccffece9e8ffe4e0e0ffb4a8a7ff634a49ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ffcdc5c5fffffffffffffffffffffffffffffffffff8f6f6ff877373ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff705858ffe5e1e1ffe4dfdfff462827ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "bfb5b4ffffffffffffffffffffffffffffffffffece9e8ff543938ff422322ff422322ff422322ff422322ff422322ff422322ff533736ffd8d1d1ffb9aeaeff"
    "8e7c7bff634a49ff432524ff422322ff422322ff422322ff4f3332fffcfcfcfff5f3f3ffe3dedeffe3dedeffffffffffffffffffffffffff6e5655ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff432423ff8b7878ff5b403fff422322ff8e7c7bffffffffffffffffff998887ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff492c2bffdcd7d6ffb9adadff"
    "958483ff877373fff7f6f6ffffffffff9c8b8bff422322ff422322ff422322ff422322ff422322ff432423ffccc3c3ffffffffffffffffffffffffffffffffff"
    "f4f2f2ffcac2c1ff9f908fff745d5cff4a2c2cff492b2aff422322ff422322ff422322ff705858ffffffffffffffffffb5a9a8ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff5b403fffcec6c6ffffffffffe5e1e1ff533736ff432524ffd9d3d3fffffffffff5f3f3ff533736ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "c4babaffffffffffcac2c1ff422322ff422322ff422322ff422322ff422322ff4d302fff887574ffa29393ffbcb0b0ffd5cfcefff8f7f7ffffffffffffffffff"
    "ffffffffffffffffe9e6e6ff948281ff492c2bff422322ff422322ff422322ffe5e1e1ffffffffffcdc4c4ff422322ff422322ff422322ff422322ff422322ff"
    "887574fff7f6f6fffffffffffffffffff5f3f3ff7d6867ff422322ff6b5252fffefefeffffffffffb6aaaaff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff9e8e8dffffffffff"
    "e9e6e6ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff472928ff715959ffa29292ffd3ccccfffefefeff"
    "fffffffffffffffff0eeeeff9e8e8dff4e3130ff422322ffc0b6b5ffffffffffe4e0e0ff422322ff422322ff422322ff422322ff8c7979fffefefeffffffffff"
    "ffffffffc4bbbbff563a39ff422322ff422322ff422322ffb6aaa9fffffffffffefdfdff684f4eff543938ff604545ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff7c6666ffffffffffffffffff4c2e2dff"
    "422322ff422322ff422322ff422322ff422322ff422322ff786261fff2efefffc7bebeff9c8c8cff715a59ff492c2bff422322ff5a3f3fffa59695ffece9e9ff"
    "fffffffffffffffff5f4f4ffa89a9affd2cacaffffffffffe1dddcff422322ff422322ff422322ff8b7878fffefefeffffffffffefececff806b6bff422322ff"
    "422322ff422322ff422322ff422322ff513433fff2f0f0ffffffffffd3ccccffafa2a1ffffffffffcfc7c7ff826d6dff462726ff422322ffdfdadafffcfcfcff"
    "fcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcffeeebebff664d4cffffffffffffffffff634948ff422322ff422322ff"
    "422322ff422322ff422322ff4c2f2effeae7e7fffffffffffffffffffffffffffffffffffcfcfcffd9d3d3ffaea0a0ff624847ff452625ff84706fffe7e2e2ff"
    "ffffffffffffffffffffffffffffffffcdc5c5ff422322ff422322ff745d5cfffefefeffffffffffedeaeaff5e4443ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ffa89a9afffffffffffffffffffefdfdffffffffffffffffffffffffffedeaeaffa49594ffeae7e7ffffffffffffffffffffffffff"
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffff1efeeff543938ffffffffffffffffff755f5eff422322ff422322ff422322ff422322ff"
    "422322ff4a2c2cff715a59ff917f7fffb1a4a4ffd1c9c9fff1efeefffffffffffffffffffffffffffefefeffc1b7b6ff644b4aff472928ff998887fff4f2f2ff"
    "ffffffffffffffffa29292ff422322ff492c2bffe6e2e1fffffffffff0eeeeff624847ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff5d4342fffefefeffffffffffd5ceceffa29292ffe1dddcffffffffffffffffffffffffffffffffffded8d8ffa29393ff705858ff6f5756ff6f5756ff"
    "6f5756ff6f5756ff6f5756ff6f5756ff6f5756ff6b5252ff452625fffefefeffffffffff877373ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff654c4bff674e4dff452625ff422322ff543938ff968484ffe6e2e1fffffffffffffffffffefefeffc2b8b8ff664c4cffb4a8a7ffffffffffffffffff"
    "624847ff422322ffa99b9affffffffffffffffffbfb5b4ff462827ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "cfc7c7fffffffffff3f1f1ff462726ff422322ffaa9d9cffffffffffffffffffffffffffffffffffffffffff543837ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ffefededffffffffff998887ff422322ff422322ff422322ff422322ff422322ff422322ff4d302fffece9e9ff"
    "fffffffff8f6f6ffd2cacaffa89a9aff7d6867ff4a2c2cff7b6565ffcdc4c4fffffffffffffffffffffffffffefefeffffffffffc4bbbbff422322ff604646ff"
    "fdfcfcffffffffffffffffffffffffffd8d2d2ff5b403fff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff836f6effffffffff"
    "ffffffff776160ff422322ffa19191fffffffffff2efefff7a6564ffc4babafffbfbfbff543837ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ffded8d8ffffffffffa19191ff422322ff422322ff422322ff422322ff422322ff422322ffb2a5a5ffffffffffffffffffffffffff"
    "fffffffffffffffffffffffff5f3f3ffb6aaa9ff6f5857ff614746ffbcb1b1fffffffffffffffffff8f6f6ff5a3f3fff422322ffad9f9ffffffffffff5f4f4ff"
    "887574fff6f5f5fffffffffff5f3f3ff816c6cff422322ff422322ff422322ff422322ff422322ff422322ff422322ff472928fff0eeeefff8f6f6ff857170ff"
    "422322ffa19191fffffffffff1efeeff422322ff422322ff523635ff826e6dffa99b9affa99b9affa99b9affa99b9affa99b9affa99b9affa99b9affa99b9aff"
    "a99b9affeae7e7ffffffffffa79898ff422322ff422322ff422322ff422322ff422322ff422322ff452625ff5b403fff745e5dff8d7a7affa59796ffcbc3c2ff"
    "fbfbfbffffffffffffffffffffffffffe6e2e1ffe2ddddfffffffffffdfcfcff7c6666ff422322ff472928fff2efefffffffffffa59695ff422322ff664c4cff"
    "ebe8e8fffffffffffcfcfcff695150ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff776160ff523534ff422322ff422322ffa19191ff"
    "fffffffff1efeeff422322ff422322ff422322ffb0a3a2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffaea0a0ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4d302fff857170ff"
    "c1b7b6fff6f5f5ffffffffffffffffffffffffffbcb1b1ff422322ff422322ff836f6effffffffffffffffff5c4140ff422322ff422322ff563a39ffcfc7c7ff"
    "745e5dff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ffa19191fffffffffff1efeeff"
    "422322ff422322ff422322ffb0a3a2fffffffffff9f8f8ffd9d3d3ffd9d3d3ffd9d3d3ffd9d3d3ffd9d3d3ffd9d3d3ffd9d3d3ffd9d3d3ffd9d3d3ff9c8b8bff"
    "422322ff422322ff422322ff422322ff422322ff422322ffbcb1b1ffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ffd6d0cfff"
    "fcfcfcffffffffffffffffffffffffffdbd5d5ffd0c8c8ffece9e8fffffffffffbfafaffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ffd0c8c8ff"
    "5d4241ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ffa19191fffffffffff1efeeff422322ff422322ff"
    "422322ffb0a3a2ffffffffffe2ddddff422322ff422322ff4c2f2eff715959ff917e7eff786261ff492c2bff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ffe5e1e1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff664c4cff422322ff"
    "422322ff422322ff422322ff422322ff422322ff5c4140ff422322ff422322ff422322ffa19191fffffffffff1efeeff422322ff422322ff422322ffb0a3a2ff"
    "ffffffffe2ddddff422322ff482a29fff7f6f6ffffffffffffffffffffffffffdcd7d6ff543938ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff988786ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ff"
    "a79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ffa79898ff543938ff422322ff422322ff422322ff"
    "422322ff452625ffaa9c9bfffbfafaff634a49ff422322ff422322ffa19191fffffffffff1efeeff422322ff422322ff422322ffb0a3a2ffffffffffe2ddddff"
    "422322ff7a6463fffffffffffcfcfcffddd7d7fff6f5f5ffffffffffaa9c9bff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff462827ff917f7fff917f7fff917f7fff917f7fff917f7fff917f7fff917f7fff917f7fff917f7fff917f7fff917f7fff"
    "917f7fff917f7fff917f7fff917f7fff917f7fff5e4443ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff715959ffd6d0cfff"
    "ffffffffffffffffd5cfceff422322ff422322ffa19191fffffffffff1efeeff422322ff422322ff422322ffb0a3a2ffffffffffe2ddddff422322ff796362ff"
    "7f6a69ff4f3231ff422322ffa89a9affffffffffd4cdcdff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff6f5756fff3f1f1ff"
    "f3f1f1ff604646ff4e3130ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffff867272ff422322ffb9adadffbeb3b3ff7e6968ff422322ff422322ff705858ffd7d0d0ffffffffffffffffffffffffffe4e0e0ff"
    "6e5655ff422322ff422322ffa19191fffffffffff1efeeff422322ff422322ff422322ffb0a3a2ffffffffffe2ddddff422322ff422322ff8d7a7affd4cdcdff"
    "593e3dff8d7a7affffffffffeeebebff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff715a59ffffffffffffffffff634948ff"
    "4c2f2efff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeefff1efeeff"
    "f1efeeff806b6bff422322fff7f6f6ffffffffff9e8e8dff422322ff422322ff634a49fffbfafafffffffffff6f5f5ffab9e9dff492c2bff422322ff422322ff"
    "422322ffa19191fffffffffff1efeeff422322ff422322ff422322ffb0a3a2ffffffffffe2ddddff422322ff5a3f3ffff4f2f2ffffffffffbcb1b1ff7d6867ff"
    "fffffffffcfcfcff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff715a59ffffffffffffffffff634948ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322fff7f6f6ffffffffff9e8e8dff422322ff422322ff422322ff8b7877ff8a7776ff4b2d2cff422322ff422322ff422322ff422322ff422322ffa19191ff"
    "fffffffff1efeeff422322ff422322ff422322ffb0a3a2ffffffffffe2ddddff583d3cffe7e3e3ffffffffffe7e2e2ff4f3231ff715a59ffffffffffffffffff"
    "472928ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff715a59ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffff9e8e8dff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4c2f2eff745d5cff745d5cffb9aeaefffffffffff5f3f3ff"
    "745d5cff745d5cff644b4affb0a3a2ffffffffffe2ddddff9f908fffffffffffebe8e8ff644b4aff422322ff6d5554ffffffffffffffffff4f3332ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff715a59ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9e8e8dff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff4f3231ff6c5353ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "c4bbbbffb0a3a2ffffffffffe3dedeff4a2c2cff7a6564ff5c4140ff4a2c2cff4a2c2cff715959ffffffffffffffffff513433ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff4c2f2eff6c5353ff6c5353ff6c5353ff6c5353ff6c5353ffafa2a1ffbeb3b3ffa09190ff6c5353ff6c5353ff6c5353ff"
    "6c5353ff6c5353ff6c5353ff6c5353ff6c5353ffa79898ffbeb3b3ffac9e9eff6c5353ff6c5353ff6c5353ff6c5353ff6c5353ff563a39ff422322ff422322ff"
    "422322ff422322ff422322ff4a2c2cffbdb2b2ffe8e4e4ff826e6dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc4bbbbffb0a3a2ff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff513433ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ffdcd7d6ffffffffffbcb0b0ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ffcac2c1ffffffffffd6d0cfff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff432423ff"
    "7d6766ffe0dbdbffffffffffffffffffd3cbcbff4e3130ff4e3130ff4e3130ff4e3130ff4e3130ff4e3130ff4e3130ff4a2c2cffb0a3a2ffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff513433ff422322ff422322ff422322ff422322ff422322ff422322ff9f908fff"
    "c7bebdffc7bebdffc7bebdffc7bebdffc7bebdffc7bebdfff5f3f3ffffffffffebe8e8ffc7bebdffc7bebdffc7bebdffc7bebdffc7bebdffc7bebdffc7bebdff"
    "c7bebdffefededfffffffffff3f1f1ffc7bebdffc7bebdffc7bebdffc7bebdffc7bebdffc7bebdff9f908fff422322ff715959ffe1dddcffffffffffffffffff"
    "ffffffffcac1c1ff503332ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff604646ff776160ff776160ffbeb3b3ffffffffff"
    "f8f7f7ff7a6564ff776160ff776160ff776160ff776160ff462726ff422322ff422322ff422322ff422322ff422322ff422322ffc7bebeffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7bebeff422322ff4f3231ffe2ddddffffffffffd5ceceff887473ff432423ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff604646ffffffffffffffffff786261ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff958483ffb9adadffb9adadffb9adadffb9adadff"
    "b9adadffb9adadfff2f0f0ffffffffffe6e2e1ffb9adadffb9adadffb9adadffb9adadffb9adadffb9adadffb9adadffb9adadffece9e8fffffffffff0eeeeff"
    "b9adadffb9adadffb9adadffb9adadffb9adadffb9adadff958483ff422322ff422322ff5a3f3eff634948ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ffe7e2e2ffffffffffa29292ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "dcd7d6ffffffffffbcb0b0ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ffcac2c1ffffffffffd6d0cfff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff857170ff684f4eff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ffa59695ffbcb0b0ff"
    "907e7dff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff8c7979ffaa9c9bff938180ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff";

_Static_assert(sizeof(kExpectedGlyphBGRA) - 1 == kGlyphWidth * kGlyphHeight * 8,
    "glyph template must contain every BGRA byte in the glyph rectangle");

static SceneBGRA RootPixel(void) {
    // Apple CARenderer's color-managed BGRA8Unorm value for
    // CGColorCreateGenericRGB(0.1,0.1,0.2,1), as established by scene0.
    return (SceneBGRA){66, 35, 34, 255};
}

static uint8_t HexDigit(char value) {
    return (uint8_t)(value <= '9' ? value - '0' : value - 'a' + 10);
}

static uint8_t HexByte(const char *value) {
    return (uint8_t)((HexDigit(value[0]) << 4) | HexDigit(value[1]));
}

static SceneBGRA ExpectedPixel(unsigned x, unsigned y) {
    if (x < kGlyphMinX || x > kGlyphMaxX || y < kGlyphMinY || y > kGlyphMaxY) {
        return RootPixel();
    }
    const size_t at = ((size_t)(y - kGlyphMinY) * kGlyphWidth +
        (x - kGlyphMinX)) * 8;
    const char *hex = kExpectedGlyphBGRA + at;
    return (SceneBGRA){HexByte(hex), HexByte(hex + 2), HexByte(hex + 4), HexByte(hex + 6)};
}

static BOOL PixelsEqual(SceneBGRA a, SceneBGRA b) {
    return a.b == b.b && a.g == b.g && a.r == b.r && a.a == b.a;
}

static SceneBGRA ActualPixel(const uint8_t *pixels, unsigned x, unsigned y) {
    const size_t at = ((size_t)y * kSceneWidth + x) * 4;
    return (SceneBGRA){pixels[at], pixels[at + 1], pixels[at + 2], pixels[at + 3]};
}

static uint64_t HashByte(uint64_t hash, uint8_t value) {
    return (hash ^ value) * 0x100000001b3ULL;
}

static uint64_t HashPixels(const uint8_t *pixels) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < kSceneByteCount; i++) hash = HashByte(hash, pixels[i]);
    return hash;
}

static NSString *ExpectedReferenceHash(void) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (unsigned y = 0; y < kSceneHeight; y++) {
        for (unsigned x = 0; x < kSceneWidth; x++) {
            const SceneBGRA pixel = ExpectedPixel(x, y);
            hash = HashByte(hash, pixel.b);
            hash = HashByte(hash, pixel.g);
            hash = HashByte(hash, pixel.r);
            hash = HashByte(hash, pixel.a);
        }
    }
    return [NSString stringWithFormat:@"%016llx", (unsigned long long)hash];
}

static size_t ExpectedNonzeroBytes(void) {
    size_t count = 0;
    for (unsigned y = 0; y < kSceneHeight; y++) {
        for (unsigned x = 0; x < kSceneWidth; x++) {
            const SceneBGRA pixel = ExpectedPixel(x, y);
            const uint8_t channels[] = {pixel.b, pixel.g, pixel.r, pixel.a};
            for (unsigned channel = 0; channel < 4; channel++) {
                if (channels[channel]) count++;
            }
        }
    }
    return count;
}

static GlyphBounds MeasureNonBackground(const uint8_t *pixels,
    unsigned minimumX, unsigned maximumX) {
    GlyphBounds result = {.minX = kSceneWidth, .minY = kSceneHeight};
    const SceneBGRA root = RootPixel();
    for (unsigned y = 0; y < kSceneHeight; y++) {
        for (unsigned x = minimumX; x <= maximumX; x++) {
            if (PixelsEqual(ActualPixel(pixels, x, y), root)) continue;
            result.found = YES;
            result.pixelCount++;
            if (x < result.minX) result.minX = x;
            if (x > result.maxX) result.maxX = x;
            if (y < result.minY) result.minY = y;
            if (y > result.maxY) result.maxY = y;
        }
    }
    return result;
}

static BOOL ValidateReferenceTemplate(void) {
    GlyphBounds measured = {.minX = kSceneWidth, .minY = kSceneHeight};
    const SceneBGRA root = RootPixel();
    for (unsigned y = 0; y < kSceneHeight; y++) {
        for (unsigned x = 0; x < kSceneWidth; x++) {
            if (PixelsEqual(ExpectedPixel(x, y), root)) continue;
            measured.found = YES;
            measured.pixelCount++;
            if (x < measured.minX) measured.minX = x;
            if (x > measured.maxX) measured.maxX = x;
            if (y < measured.minY) measured.minY = y;
            if (y > measured.maxY) measured.maxY = y;
        }
    }
    NSString *computedHash = ExpectedReferenceHash();
    if (!measured.found || measured.minX != kGlyphMinX || measured.minY != kGlyphMinY ||
        measured.maxX != kGlyphMaxX || measured.maxY != kGlyphMaxY ||
        measured.pixelCount != kGlyphNonBackgroundPixels ||
        ![computedHash isEqualToString:kExpectedReferenceHash] ||
        ExpectedNonzeroBytes() != kSceneByteCount) {
        fprintf(stderr, "scene3 key error: embedded native reference template is inconsistent: "
            "bounds=(%u,%u)-(%u,%u) count=%zu hash=%s nonzeroBytes=%zu\n",
            measured.minX, measured.minY, measured.maxX, measured.maxY,
            measured.pixelCount, computedHash.UTF8String, ExpectedNonzeroBytes());
        return NO;
    }
    return YES;
}

static void ReleaseBundledFontBytes(void *info, const void *data, size_t size) {
    (void)info;
    (void)size;
    free((void *)data);
}

// Create CoreText's font directly from the repository's bundled TTF bytes.
// The provider owns an exact copy, so no NSData lifetime or font registration
// can influence rendering. No CTFontCreateWithName/system-font fallback exists.
static CTFontRef CreateBundledFont(NSError **error) {
    NSData *fontData = [NSData dataWithContentsOfFile:kBundledFontPath
        options:0 error:error];
    if (!fontData || fontData.length == 0) return NULL;
    void *bytes = malloc(fontData.length);
    if (!bytes) {
        if (error) {
            *error = [NSError errorWithDomain:@"HarmoniosScene3Bundled" code:10
                userInfo:@{NSLocalizedDescriptionKey: @"cannot allocate bundled font bytes"}];
        }
        return NULL;
    }
    memcpy(bytes, fontData.bytes, fontData.length);
    CGDataProviderRef provider = CGDataProviderCreateWithData(NULL, bytes,
        (size_t)fontData.length, ReleaseBundledFontBytes);
    if (!provider) {
        free(bytes);
        return NULL;
    }
    CGFontRef graphicsFont = CGFontCreateWithDataProvider(provider);
    CGDataProviderRelease(provider);
    if (!graphicsFont) return NULL;
    CTFontRef font = CTFontCreateWithGraphicsFont(graphicsFont, 32.0, NULL, NULL);
    CGFontRelease(graphicsFont);
    return font;
}

static CALayer *CreateScene3(CTFontRef font) {
    CALayer *root = [CALayer layer];
    root.bounds = CGRectMake(0, 0, kSceneWidth, kSceneHeight);
    root.position = CGPointMake(kSceneWidth / 2.0, kSceneHeight / 2.0);
    CGColorRef background = CGColorCreateGenericRGB(0.1, 0.1, 0.2, 1);
    root.backgroundColor = background;
    if (background) CGColorRelease(background);
    root.geometryFlipped = NO;

    CATextLayer *text = [CATextLayer layer];
    text.frame = CGRectMake(16, 16, 224, 64);
    text.string = @"鸿蒙";
    text.font = font;
    text.fontSize = 32;
    text.foregroundColor = CGColorGetConstantColor(kCGColorWhite);
    text.alignmentMode = kCAAlignmentLeft;
    text.wrapped = NO;
    text.contentsScale = 1.0;
    [root addSublayer:text];
    return root;
}

static size_t CheckNativePixels(const uint8_t *pixels) {
    size_t mismatches = 0;
    for (unsigned y = 0; y < kSceneHeight; y++) {
        for (unsigned x = 0; x < kSceneWidth; x++) {
            const SceneBGRA expected = ExpectedPixel(x, y);
            const SceneBGRA actual = ActualPixel(pixels, x, y);
            if (PixelsEqual(actual, expected)) continue;
            if (mismatches < 16) {
                fprintf(stderr, "scene3 mismatch (%u,%u): got BGRA(%u,%u,%u,%u), "
                    "expected BGRA(%u,%u,%u,%u)\n", x, y,
                    actual.b, actual.g, actual.r, actual.a,
                    expected.b, expected.g, expected.r, expected.a);
            }
            mismatches++;
        }
    }
    if (mismatches) {
        fprintf(stderr, "scene3: %zu of %u pixels failed strict native-template validation\n",
            mismatches, kSceneWidth * kSceneHeight);
    }
    return mismatches;
}

static size_t CheckOneGlyphBounds(const char *name, GlyphBounds actual,
    unsigned minX, unsigned minY, unsigned maxX, unsigned maxY, size_t count) {
    if (actual.found && actual.minX == minX && actual.minY == minY &&
        actual.maxX == maxX && actual.maxY == maxY && actual.pixelCount == count) return 0;
    fprintf(stderr, "scene3 %s non-background bounds mismatch: got found=%d "
        "(%u,%u)-(%u,%u) count=%zu, expected (%u,%u)-(%u,%u) count=%zu\n",
        name, actual.found, actual.minX, actual.minY, actual.maxX, actual.maxY,
        actual.pixelCount, minX, minY, maxX, maxY, count);
    return 1;
}

static size_t CheckGlyphBounds(const uint8_t *pixels) {
    size_t mismatches = 0;
    mismatches += CheckOneGlyphBounds("all glyphs",
        MeasureNonBackground(pixels, 0, kSceneWidth - 1),
        17, 43, 78, 72, 1059);
    mismatches += CheckOneGlyphBounds("hong",
        MeasureNonBackground(pixels, 16, 47), 17, 44, 44, 72, 457);
    mismatches += CheckOneGlyphBounds("meng",
        MeasureNonBackground(pixels, 48, 79), 49, 43, 78, 72, 602);
    return mismatches;
}

static int ProbeReportFailure(NSString *message) {
    fprintf(stderr, "probe report: %s\n", message.UTF8String);
    return 1;
}

static BOOL RequireReportNumber(NSDictionary *report, NSString *key, long long expected) {
    id value = report[key];
    if ([value isKindOfClass:[NSNumber class]] && [value longLongValue] == expected) return YES;
    ProbeReportFailure([NSString stringWithFormat:@"%@ must be %lld, got %@",
        key, expected, value ?: @"<missing>"]);
    return NO;
}

static BOOL RequireReportString(NSDictionary *report, NSString *key, NSString *expected) {
    id value = report[key];
    if ([value isKindOfClass:[NSString class]] && [value isEqualToString:expected]) return YES;
    ProbeReportFailure([NSString stringWithFormat:@"%@ must be %@, got %@",
        key, expected, value ?: @"<missing>"]);
    return NO;
}

static BOOL RequireReportSample(NSDictionary *samples, const SceneSample sample) {
    NSString *name = [NSString stringWithUTF8String:sample.name];
    id value = samples[name];
    if (![value isKindOfClass:[NSDictionary class]]) {
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ is missing or not an object", name]);
        return NO;
    }
    NSDictionary *entry = value;
    id actualX = entry[@"x"];
    id actualY = entry[@"y"];
    if (![actualX isKindOfClass:[NSNumber class]] || [actualX unsignedIntValue] != sample.x ||
        ![actualY isKindOfClass:[NSNumber class]] || [actualY unsignedIntValue] != sample.y) {
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ must be at (%u,%u), got (%@,%@)",
            name, sample.x, sample.y, actualX ?: @"<missing>", actualY ?: @"<missing>"]);
        return NO;
    }
    id bgra = entry[@"bgra"];
    if (![bgra isKindOfClass:[NSArray class]] || [bgra count] != 4) {
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ must contain four BGRA channels", name]);
        return NO;
    }
    const SceneBGRA expected = ExpectedPixel(sample.x, sample.y);
    const uint8_t channels[] = {expected.b, expected.g, expected.r, expected.a};
    for (unsigned channel = 0; channel < 4; channel++) {
        id actual = bgra[channel];
        if (![actual isKindOfClass:[NSNumber class]] ||
            [actual unsignedIntValue] != channels[channel]) {
            ProbeReportFailure([NSString stringWithFormat:
                @"sample %@ BGRA channel %u must be %u, got %@",
                name, channel, channels[channel], actual]);
            return NO;
        }
    }
    return YES;
}

// Success and nonzero pixels are only smoke signals. Require the complete
// lifecycle, exact native hash, exact text/background colors and diagnostics.
static int CheckProbeReport(NSString *path) {
    if (!ValidateReferenceTemplate()) return 1;
    NSError *error = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:&error];
    if (!data) {
        return ProbeReportFailure([NSString stringWithFormat:@"cannot read %@: %@",
            path, error.localizedDescription ?: @"unknown I/O error"]);
    }
    id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (![value isKindOfClass:[NSDictionary class]]) {
        return ProbeReportFailure([NSString stringWithFormat:@"invalid JSON report: %@",
            error.localizedDescription ?: @"top level is not an object"]);
    }
    NSDictionary *report = value;
    @try {
        if (!RequireReportNumber(report, @"scene", 3) ||
            !RequireReportNumber(report, @"success", 1) ||
            !RequireReportString(report, @"stage", @"complete") ||
            !RequireReportNumber(report, @"rendererCreated", 1) ||
            !RequireReportNumber(report, @"frameEnded", 1) ||
            !RequireReportNumber(report, @"commandBufferStatus", MTLCommandBufferStatusCompleted) ||
            !RequireReportNumber(report, @"width", kSceneWidth) ||
            !RequireReportNumber(report, @"height", kSceneHeight) ||
            !RequireReportString(report, @"pixelFormat", @"BGRA8Unorm") ||
            !RequireReportNumber(report, @"nonZeroPixels", kSceneWidth * kSceneHeight) ||
            !RequireReportNumber(report, @"nonZeroBytes", (long long)ExpectedNonzeroBytes()) ||
            !RequireReportNumber(report, @"pixelMismatchCount", 0) ||
            !RequireReportNumber(report, @"unimplementedSelectorCount", 0)) return 1;

        id reportError = report[@"error"];
        if (reportError && (![reportError isKindOfClass:[NSString class]] ||
                [reportError length] != 0)) {
            return ProbeReportFailure([NSString stringWithFormat:@"unexpected key error: %@", reportError]);
        }
        id keyErrors = report[@"keyErrors"];
        if (keyErrors && (![keyErrors isKindOfClass:[NSArray class]] || [keyErrors count] != 0)) {
            return ProbeReportFailure([NSString stringWithFormat:@"unexpected keyErrors: %@", keyErrors]);
        }
        id device = report[@"device"];
        if (![device isKindOfClass:[NSString class]] || [device length] == 0) {
            return ProbeReportFailure(@"device must be a nonempty string");
        }
        id selectors = report[@"unimplementedSelectors"];
        if (![selectors isKindOfClass:[NSArray class]] || [selectors count] != 0) {
            return ProbeReportFailure([NSString stringWithFormat:
                @"unimplemented selectors are not allowed: %@", selectors ?: @"<missing>"]);
        }
        if (!RequireReportString(report, @"referenceFnv1a64", kExpectedReferenceHash) ||
            !RequireReportString(report, @"readbackFnv1a64", kExpectedReferenceHash)) return 1;
        id samples = report[@"samples"];
        if (![samples isKindOfClass:[NSDictionary class]]) {
            return ProbeReportFailure(@"samples is missing or not an object");
        }
        for (size_t i = 0; i < sizeof(kSamples) / sizeof(kSamples[0]); i++) {
            if (!RequireReportSample(samples, kSamples[i])) return 1;
        }
    } @catch (NSException *exception) {
        return ProbeReportFailure([NSString stringWithFormat:@"%@: %@",
            exception.name, exception.reason]);
    }
    printf("probe report: scene 3 exact full-frame hash, text/background samples, "
        "complete lifecycle, selectors and key errors passed\n");
    return 0;
}

static NSDictionary *SampleReport(const uint8_t *pixels) {
    NSMutableDictionary *samples = [NSMutableDictionary dictionary];
    for (size_t i = 0; i < sizeof(kSamples) / sizeof(kSamples[0]); i++) {
        const SceneSample sample = kSamples[i];
        const SceneBGRA pixel = ActualPixel(pixels, sample.x, sample.y);
        NSString *name = [NSString stringWithUTF8String:sample.name];
        samples[name] = @{
            @"x": @(sample.x),
            @"y": @(sample.y),
            @"bgra": @[@(pixel.b), @(pixel.g), @(pixel.r), @(pixel.a)],
            @"rgba": [NSString stringWithFormat:@"#%02x%02x%02x%02x",
                pixel.r, pixel.g, pixel.b, pixel.a],
        };
    }
    return samples;
}

static NSDictionary *BoundsReport(GlyphBounds bounds) {
    if (!bounds.found) return @{@"found": @NO, @"nonBackgroundPixels": @0};
    return @{
        @"found": @YES,
        @"minX": @(bounds.minX), @"minY": @(bounds.minY),
        @"maxX": @(bounds.maxX), @"maxY": @(bounds.maxY),
        @"width": @(bounds.maxX - bounds.minX + 1),
        @"height": @(bounds.maxY - bounds.minY + 1),
        @"nonBackgroundPixels": @(bounds.pixelCount),
    };
}

static NSDictionary *FontReport(CTFontRef font) {
    NSDictionary *sourceAttributes = [[NSFileManager defaultManager]
        attributesOfItemAtPath:kBundledFontPath error:NULL];
    NSString *postScriptName = CFBridgingRelease(CTFontCopyPostScriptName(font));
    NSString *familyName = CFBridgingRelease(CTFontCopyFamilyName(font));
    NSString *fullName = CFBridgingRelease(CTFontCopyFullName(font));
    NSURL *url = CFBridgingRelease(CTFontCopyAttribute(font, kCTFontURLAttribute));
    NSData *head = CFBridgingRelease(CTFontCopyTable(font, kCTFontTableHead, 0));
    uint32_t revision = 0;
    if (head.length >= 8) {
        const uint8_t *bytes = head.bytes;
        revision = ((uint32_t)bytes[4] << 24) | ((uint32_t)bytes[5] << 16) |
            ((uint32_t)bytes[6] << 8) | bytes[7];
    }
    const CGRect fontBounds = CTFontGetBoundingBox(font);
    UniChar characters[] = {0x9e3f, 0x8499};
    CGGlyph glyphs[2] = {0};
    const BOOL mapped = CTFontGetGlyphsForCharacters(font, characters, glyphs, 2);
    CGSize advances[2] = {CGSizeZero, CGSizeZero};
    CGRect glyphBounds[2] = {CGRectZero, CGRectZero};
    CTFontGetAdvancesForGlyphs(font, kCTFontOrientationHorizontal, glyphs, advances, 2);
    CTFontGetBoundingRectsForGlyphs(font, kCTFontOrientationHorizontal, glyphs, glyphBounds, 2);

    NSAttributedString *attributed = [[NSAttributedString alloc] initWithString:@"鸿蒙"
        attributes:@{(__bridge NSString *)kCTFontAttributeName: (__bridge id)font}];
    CTLineRef line = CTLineCreateWithAttributedString((__bridge CFAttributedStringRef)attributed);
    CGFloat lineAscent = 0, lineDescent = 0, lineLeading = 0;
    const double lineWidth = line ? CTLineGetTypographicBounds(line,
        &lineAscent, &lineDescent, &lineLeading) : 0;
    CFArrayRef runs = line ? CTLineGetGlyphRuns(line) : NULL;
    const CFIndex runCount = runs ? CFArrayGetCount(runs) : 0;
    CFIndex lineGlyphCount = 0;
    for (CFIndex i = 0; i < runCount; i++) {
        CTRunRef run = (CTRunRef)CFArrayGetValueAtIndex(runs, i);
        lineGlyphCount += CTRunGetGlyphCount(run);
    }
    const CGRect linePathBounds = line ? CTLineGetBoundsWithOptions(line,
        kCTLineBoundsUseGlyphPathBounds) : CGRectZero;
    if (line) CFRelease(line);

    return @{
        @"creationAPI": @"CGDataProviderCreateWithData + CGFontCreateWithDataProvider + CTFontCreateWithGraphicsFont",
        @"sourcePath": kBundledFontPath,
        @"sourceByteCount": sourceAttributes[NSFileSize] ?: @0,
        @"systemFontFallback": @NO,
        @"postScriptName": postScriptName ?: @"",
        @"familyName": familyName ?: @"",
        @"fullName": fullName ?: @"",
        @"fontRevision": @(revision / 65536.0),
        @"pointSize": @(CTFontGetSize(font)),
        @"url": url.path ?: @"",
        @"unitsPerEm": @(CTFontGetUnitsPerEm(font)),
        @"ascent": @(CTFontGetAscent(font)),
        @"descent": @(CTFontGetDescent(font)),
        @"leading": @(CTFontGetLeading(font)),
        @"capHeight": @(CTFontGetCapHeight(font)),
        @"xHeight": @(CTFontGetXHeight(font)),
        @"boundingBox": @[@(fontBounds.origin.x), @(fontBounds.origin.y),
            @(fontBounds.size.width), @(fontBounds.size.height)],
        @"charactersMapped": @(mapped),
        @"glyphIDs": @[@(glyphs[0]), @(glyphs[1])],
        @"advances": @[@(advances[0].width), @(advances[1].width)],
        @"glyphBoundingBoxes": @[
            @[@(glyphBounds[0].origin.x), @(glyphBounds[0].origin.y),
                @(glyphBounds[0].size.width), @(glyphBounds[0].size.height)],
            @[@(glyphBounds[1].origin.x), @(glyphBounds[1].origin.y),
                @(glyphBounds[1].size.width), @(glyphBounds[1].size.height)],
        ],
        @"line": @{
            @"typographicWidth": @(lineWidth),
            @"ascent": @(lineAscent), @"descent": @(lineDescent), @"leading": @(lineLeading),
            @"runCount": @(runCount), @"glyphCount": @(lineGlyphCount),
            @"glyphPathBounds": @[@(linePathBounds.origin.x), @(linePathBounds.origin.y),
                @(linePathBounds.size.width), @(linePathBounds.size.height)],
        },
        @"metricNote": @"All values are measured from the actual macOS CoreText font. "
            "No Harmony metric is assumed and no font-metric tolerance is built into the "
            "reference. A cross-platform difference must be diagnosed from the real font "
            "revision, glyph mapping, advances, baseline and rasterizer output.",
    };
}

static BOOL WritePNG(NSURL *url, NSData *readback, NSError **error) {
    CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)readback);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!provider || !colorSpace) {
        if (provider) CGDataProviderRelease(provider);
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        return NO;
    }
    const CGBitmapInfo bitmapInfo =
        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little;
    CGImageRef image = CGImageCreate(kSceneWidth, kSceneHeight, 8, 32,
        kSceneWidth * 4, colorSpace, bitmapInfo, provider, NULL, false,
        kCGRenderingIntentDefault);
    CGDataProviderRelease(provider);
    CGColorSpaceRelease(colorSpace);
    if (!image) return NO;
    CGImageDestinationRef destination = CGImageDestinationCreateWithURL(
        (__bridge CFURLRef)url, CFSTR("public.png"), 1, NULL);
    if (!destination) {
        CGImageRelease(image);
        return NO;
    }
    CGImageDestinationAddImage(destination, image, NULL);
    const BOOL success = CGImageDestinationFinalize(destination);
    if (!success && error) {
        *error = [NSError errorWithDomain:@"HarmoniosScene3" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"CGImageDestinationFinalize failed"}];
    }
    CFRelease(destination);
    CGImageRelease(image);
    return success;
}

static BOOL WriteArtifacts(NSData *readback, const uint8_t *pixels,
    size_t nonzeroPixels, size_t nonzeroBytes, uint64_t hash,
    size_t pixelMismatches, size_t glyphBoundaryMismatches, BOOL hashMatches,
    CTFontRef font, NSError **error) {
    NSURL *directory = [NSURL fileURLWithPath:kArtifactDirectory isDirectory:YES];
    if (![[NSFileManager defaultManager] createDirectoryAtURL:directory
            withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    if (![readback writeToURL:[directory URLByAppendingPathComponent:@"reference.bgra"]
            options:NSDataWritingAtomic error:error]) return NO;
    if (!WritePNG([directory URLByAppendingPathComponent:@"reference.png"], readback, error)) {
        if (error && !*error) {
            *error = [NSError errorWithDomain:@"HarmoniosScene3" code:2
                userInfo:@{NSLocalizedDescriptionKey: @"PNG encoding failed"}];
        }
        return NO;
    }
    NSDictionary *metadata = @{
        @"backend": @"Apple Metal (native macOS CARenderer bundled-font reference)",
        @"operatingSystem": NSProcessInfo.processInfo.operatingSystemVersionString,
        @"scene": @3,
        @"width": @(kSceneWidth), @"height": @(kSceneHeight),
        @"pixelFormat": @"BGRA8Unorm",
        @"bytes": @(kSceneByteCount), @"bytesPerRow": @(kSceneWidth * 4),
        @"nonzeroPixels": @(nonzeroPixels), @"nonzeroBytes": @(nonzeroBytes),
        @"fnv1a": [NSString stringWithFormat:@"%016llx", (unsigned long long)hash],
        @"expectedFnv1a": kExpectedReferenceHash,
        @"hashMatches": @(hashMatches),
        @"pixelMismatches": @(pixelMismatches),
        @"strictPixelCount": @(kSceneWidth * kSceneHeight),
        @"glyphBoundaryMismatches": @(glyphBoundaryMismatches),
        @"root": @{
            @"bounds": @[@0, @0, @256, @256],
            @"backgroundColor": @"CGColorCreateGenericRGB(0.1,0.1,0.2,1)",
            @"nativeBackgroundBGRA": @[@66, @35, @34, @255],
            @"geometryFlipped": @NO,
        },
        @"textLayer": @{
            @"class": @"CATextLayer",
            @"frame": @[@16, @16, @224, @64],
            @"string": @"鸿蒙",
            @"fontSize": @32,
            @"foregroundColor": @"opaque white (kCGColorWhite)",
            @"alignmentMode": @"left",
            @"wrapped": @NO,
            @"contentsScale": @1,
            @"transform": @"identity (no corrective flip added)",
        },
        @"glyphBoundsDefinition": @"Any pixel whose four BGRA channels differ from "
            "native root BGRA(66,35,34,255); coordinates are zero-based readback texels.",
        @"glyphBounds": BoundsReport(MeasureNonBackground(pixels, 0, kSceneWidth - 1)),
        @"characterGlyphBounds": @{
            @"hong": BoundsReport(MeasureNonBackground(pixels, 16, 47)),
            @"meng": BoundsReport(MeasureNonBackground(pixels, 48, 79)),
        },
        @"font": FontReport(font),
        @"samples": SampleReport(pixels),
        @"referenceValidation": @"Every one of 65,536 pixels is compared with the embedded "
            "native glyph-rectangle BGRA template or the exact scene0 background. Nonzero "
            "coverage alone is never accepted.",
        @"source": @"tests/ca_renderer_scene3_bundled.m",
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:metadata
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:error];
    if (!json) return NO;
    return [json writeToURL:[directory URLByAppendingPathComponent:@"reference.json"]
        options:NSDataWritingAtomic error:error];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 3 && strcmp(argv[1], "--check-probe-report") == 0) {
            NSString *path = [NSString stringWithUTF8String:argv[2]];
            return path ? CheckProbeReport(path) : ProbeReportFailure(@"report path is not valid UTF-8");
        }
        if (argc != 1) {
            fprintf(stderr, "usage: %s [--check-probe-report report.json]\n", argv[0]);
            return 64;
        }
        if (!ValidateReferenceTemplate()) return 8;
        @try {
            id<MTLDevice> device = MTLCreateSystemDefaultDevice();
            if (!device) { fprintf(stderr, "scene3 key error: no Metal device\n"); return 2; }
            MTLTextureDescriptor *descriptor = [MTLTextureDescriptor
                texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                width:kSceneWidth height:kSceneHeight mipmapped:NO];
            descriptor.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
            id<MTLTexture> texture = [device newTextureWithDescriptor:descriptor];
            if (!texture) { fprintf(stderr, "scene3 key error: texture creation failed\n"); return 3; }
            id<MTLCommandQueue> queue = [device newCommandQueue];
            if (!queue) { fprintf(stderr, "scene3 key error: command queue creation failed\n"); return 3; }
            CARenderer *renderer = [CARenderer rendererWithMTLTexture:texture
                options:@{kCARendererMetalCommandQueue: queue}];
            if (!renderer) { fprintf(stderr, "scene3 key error: CARenderer refused texture\n"); return 3; }
            NSError *fontError = nil;
            CTFontRef font = CreateBundledFont(&fontError);
            if (!font) {
                fprintf(stderr, "scene3 bundled key error: bundled font creation failed: %s\n",
                    fontError.localizedDescription.UTF8String ?: "invalid font data");
                return 3;
            }
            NSString *postScriptName = CFBridgingRelease(CTFontCopyPostScriptName(font));
            if (![postScriptName isEqualToString:@"PingFangSC-Regular"] ||
                    CTFontGetSize(font) != 32.0 || CTFontGetUnitsPerEm(font) != 2048) {
                fprintf(stderr, "scene3 bundled key error: invalid in-memory font: "
                    "postScriptName=%s size=%.6fpt unitsPerEm=%u\n",
                    postScriptName.UTF8String ?: "", CTFontGetSize(font),
                    (unsigned)CTFontGetUnitsPerEm(font));
                CFRelease(font);
                return 3;
            }
            UniChar characters[] = {0x9e3f, 0x8499};
            CGGlyph glyphs[2] = {0};
            if (!CTFontGetGlyphsForCharacters(font, characters, glyphs, 2) ||
                    glyphs[0] != kExpectedGlyphIDs[0] || glyphs[1] != kExpectedGlyphIDs[1]) {
                fprintf(stderr, "scene3 bundled key error: glyph mapping mismatch: "
                    "got=(%u,%u), expected=(%u,%u)\n", glyphs[0], glyphs[1],
                    kExpectedGlyphIDs[0], kExpectedGlyphIDs[1]);
                CFRelease(font);
                return 3;
            }
            NSDictionary *sourceAttributes = [[NSFileManager defaultManager]
                attributesOfItemAtPath:kBundledFontPath error:NULL];
            printf("bundledFont=%s bytes=%llu unitsPerEm=%u glyphIDs=(%u,%u)\n",
                postScriptName.UTF8String,
                (unsigned long long)[sourceAttributes[NSFileSize] unsignedLongLongValue],
                (unsigned)CTFontGetUnitsPerEm(font),
                (unsigned)glyphs[0], (unsigned)glyphs[1]);
            CALayer *root = CreateScene3(font);
            CATextLayer *text = (CATextLayer *)root.sublayers.firstObject;
            if (![text isKindOfClass:[CATextLayer class]] || root.sublayers.count != 1 ||
                !CGRectEqualToRect(text.frame, CGRectMake(16, 16, 224, 64)) ||
                ![text.string isEqual:@"鸿蒙"] || text.fontSize != 32.0 ||
                text.font != font ||
                !CGColorEqualToColor(text.foregroundColor,
                    CGColorGetConstantColor(kCGColorWhite)) ||
                CGColorGetAlpha(text.foregroundColor) != 1.0 ||
                ![text.alignmentMode isEqualToString:kCAAlignmentLeft] || text.wrapped ||
                text.contentsScale != 1.0 || root.geometryFlipped || text.geometryFlipped ||
                !CATransform3DIsIdentity(text.transform)) {
                fprintf(stderr, "scene3 key error: CATextLayer scene invariant changed\n");
                CFRelease(font);
                return 3;
            }
            renderer.layer = root;
            renderer.bounds = CGRectMake(0, 0, kSceneWidth, kSceneHeight);
            [CATransaction flush];
            [renderer beginFrameAtTime:CACurrentMediaTime() timeStamp:NULL];
            [renderer addUpdateRect:renderer.bounds];
            [renderer render];
            [renderer endFrame];
            id<MTLCommandBuffer> fence = [queue commandBuffer];
            if (!fence) {
                fprintf(stderr, "scene3 key error: fence creation failed\n");
                CFRelease(font);
                return 5;
            }
            [fence commit];
            [fence waitUntilCompleted];
            NSError *fenceError = fence.error;
            if (fence.status != MTLCommandBufferStatusCompleted || fenceError) {
                fprintf(stderr, "scene3 key error: fence status=%ld error=%s\n",
                    (long)fence.status, fenceError.localizedDescription.UTF8String ?: "none");
                CFRelease(font);
                return 5;
            }
            NSMutableData *readback = [NSMutableData dataWithLength:kSceneByteCount];
            uint8_t *pixels = readback.mutableBytes;
            if (!pixels) {
                fprintf(stderr, "scene3 key error: readback allocation failed\n");
                CFRelease(font);
                return 6;
            }
            [texture getBytes:pixels bytesPerRow:kSceneWidth * 4
                fromRegion:MTLRegionMake2D(0, 0, kSceneWidth, kSceneHeight) mipmapLevel:0];
            size_t nonzeroPixels = 0, nonzeroBytes = 0;
            for (size_t i = 0; i < kSceneByteCount; i += 4) {
                BOOL nonzero = NO;
                for (unsigned channel = 0; channel < 4; channel++) {
                    if (!pixels[i + channel]) continue;
                    nonzeroBytes++;
                    nonzero = YES;
                }
                if (nonzero) nonzeroPixels++;
            }
            const uint64_t hash = HashPixels(pixels);
            NSString *actualHash = [NSString stringWithFormat:@"%016llx", (unsigned long long)hash];
            const BOOL hashMatches = [actualHash isEqualToString:kExpectedReferenceHash];
            printf("device=%s nonzeroPixels=%zu nonzeroBytes=%zu hash=%s expected=%s\n",
                device.name.UTF8String, nonzeroPixels, nonzeroBytes,
                actualHash.UTF8String, kExpectedReferenceHash.UTF8String);
            for (size_t i = 0; i < sizeof(kSamples) / sizeof(kSamples[0]); i++) {
                const SceneSample sample = kSamples[i];
                const SceneBGRA pixel = ActualPixel(pixels, sample.x, sample.y);
                printf("sample %s (%u,%u) BGRA(%u,%u,%u,%u)\n", sample.name,
                    sample.x, sample.y, pixel.b, pixel.g, pixel.r, pixel.a);
            }
            const size_t pixelMismatches = CheckNativePixels(pixels);
            const size_t glyphBoundaryMismatches = CheckGlyphBounds(pixels);
            NSError *outputError = nil;
            const BOOL artifactsWritten = WriteArtifacts(readback, pixels,
                nonzeroPixels, nonzeroBytes, hash, pixelMismatches,
                glyphBoundaryMismatches, hashMatches, font, &outputError);
            CFRelease(font);
            if (!artifactsWritten) {
                fprintf(stderr, "scene3 key error: cannot write artifacts: %s\n",
                    outputError.localizedDescription.UTF8String ?: "unknown I/O error");
                return 6;
            }
            if (!hashMatches) fprintf(stderr, "scene3: full-frame FNV-1a64 differs from native reference\n");
            if (pixelMismatches || glyphBoundaryMismatches || !hashMatches) return 4;
            printf("scene3: all %u pixels matched native CATextLayer text/background; "
                "glyph bounds and all probe samples passed; artifacts=%s\n",
                kSceneWidth * kSceneHeight, kArtifactDirectory.UTF8String);
            return 0;
        } @catch (NSException *exception) {
            fprintf(stderr, "scene3 key error: %s: %s\n",
                exception.name.UTF8String, exception.reason.UTF8String);
            return 7;
        }
    }
}
