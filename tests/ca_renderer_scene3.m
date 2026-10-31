#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const unsigned kSceneWidth = 256;
static const unsigned kSceneHeight = 256;
static const size_t kSceneByteCount = kSceneWidth * kSceneHeight * 4;
static NSString *const kArtifactDirectory = @"artifacts/mac-ca-scene3";
static NSString *const kExpectedReferenceHash = @"44f480c8570de2e8";

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
// They cover opaque interiors, antialiasing and several background regions.
static const SceneSample kSamples[] = {
    {"root", 8, 8},
    {"textLayerBackground", 16, 16},
    {"hongInk", 18, 44},
    {"mengInk", 62, 43},
    {"hongAntialias", 24, 52},
    {"mengAntialias", 64, 52},
    {"afterText", 80, 64},
};

// Lossless Apple M1 Pro / macOS 27.0.1 CARenderer reference. The rectangle is
// the complete non-background glyph extent, including background holes. Bytes
// are raw BGRA read back from the Metal texture, not a CoreGraphics rasterizer.
static const unsigned kGlyphMinX = 17;
static const unsigned kGlyphMinY = 42;
static const unsigned kGlyphMaxX = 78;
static const unsigned kGlyphMaxY = 72;
static const unsigned kGlyphWidth = kGlyphMaxX - kGlyphMinX + 1;
static const unsigned kGlyphHeight = kGlyphMaxY - kGlyphMinY + 1;
static const size_t kGlyphNonBackgroundPixels = 1024;
static const char kExpectedGlyphBGRA[] =
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff6d5554ff715a59ff5e44"
    "43ff472928ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "432524ff7a6564ff928080ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff422322ff6f5857fff2f0f0ffefececffd4cdcdffb5a9a8ff664c4cff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff948281ffaea0a0ff6a5251ff422322ff422322ff422322ff422322ff422322ff422322ff4e3130fffbfbfbffffffffffffff"
    "fffffefefeffcbc3c2ff6e5655ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff786261ff4b2d2cff422322ff"
    "8e7b7afffffffffff2f0f0ff462827ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff422322ffa89a9afffffffffffffffffffffffffffffffffffbfafaff8e7b7aff422322ff422322ff422322ff"
    "422322ff422322ff614746fffaf9f9ffffffffffffffffffe4e0e0ffa29292ff5e4443ff422322ff422322ff422322ff695150ffc1b7b6ffc7bebdfff1ef"
    "eefffffffffffffffffff8f6f6ff583d3cff422322ff422322ff422322ff422322ff422322ff422322ff4c2e2dffb6aaaaffffffffffc5bcbbff432524ff"
    "523635fffcfcfcffffffffff7d6867ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff422322ff624847ff6a5251ff69504fff826d6dffd5cfcefffffffffff5f3f3ff4a2c2cff422322ff422322ff"
    "422322ff422322ff4f3231ff897675ffc6bdbcfff9f8f8ffffffffffffffffffffffffffd9d3d3ff968484ff513433ff422322ff422322ff422322ff4325"
    "24ff6a5251fff5f3f3ffffffffff9b8b8aff422322ff422322ff422322ff422322ff422322ff6e5655ffe6e2e1ffffffffffffffffffeae7e7ff604545ff"
    "422322ffc8bfbfffffffffffc1b7b6ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff462827ffefececffffffffff745e5dff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff4b2d2cff816c6cffbeb3b3fff5f4f4fffffffffffffffffff5f4f4ff9c8c8cff492b2aff422322ff4223"
    "22ff422322ffa89a9affffffffffbfb5b4ff422322ff422322ff422322ff422322ffa39494fffdfcfcfffffffffffbfafaffa79898ff4a2c2cff422322ff"
    "422322ff836f6efffffffffff9f8f8ff4c2f2eff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ffbfb4b4ffffffffff948281ff422322ff422322ff"
    "422322ff422322ff422322ff472928ff4b2d2cff422322ff422322ff422322ff472928ff7a6463ffb9adadfffbfafaffffffffffeae7e7ff897675ff4325"
    "24ff422322ff897675ffffffffffd5ceceff422322ff422322ff422322ff968484ffffffffffffffffffccc3c3ff5f4544ff422322ff422322ff422322ff"
    "422322ff492b2afff5f3f3ffffffffff8a7776ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff432524ff492c"
    "2bff492c2bff492c2bff492c2bff492c2bff492c2bff492c2bff492c2bff492c2bff462827ff422322ffa29393ffffffffffb0a3a2ff422322ff422322ff"
    "422322ff422322ff422322ffa09190fffbfbfbffcfc7c7ff9a8a89ff644b4aff422322ff422322ff422322ff593e3dffb6aaaafffdfcfcffffffffffdcd7"
    "d6ff755f5eff796362ffffffffffddd7d7ff422322ff422322ff6c5453fffbfbfbffffffffffaa9d9cff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ffb6aaaaffffffffffcdc5c5ff422322ff422322ff432524ff422322ff422322ff422322ff422322ff422322ff422322ff664d4cffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaea0a0ff422322ff917f7fffffffffffbfb4b4ff422322ff422322ff"
    "422322ff422322ff462726ffd1c9c9fffdfcfcffffffffffffffffffffffffffe2ddddff9f8f8eff5b403fff422322ff422322ff5d4342ffbcb1b1fffefd"
    "fdffffffffffe1dddcffffffffffddd7d7ff422322ff513433ffeae7e7ffffffffffbdb2b2ff432423ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff715a59fffffffffffefdfdff543938ff422322ff9b8b8affd8d1d1ff958483ff543837ff422322ff422322ff422322ff664d4cffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffaea0a0ff422322ff857171ffffffffffcdc4c4ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff4c2f2eff7a6463ffaa9c9bffe3dedeffffffffffffffffffffffffffcec6c6ff786261ff432423ff422322ff6349"
    "48ffc3b9b9fffffffffffffffffff0eeeeff907e7dffcbc3c2ffffffffffcdc5c5ff462827ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff432423ffe9e5e5ffffffffff968484ff422322ffcac1c1fffffffffffffffffffefdfdffcdc4c4ff8a7776ff4d302fff442625ff4f32"
    "31ff4f3231ff4f3231ff4f3231ff4f3231ff4f3231ff4f3231ff4f3231ff4f3231ff492c2bff422322ff7c6666ffffffffffdad4d4ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff624847ff9f8f8effe1dcdcffffffffffffffffffdfdadaff816c6cff4223"
    "22ff422322ffc0b6b5fffffffffffffffffffffffffffffffffffbfbfbff634948ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ffa59796ffffffffffd9d3d3ff422322ff684f4eff998988ffc8bfbffff5f3f3fffffffffffffffffff9f8f8ffc1b7b7ff7f6a"
    "69ff432423ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff796362ffffffffffe3dedeff422322ff422322ff"
    "422322ff422322ff422322ff573b3affe1dddcffb3a6a6ff7b6565ff492c2bff422322ff422322ff422322ff715a59ffc0b6b5fffcfcfcffffffffffd0c8"
    "c8ff715959fff8f7f7ffffffffff938180ffc8bfbffffffffffffffffffff7f6f6ff998887ff452625ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff604646ffffffffffffffffff5f4544ff422322ff422322ff422322ff9c8c8cfffffffffff2f0f0fff7f6f6ffffffffffffff"
    "ffff462827ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff765f5fffffffffffe8e4e4ff422322ff422322ff"
    "422322ff422322ff422322ffb7ababfffffffffffffffffffffffffffaf9f9ffcac2c1ff928080ff4f3231ff422322ff422322ff5c4140ffbfb5b4fffefe"
    "feffffffffffffffffffcdc4c4ff422322ff422322ff644b4affbdb2b2fffdfcfcffffffffffddd7d7ff6c5453ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ffd9d3d3ffeeebebff776060ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff4c2f2eff917e7effded8"
    "d8ff462827ff8c7979ff9c8b8bff9c8b8bff9c8b8bff9c8b8bff9c8b8bff9c8b8bff9c8b8bff9c8b8bffb6aaa9ffffffffffece9e9ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff5c4140ff826e6dffac9e9effded8d8fffefefefffffffffff7f6f6ffaea1a1ff5a3f3fff422322ff432423ffbbb0"
    "affffffffffffefdfdff6c5453ff422322ff422322ff422322ff422322ff6e5655ffe6e2e1fffffffffffefefeffb3a6a6ff462726ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff5b403fff462726ff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1efeeff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff523635ff8b7878ffccc3c3fffdfcfcfffdfcfcffbfb5b4ffc5bcbbffffff"
    "fffffbfafaff826d6dff422322ff422322ff422322ff422322ff422322ff422322ff4c2e2dffb7ababffffffffff9c8b8bff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffffcac2c1ffb5a9a8ffb5a9a8ffb5a9a8ffb5a9a8ffb5a9a8ffb5a9a8ffb5a9a8ffb5a9a8ffaea1a1ff422322ff422322ff"
    "422322ff422322ff563a39ff624847ff624847ff624847ff624847ff624847ff624847ff624847ff624847ff786261ffcac2c1fffffffffffffffffffefe"
    "feff968484ff624847ff624847ff624847ff624847ff624847ff624847ff624847ff624847ff624847ff836f6eff624847ff624847ff563a39ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ffb9aeaeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb9aeaeff422322ff"
    "422322ff422322ff422322ff422322ff695150ff8e7c7bff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ff422322ff422322ffbcb1b1ffcbc3c2ffafa2a1ff7d6766ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff9c8b8bffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9"
    "c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ffd0c9c8ff9c8b8bff422322ff"
    "422322ff422322ff422322ff5f4544fff0eeeeffffffffff887473ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ff422322ff614746ffffffffffffffffffffffffffffffffff998988ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff5e4443ffe9e5e5ffffffffffe7e2e2ff553939ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ff422322ff533736ff6f5857ff6f5756ff9f8f8efffefefefff6f5f5ff472928ff422322ff422322ff422322ff"
    "422322ff422322ff503332ffe7e3e3ffe7e3e3ff5b403fff422322ff553939ff867272ff867272ff867272ff867272ff867272ff867272ff867272ff8672"
    "72ff867272ff867272ff867272ff867272ff867272ff867272ff867272ff867272ff553939ff422322ff604646ffe7e3e3ffe7e3e3ff4b2d2cff422322ff"
    "422322ff6b5252fff0eeeeffffffffffece9e9ff5b403fff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ff422322ff422322ff4c2e2dff432524ff422322ffd4cdcdffffffffff674e4dff422322ff422322ff422322ff"
    "422322ff422322ff523635ffffffffffffffffff5e4443ff422322ff786261ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff786261ff422322ff654c4bffffffffffffffffff4c2f2eff422322ff"
    "664c4cfff8f6f6ffffffffffe4e0e0ff5c4140ff422322ff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ff422322ff422322ffc6bdbcffd1c9c9ff4b2d2cffb6aaa9ffffffffff857170ff422322ff422322ff422322ff"
    "422322ff422322ff523635ffffffffffffffffff5e4443ff422322ff563a39ff877373ff877373ff877373ff877373ff877373ff877373ff877373ff8773"
    "73ff877373ff877373ff877373ff877373ff877373ff877373ff877373ff877373ff563a39ff422322ff654c4bffffffffffffffffff4c2f2eff422322ff"
    "432524ffb5a9a8ffd8d1d1ff523534ff422322ff422322ff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ff422322ff988786ffffffffffbdb2b2ff422322ffa29393ffffffffff9c8b8bff422322ff422322ff422322ff"
    "422322ff422322ff523635ffffffffffffffffff5e4443ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff654c4bffffffffffffffffff4c2f2eff422322ff"
    "422322ff432423ff482a29ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ff806b6bfffefdfdffddd7d7ff4b2d2cff422322ff948281ffffffffffaea0a0ff422322ff422322ff422322ff"
    "422322ff422322ff523635ffffffffffffffffffe6e2e1ffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dd"
    "dcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe1dddcffe7e2e2ffffffffffffffffff4c2f2eff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff9c8c8cffffffffffccc3c3ff422322ff422322ff4223"
    "22ff422322ffded8d8ffffffffff786261ffaea0a0ffe9e5e5ff563a39ff422322ff422322ff887574ffffffffffbfb4b4ff422322ff422322ff422322ff"
    "422322ff422322ff523635fffcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffefdfdfffffffffffffffffffcfcfcfffcfcfcfffcfcfcfffcfc"
    "fcfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffffffffffffffffffefdfdfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcfffcfcfcff4c2f2eff422322ff"
    "422322ff422322ff422322ff422322ff9f8f8effa19191ff422322ff492b2aff4c2f2eff4c2f2effa29393ffffffffffcfc7c7ff4c2f2eff4c2f2eff4a2c"
    "2cff422322ffded8d8ffffffffff786261ff422322ff492b2aff422322ff422322ff422322ff7e6968ffffffffffccc3c3ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff998988ffffffffffedeaeaff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ffe7e3e3ffffffffffa09190ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff8e7c7bffffffffffffffffff7c6666ffb6aaaaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd3cc"
    "ccff422322ffded8d8ffffffffffdcd7d6ffcdc5c5ffcdc5c5ffcdc5c5ffcdc5c5ffcdc5c5ffdcd7d6ffffffffffd7d0d0ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff998988ffffffffffedeaeaff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ffe7e3e3ffffffffffa09190ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff917e7efffefdfdffffffffffbcb1b1ff432524ffb6aaaaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd3cc"
    "ccff422322ffded8d8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe2ddddff422322ff422322ff422322ff"
    "422322ff422322ffb5a9a8ffc3b9b9ffc3b9b9ffc3b9b9ffc3b9b9ffc3b9b9ffc3b9b9ffdfdadafffffffffffaf9f9ffc3b9b9ffc3b9b9ffc3b9b9ffc3b9"
    "b9ffc3b9b9ffc3b9b9ffc3b9b9ffc3b9b9fff8f6f6ffffffffffe1dcdcffc3b9b9ffc3b9b9ffc3b9b9ffc3b9b9ffc3b9b9ffc3b9b9ffb9adadff422322ff"
    "422322ffa59796ffffffffffffffffffc4babaff452625ff422322ff4f3332ff583d3cff583d3cff583d3cff583d3cff583d3cff583d3cff583d3cff5337"
    "36ff422322ff776160ff826e6dff9e8e8dfffffffffffaf9f9ff857171ff826e6dff826e6dff826e6dff826e6dff7b6565ff422322ff422322ff422322ff"
    "422322ff422322ffeae7e7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0eeeeff422322ff"
    "664d4cfffaf9f9ffffffffffb1a4a4ff442625ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff452625fff2efefffffffffff7b6565ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff6a5251ff6f5756ff6f5756ff6f5756ff6f5756ff6f5756ff6f5756ffb2a5a5fffffffffff2efefff6f5756ff6f5756ff6f5756ff6f57"
    "56ff6f5756ff6f5756ff6f5756ff6f5756ffedeaeaffffffffffb6aaaaff6f5756ff6f5756ff6f5756ff6f5756ff6f5756ff6f5756ff6c5353ff422322ff"
    "422322ff745e5dff978686ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ffb6aaaaffffffffffc6bdbcff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff998988ffffffffffedeaeaff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ffe7e3e3ffffffffffa09190ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff5a3f3fff6e5655ff523534ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff"
    "422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff583d3cff725b5aff6d5554ff422322ff422322ff422322ff4223"
    "22ff422322ff422322ff422322ff422322ff664d4cff6c5353ff573b3aff422322ff422322ff422322ff422322ff422322ff422322ff422322ff422322ff";

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
        17, 42, 78, 72, 1024);
    mismatches += CheckOneGlyphBounds("hong",
        MeasureNonBackground(pixels, 16, 47), 17, 43, 45, 72, 450);
    mismatches += CheckOneGlyphBounds("meng",
        MeasureNonBackground(pixels, 48, 79), 50, 42, 78, 72, 574);
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
        @"requestedPostScriptName": @"PingFangSC-Regular",
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
        @"backend": @"Apple Metal (native macOS CARenderer reference)",
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
        @"source": @"tests/ca_renderer_scene3.m",
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
            CTFontRef font = CTFontCreateWithName(CFSTR("PingFangSC-Regular"), 32.0, NULL);
            if (!font) { fprintf(stderr, "scene3 key error: PingFang SC creation failed\n"); return 3; }
            NSString *postScriptName = CFBridgingRelease(CTFontCopyPostScriptName(font));
            if (![postScriptName isEqualToString:@"PingFangSC-Regular"] || CTFontGetSize(font) != 32.0) {
                fprintf(stderr, "scene3 key error: font substitution/metric mismatch: requested "
                    "PingFangSC-Regular 32pt, got %s %.6fpt\n",
                    postScriptName.UTF8String, CTFontGetSize(font));
                CFRelease(font);
                return 3;
            }
            CALayer *root = CreateScene3(font);
            CATextLayer *text = (CATextLayer *)root.sublayers.firstObject;
            if (![text isKindOfClass:[CATextLayer class]] || root.sublayers.count != 1 ||
                !CGRectEqualToRect(text.frame, CGRectMake(16, 16, 224, 64)) ||
                ![text.string isEqual:@"鸿蒙"] || text.fontSize != 32.0 ||
                CGColorGetAlpha(text.foregroundColor) != 1.0 ||
                ![text.alignmentMode isEqualToString:kCAAlignmentLeft] || text.wrapped ||
                text.contentsScale != 1.0) {
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
