// Native macOS reference for scene 3's CoreText-bitmap CALayer.contents path.
// CoreText and CoreGraphics perform all text shaping and rasterization. The
// resulting CGImage is rendered through a real CARenderer/Metal texture.
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
#include <unistd.h>

static const unsigned kSceneWidth = 256;
static const unsigned kSceneHeight = 256;
static const unsigned kTextWidth = 224;
static const unsigned kTextHeight = 64;
static const size_t kSceneByteCount = kSceneWidth * kSceneHeight * 4;
static NSString *const kArtifactDirectory = @"artifacts/mac-ca-scene3-coretext";
static NSString *const kBundledFontPath =
    @"harmonios/src/main/resources/rawfile/target/bundle/Fonts/PingFangSC.ttf";

// This is a CoreText-bitmap reference, not either of the old CATextLayer
// references. --generate-reference exists only to bootstrap a newly captured
// native reference; normal execution and probe-report checking are strict.
static NSString *const kExpectedReferenceHash = @"c5ef5395af310e3e";
static NSString *const kEncodedReferenceRuns =
    @"JCQCjnt6XEA/JDgERicmk4GAloSDiXR0JEQDfWdmhG9vgGppJRICWTw8Vjk4JSMEWTw8/////v7+ycC/JTgEVzs6////////8/LyJUMFRSYl////////////"
    @"UTQzJhEGWz8+7+zs/Pz8xry8e2RjRCQjJiMEjHl4////////4t7eJjIci3d2k4GAk4GAk4GAk4GAk4GAn4+P////////+fj4k4GAk4GAk4GAk4GAk4GAk4GA"
    @"k4GAlYOD////////////nIuKk4GAk4GAk4GAk4GAk4GAi3d2JxEH2tTU////////////////z8bGUzY1JyAMTC4tUjU0UjU02NLR////////rqCgUjU0UjU0"
    @"UjU0UjU0SCkoJzIc////////////////////////////////////////////////////////////////////////////////////////////////////////"
    @"////////KBEIfWhn1s/P////////////////6+joVTg3KCAM49/e////////////////////////////////////////i3d2KDIc////////////////////"
    @"////////////////////////////////////////////////////////////////////////////////////////////KRMZcVlY4t3d////////////6eXl"
    @"5eHh5eHh5eHh5eHh5eHh5eHh29XV6OTk////////////////////////////////////////jHl4KTIcmIeGoJCQoJCQoJCQoJCQoJCQq52d////////+fj4"
    @"oJCQoJCQoJCQoJCQoJCQoJCQoJCQopOS////////////qJqZoJCQoJCQoJCQoJCQoJCQmIeGKhQYTS8uwri38O7uxbu7////////////////////////////"
    @"/Pz86OTk////////5eHh+fj47uzr4t3d4t3d8O7u////////jXp5KjQZRicmRicmRicmRicmWz8+////////8/LyRicmRicmRicmRicmRicmRicmRicmSisq"
    @"////////////VTg3RicmRicmRicmRicmRCQjKxYRSCkon46O////////////////////////////9/b26OTk////////x76+////7+zsb1dWKygEpZaW////"
    @"////inZ2KzMao5ST////////////////////////////////////////////////////////////////////////////////////////////////z8fHLBID"
    @"kH19e2RjRSUkLBcVRSYlTjAvTjAv3NbW////////dV5dTjAvSywr6OTk////////+Pf3////////9PLyXUJBqZqa////////hnJxLDMaqpub////////////"
    @"////////////////////////////////////////////////////////////////////////////////////1s/PLREGf2lp////////7OnppJSUSywrLRoE"
    @"2dPS////////bFNSLSAM6OTk////////fmho8O3t////////3dfXuq6u////////gWxrLTMaqpub////////6+fn2NLR2NLR2NLR2NLR2NLR2NLR2NLR2NLR"
    @"2NLR2NLR2NLR2NLR2NLR2NLR2NLR2NLR2NLR2NLR4t7e////////1s/PLhEH6ubm////////////////5eDgb1ZWLhoE2dPS////////bFNSLiAM6OTk////"
    @"////XUJBbVVU/f39////8/HxzMPD////////dV1cLjMaqpub////////m4qKa1JRy8LCy8LCy8LCy8LCy8LCy8LCy8LCy8LCy8LCy8LCy8LCy8LCy8LCy8LC"
    @"y8LCy8LClIKCclpZ////////1s/PLxEIcltaysHB/////////////////f39YUdGLxoE2dPS////////bFNSLyAM6OTk////////XUJBblVVzsbF1M3NWz8+"
    @"2tPT////////ZkxLLzMaqpub////////m4qKhnJx////////////////////////////////////////////////////////////////vrOzclpZ////////"
    @"1s/PMBMGZkxL19HR////////7erqTjAvMBoE2dPS////////bFNSMCAM6OTk////////XUJB3djY////7+zsxbu7/Pv7/////v7+Sy0sMDMahnFwzMTEzMTE"
    @"e2VkhnJx////////////////////////////////////////////////////////////////vrOzUDIxl4aFl4aFfWdmMRQERygnrqCg////gGppMRoE2dPS"
    @"////////bFNSMSAL6OTk////////XUJBp5iX////////////////////19DQMTIcRSYlgGppgWxrgWxrgWxriXR0qpycqpycqpycqpycqpycqpycqpycqpyc"
    @"qpycqpycqpycqpycqpycqpycqpycqpyclIKCgWxrgWxrgWxrgWxrWTw8MhYBWz8+MhoE2dPS////////bFNSMiAL6OTk////////XUJBalBP7uvr////////"
    @"////4dzcXkJCMjIcYEVE////////////////////////////////////////////////////////////////////////////////////////////////////"
    @"////no2NMxoE2dPS////////bFNSMyAN6OTk////////vrOzs6ems6emx76+49/ez8fHtKens6ems6emmIeGMzIcYEVE////////////////////////////"
    @"////////////////////////////////////////////////////////////////////////////no2NNBYCe2VkTS8uNBoE2dPS////////bFNSNCAN6OTk"
    @"////////////////////////////////////////////6+fnNDIcTC4tqJmYqZqaqZqaqZqaqZqaqZqarJ6d2dPS////////////////////////ycC/qZqa"
    @"8vDw////////0srKqZqaqZqaxLm5////3NbWqZqabFNSNRUEYkhH////8/HxnIyLNRoE2dPS////////bFNSNR8ORicm6OTk////////////////////////"
    @"////////////////////5eDgNTUNVjo5b1dWiXR0t6uq8O3t////////////////////////////kX9+NUMEraCf////////zsbFNUgFblVV8O3t/////v7+"
    @"mIeGNhUEraCf////////39nZNhoT2dPS////////k4GAtKen9PLys6emg25ug25ug25ug25ug25ug25ug25ug25ukoB/////////3tnYNjIbXEFA4t3d+fj4"
    @"////////////////////////////////6ubm/f39/////////f39dFxcZElJ////////////ppeX+fj4////////////qpycNxQFSCko8vDw////////pJSU"
    @"NxoH2dPS////////////////////jHl4NykEZ05N////////2NLRNzMZ0svL////////////////////////6OXl0MjI3NbW/Pv7////////////////4t7e"
    @"Rygn1s/P////////////////////9vT0hXBwOBQZh3Ny////////////sKKi0MjI/f39////////////////////j3x8SSopSSopSSopSSopSSopSSopSSop"
    @"SSopeWJi////////z8bGODMYYEVE+fj4/v7+4dzcuKyrlIKCrJ6d29XV/////////////////v7+////////////jXp5g25t////////////////29XVXkJC"
    @"ORQZ0svL////////////////////////////////////////////////////////////////////////////////rqCg////////vLGxOTMRVjk4kH19opKR"
    @"tqmp1c7O9fPz/////////////////Pv7vLGxr6Gh/v7+////////zsbFOUUFycC/////////////dV1cOhMaalBP////////////////////////////4dzc"
    @"qZqa////////////////////////////////////////////////xry8////////qpubOjIZsaSk/////////////////////////////////Pv7tqqql4WE"
    @"4t7e/////////////////Pz8RicmWT089vT0////////9fPzbFNSOxMI19DQ////////7Onp2tPT+/r6wLW1cltaOxwRUTQz08zL1c7O1c7O1c7O1c7O1c7O"
    @"1c7O1c7O1c7O1c7O1c7O1c7OyL++////////l4aFOzITXkJC+Pf3////////////////6+fnwLW1o5STraCf4Nvb////////////////////////////WTw8"
    @"O0YGj3x8////////////8/Lyf2lpPBIHjHl4////////////iXR0Vzs6UzY1PCkEz8fH////////fWhnPDMSkoB/1s/PrqCgg25ucFhXi3d2v7S0+fj4////"
    @"////////////7+zsnIyL/Pv7////////aE9OPEcHnIyL////////////////xLm5Vjo5PREFTzEw8O3t////////19HRPSkE8vDw////////X0RDPTEUTjAv"
    @"a1JRhXBwno2Nuq6u5+Pj////////////////////////6OTkkoB/SSopVjk4////////////XEA/PUgHno2N////////////////9PLyjnt7PhEFsaSk////"
    @"/////v7+bFNSPiQJaU9PysHBoJCQemNjiXR0////////+Pf3RSYlPjENpJSU////////////////////////////////////4NraiHRzRSYlPkAFiHRz////"
    @"/////Pz8RicmPkkGkH199vX1////////////19DQPxAFSCko/Pv7////////u6+vPyQIbVVU////////////////////////ycDAPzETSywr4dzc////////"
    @"/////f393NbWsaSkhnFwWz8+fWdm5uLi1M3Nw7m4x76+/v7+////////5eHhP0oFWz8+zcXE////7+zsX0NCQBEEcFhX5eDg9vX1Vjo5QCUH6ubm////////"
    @"////////9vT0ZElJQDIFZUtKxLm5oJCQdV5dTC4tQDsJeWJi////////////////////////////jXp5QEwCgm1sZEpJQRICSisqY0hIQSUGf2lptKenxr29"
    @"vbKxnIyLYkhHQTsIRygn9PLy////////////////5N/fjXp5QjwFUjU0YkhHcFhXe2VkZEpJ";

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

static const SceneSample kSamples[] = {
    {"root", 8, 8},
    {"textLayerBackground", 16, 16},
    {"hongInk", 18, 44},
    {"mengInk", 62, 43},
    {"hongAntialias", 24, 52},
    {"mengAntialias", 64, 52},
    {"afterText", 80, 64},
};

static const CGGlyph kExpectedGlyphIDs[] = {28878, 22312};
static const GlyphBounds kExpectedAllGlyphBounds = {
    .found = YES, .minX = 16, .minY = 36, .maxX = 78, .maxY = 66, .pixelCount = 1261,
};
static const GlyphBounds kExpectedHongGlyphBounds = {
    .found = YES, .minX = 16, .minY = 36, .maxX = 44, .maxY = 65, .pixelCount = 541,
};
static const GlyphBounds kExpectedMengGlyphBounds = {
    .found = YES, .minX = 49, .minY = 36, .maxX = 78, .maxY = 66, .pixelCount = 720,
};

static SceneBGRA RootPixel(void) {
    // Apple CARenderer's color-managed BGRA8Unorm value for
    // CGColorCreateGenericRGB(0.1,0.1,0.2,1), also used by scenes 0/1/2.
    return (SceneBGRA){66, 35, 34, 255};
}

static SceneBGRA BitmapBackgroundPixel(void) {
    // The same CGColor inside the DeviceRGB bitmap is color-managed through
    // CGImage contents to this distinct value. This is an exact observation,
    // not a tolerance: full-frame comparisons still use the embedded bytes.
    return (SceneBGRA){67, 35, 34, 255};
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

// Lossless native readback encoded as runs differing from the exact root or
// bitmap backdrop. Each run is y, x, length followed by literal BGR triplets.
// Alpha is opaque everywhere. These bytes are expectations only and are never
// used to construct a scene.
static NSData *ReferencePixels(void) {
    static NSData *frame = nil;
    if (frame) return frame;
    NSMutableData *decoded = [NSMutableData dataWithLength:kSceneByteCount];
    uint8_t *pixels = decoded.mutableBytes;
    const SceneBGRA root = RootPixel();
    for (unsigned i = 0; i < kSceneWidth * kSceneHeight; i++) {
        pixels[i * 4] = root.b;
        pixels[i * 4 + 1] = root.g;
        pixels[i * 4 + 2] = root.r;
        pixels[i * 4 + 3] = root.a;
    }
    const SceneBGRA bitmapBackground = BitmapBackgroundPixel();
    for (unsigned y = 16; y < 16 + kTextHeight; y++) {
        for (unsigned x = 16; x < 16 + kTextWidth; x++) {
            const size_t at = ((size_t)y * kSceneWidth + x) * 4;
            pixels[at] = bitmapBackground.b;
            pixels[at + 1] = bitmapBackground.g;
            pixels[at + 2] = bitmapBackground.r;
            pixels[at + 3] = bitmapBackground.a;
        }
    }
    if (kEncodedReferenceRuns.length == 0) {
        frame = decoded;
        return frame;
    }
    NSData *runs = [[NSData alloc] initWithBase64EncodedString:kEncodedReferenceRuns options:0];
    if (!runs) {
        fprintf(stderr, "scene3 CoreText reference: base64 decode failed (characters=%lu)\n",
            (unsigned long)kEncodedReferenceRuns.length);
        return nil;
    }
    const uint8_t *bytes = runs.bytes;
    size_t at = 0;
    while (at < runs.length) {
        if (at + 3 > runs.length) {
            fprintf(stderr, "scene3 CoreText reference: truncated run header at %zu/%lu\n",
                at, (unsigned long)runs.length);
            return nil;
        }
        const unsigned y = bytes[at], x = bytes[at + 1], count = bytes[at + 2];
        at += 3;
        if (y >= kSceneHeight || x + count > kSceneWidth || at + count * 3 > runs.length) {
            fprintf(stderr, "scene3 CoreText reference: invalid run y=%u x=%u count=%u at %zu/%lu\n",
                y, x, count, at, (unsigned long)runs.length);
            return nil;
        }
        for (unsigned column = 0; column < count; column++) {
            const size_t output = ((size_t)y * kSceneWidth + x + column) * 4;
            pixels[output] = bytes[at++];
            pixels[output + 1] = bytes[at++];
            pixels[output + 2] = bytes[at++];
        }
    }
    frame = decoded;
    return frame;
}

static SceneBGRA ExpectedPixel(unsigned x, unsigned y) {
    NSData *reference = ReferencePixels();
    return reference.length == kSceneByteCount
        ? ActualPixel(reference.bytes, x, y) : RootPixel();
}

static NSString *ExpectedReferenceHash(void) {
    NSData *reference = ReferencePixels();
    if (reference.length != kSceneByteCount) return @"invalid-reference";
    return [NSString stringWithFormat:@"%016llx",
        (unsigned long long)HashPixels(reference.bytes)];
}

static size_t ExpectedNonzeroBytes(void) {
    NSData *reference = ReferencePixels();
    if (reference.length != kSceneByteCount) return 0;
    const uint8_t *pixels = reference.bytes;
    size_t count = 0;
    for (size_t i = 0; i < kSceneByteCount; i++) {
        if (pixels[i]) count++;
    }
    return count;
}

static GlyphBounds MeasureNonBackground(const uint8_t *pixels,
    unsigned minimumX, unsigned maximumX) {
    GlyphBounds result = {.minX = kSceneWidth, .minY = kSceneHeight};
    if (!pixels) return result;
    const SceneBGRA root = RootPixel();
    const SceneBGRA bitmapBackground = BitmapBackgroundPixel();
    for (unsigned y = 0; y < kSceneHeight; y++) {
        for (unsigned x = minimumX; x <= maximumX; x++) {
            const BOOL insideImage = x >= 16 && x < 16 + kTextWidth && y >= 16 && y < 16 + kTextHeight;
            if (PixelsEqual(ActualPixel(pixels, x, y), insideImage ? bitmapBackground : root)) continue;
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

static BOOL BoundsEqual(GlyphBounds a, GlyphBounds b) {
    return a.found == b.found && a.minX == b.minX && a.minY == b.minY &&
        a.maxX == b.maxX && a.maxY == b.maxY && a.pixelCount == b.pixelCount;
}

static BOOL ValidateReferenceTemplate(void) {
    NSData *reference = ReferencePixels();
    if (reference.length != kSceneByteCount) {
        fprintf(stderr, "scene3 CoreText key error: invalid embedded reference encoding\n");
        return NO;
    }
    const uint8_t *pixels = reference.bytes;
    NSString *computedHash = ExpectedReferenceHash();
    if (![computedHash isEqualToString:kExpectedReferenceHash] ||
        !BoundsEqual(MeasureNonBackground(pixels, 0, kSceneWidth - 1), kExpectedAllGlyphBounds) ||
        !BoundsEqual(MeasureNonBackground(pixels, 16, 47), kExpectedHongGlyphBounds) ||
        !BoundsEqual(MeasureNonBackground(pixels, 48, 79), kExpectedMengGlyphBounds) ||
        ExpectedNonzeroBytes() != kSceneByteCount) {
        GlyphBounds all = MeasureNonBackground(pixels, 0, kSceneWidth - 1);
        fprintf(stderr, "scene3 CoreText key error: embedded native reference is inconsistent: "
            "bounds=(%u,%u)-(%u,%u) count=%zu hash=%s nonzeroBytes=%zu\n",
            all.minX, all.minY, all.maxX, all.maxY, all.pixelCount,
            computedHash.UTF8String, ExpectedNonzeroBytes());
        return NO;
    }
    return YES;
}

static void ReleaseBundledFontBytes(void *info, const void *data, size_t size) {
    (void)info;
    (void)size;
    free((void *)data);
}

// No font registration and no system-font fallback: CoreText consumes the
// exact bundled TTF bytes through CGDataProvider/CGFont.
static CTFontRef CreateBundledFont(NSError **error) {
    NSData *fontData = [NSData dataWithContentsOfFile:kBundledFontPath options:0 error:error];
    if (!fontData || fontData.length == 0) return NULL;
    void *bytes = malloc(fontData.length);
    if (!bytes) {
        if (error) {
            *error = [NSError errorWithDomain:@"HarmoniosScene3CoreText" code:10
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

static CGImageRef CreateCoreTextImage(CTFontRef font, CGColorRef background) {
    CGColorRef white = CGColorCreateGenericRGB(1, 1, 1, 1);
    NSAttributedString *attributed = [[NSAttributedString alloc] initWithString:@"鸿蒙"
        attributes:@{
            (__bridge NSString *)kCTFontAttributeName: (__bridge id)font,
            (__bridge NSString *)kCTForegroundColorAttributeName: (__bridge id)white,
        }];
    CTLineRef line = CTLineCreateWithAttributedString((__bridge CFAttributedStringRef)attributed);
    if (!line) {
        if (white) CGColorRelease(white);
        return NULL;
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    const CGBitmapInfo bitmapInfo =
        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little;
    // CoreGraphics owns the storage. No host-provided or host-rasterized pixels.
    CGContextRef context = colorSpace ? CGBitmapContextCreate(NULL,
        kTextWidth, kTextHeight, 8, kTextWidth * 4, colorSpace, bitmapInfo) : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!context) {
        CFRelease(line);
        return NULL;
    }
    CGContextSetFillColorWithColor(context, background);
    CGContextFillRect(context, CGRectMake(0, 0, kTextWidth, kTextHeight));
    CGContextSetFillColorWithColor(context, white);
    CGContextSetTextDrawingMode(context, kCGTextFill);
    CGContextSetShouldAntialias(context, true);
    CGContextSetShouldSmoothFonts(context, false);
    CGContextSetTextPosition(context, 0, 16);
    CTLineDraw(line, context);
    CGImageRef image = CGBitmapContextCreateImage(context);
    if (white) CGColorRelease(white);
    CGContextRelease(context);
    CFRelease(line);
    return image;
}

static CALayer *CreateScene3(CTFontRef font) {
    CALayer *root = [CALayer layer];
    root.bounds = CGRectMake(0, 0, kSceneWidth, kSceneHeight);
    root.position = CGPointMake(kSceneWidth / 2.0, kSceneHeight / 2.0);
    root.geometryFlipped = NO;
    CGColorRef background = CGColorCreateGenericRGB(0.1, 0.1, 0.2, 1);
    root.backgroundColor = background;

    CGImageRef image = CreateCoreTextImage(font, background);
    if (background) CGColorRelease(background);
    if (!image) return nil;
    CALayer *imageLayer = [CALayer layer];
    imageLayer.frame = CGRectMake(16, 16, kTextWidth, kTextHeight);
    imageLayer.contentsScale = 1.0;
    // CARenderer presents bitmap CGImage row zero at the bottom on macOS.
    // Match scene1's geometry-only correction; the CGImage is not re-rasterized.
    imageLayer.transform = CATransform3DMakeScale(1, -1, 1);
    imageLayer.contents = (__bridge id)image;
    [root addSublayer:imageLayer];
    CGImageRelease(image);
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
                fprintf(stderr, "scene3 CoreText mismatch (%u,%u): got BGRA(%u,%u,%u,%u), "
                    "expected BGRA(%u,%u,%u,%u)\n", x, y,
                    actual.b, actual.g, actual.r, actual.a,
                    expected.b, expected.g, expected.r, expected.a);
            }
            mismatches++;
        }
    }
    if (mismatches) {
        fprintf(stderr, "scene3 CoreText: %zu of %u pixels failed strict native validation\n",
            mismatches, kSceneWidth * kSceneHeight);
    }
    return mismatches;
}

static size_t CheckOneGlyphBounds(const char *name, GlyphBounds actual, GlyphBounds expected) {
    if (BoundsEqual(actual, expected)) return 0;
    fprintf(stderr, "scene3 CoreText %s bounds mismatch: got found=%d "
        "(%u,%u)-(%u,%u) count=%zu, expected found=%d (%u,%u)-(%u,%u) count=%zu\n",
        name, actual.found, actual.minX, actual.minY, actual.maxX, actual.maxY, actual.pixelCount,
        expected.found, expected.minX, expected.minY, expected.maxX, expected.maxY, expected.pixelCount);
    return 1;
}

static size_t CheckGlyphBounds(const uint8_t *pixels) {
    size_t mismatches = 0;
    mismatches += CheckOneGlyphBounds("all glyphs",
        MeasureNonBackground(pixels, 0, kSceneWidth - 1), kExpectedAllGlyphBounds);
    mismatches += CheckOneGlyphBounds("hong",
        MeasureNonBackground(pixels, 16, 47), kExpectedHongGlyphBounds);
    mismatches += CheckOneGlyphBounds("meng",
        MeasureNonBackground(pixels, 48, 79), kExpectedMengGlyphBounds);
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
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ is missing", name]);
        return NO;
    }
    NSDictionary *entry = value;
    id actualX = entry[@"x"], actualY = entry[@"y"];
    if (![actualX isKindOfClass:[NSNumber class]] || [actualX unsignedIntValue] != sample.x ||
        ![actualY isKindOfClass:[NSNumber class]] || [actualY unsignedIntValue] != sample.y) {
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ has incorrect coordinates", name]);
        return NO;
    }
    id bgra = entry[@"bgra"];
    if (![bgra isKindOfClass:[NSArray class]] || [bgra count] != 4) {
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ must contain BGRA", name]);
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

static int CheckProbeReport(NSString *path) {
    if (!ValidateReferenceTemplate()) return 1;
    NSError *error = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:&error];
    if (!data) return ProbeReportFailure([NSString stringWithFormat:@"cannot read %@: %@",
        path, error.localizedDescription ?: @"unknown I/O error"]);
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
            !RequireReportNumber(report, @"unimplementedSelectorCount", 0) ||
            !RequireReportString(report, @"referenceFnv1a64", kExpectedReferenceHash) ||
            !RequireReportString(report, @"readbackFnv1a64", kExpectedReferenceHash)) return 1;
        id reportError = report[@"error"];
        if (reportError && (![reportError isKindOfClass:[NSString class]] || [reportError length] != 0)) {
            return ProbeReportFailure([NSString stringWithFormat:@"unexpected error: %@", reportError]);
        }
        id selectors = report[@"unimplementedSelectors"];
        if (![selectors isKindOfClass:[NSArray class]] || [selectors count] != 0) {
            return ProbeReportFailure([NSString stringWithFormat:@"unimplemented selectors: %@",
                selectors ?: @"<missing>"]);
        }
        id samples = report[@"samples"];
        if (![samples isKindOfClass:[NSDictionary class]]) return ProbeReportFailure(@"samples missing");
        for (size_t i = 0; i < sizeof(kSamples) / sizeof(kSamples[0]); i++) {
            if (!RequireReportSample(samples, kSamples[i])) return 1;
        }
    } @catch (NSException *exception) {
        return ProbeReportFailure([NSString stringWithFormat:@"%@: %@", exception.name, exception.reason]);
    }
    printf("probe report: scene 3 CoreText bitmap passed exact hash, samples, lifecycle and selectors\n");
    return 0;
}

static NSDictionary *SampleReport(const uint8_t *pixels) {
    NSMutableDictionary *samples = [NSMutableDictionary dictionary];
    for (size_t i = 0; i < sizeof(kSamples) / sizeof(kSamples[0]); i++) {
        const SceneSample sample = kSamples[i];
        const SceneBGRA pixel = ActualPixel(pixels, sample.x, sample.y);
        NSString *name = [NSString stringWithUTF8String:sample.name];
        samples[name] = @{
            @"x": @(sample.x), @"y": @(sample.y),
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
        @"found": @YES, @"minX": @(bounds.minX), @"minY": @(bounds.minY),
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
        @"fontRegistration": @"not used",
        @"systemFontFallback": @NO,
        @"postScriptName": postScriptName ?: @"",
        @"familyName": familyName ?: @"",
        @"fullName": fullName ?: @"",
        @"fontRevision": @(revision / 65536.0),
        @"pointSize": @(CTFontGetSize(font)),
        @"unitsPerEm": @(CTFontGetUnitsPerEm(font)),
        @"ascent": @(CTFontGetAscent(font)), @"descent": @(CTFontGetDescent(font)),
        @"leading": @(CTFontGetLeading(font)),
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
    const CGBitmapInfo bitmapInfo = kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little;
    CGImageRef image = CGImageCreate(kSceneWidth, kSceneHeight, 8, 32,
        kSceneWidth * 4, colorSpace, bitmapInfo, provider, NULL, false, kCGRenderingIntentDefault);
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
        *error = [NSError errorWithDomain:@"HarmoniosScene3CoreText" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"CGImageDestinationFinalize failed"}];
    }
    CFRelease(destination);
    CGImageRelease(image);
    return success;
}

static BOOL WriteArtifacts(NSData *readback, const uint8_t *pixels,
    size_t nonzeroPixels, size_t nonzeroBytes, uint64_t hash,
    size_t pixelMismatches, size_t glyphBoundaryMismatches, BOOL hashMatches,
    BOOL generationRun, CTFontRef font, CGImageRef image, NSError **error) {
    NSURL *directory = [NSURL fileURLWithPath:kArtifactDirectory isDirectory:YES];
    if (![[NSFileManager defaultManager] createDirectoryAtURL:directory
            withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    if (![readback writeToURL:[directory URLByAppendingPathComponent:@"reference.bgra"]
            options:NSDataWritingAtomic error:error]) return NO;
    if (!WritePNG([directory URLByAppendingPathComponent:@"reference.png"], readback, error)) return NO;
    NSString *hashText = [NSString stringWithFormat:@"%016llx\n", (unsigned long long)hash];
    if (![hashText writeToURL:[directory URLByAppendingPathComponent:@"reference.fnv1a64"]
            atomically:YES encoding:NSUTF8StringEncoding error:error]) return NO;
    NSDictionary *metadata = @{
        @"backend": @"Apple Metal (native macOS CARenderer CoreText-bitmap reference)",
        @"operatingSystem": NSProcessInfo.processInfo.operatingSystemVersionString,
        @"scene": @3, @"width": @(kSceneWidth), @"height": @(kSceneHeight),
        @"pixelFormat": @"BGRA8Unorm", @"bytes": @(kSceneByteCount),
        @"bytesPerRow": @(kSceneWidth * 4),
        @"nonzeroPixels": @(nonzeroPixels), @"nonzeroBytes": @(nonzeroBytes),
        @"fnv1a64": [NSString stringWithFormat:@"%016llx", (unsigned long long)hash],
        @"expectedFnv1a64": generationRun ? @"(generation run)" : kExpectedReferenceHash,
        @"hashMatches": @(hashMatches), @"generationRun": @(generationRun),
        @"pixelMismatches": @(pixelMismatches),
        @"strictPixelCount": @(kSceneWidth * kSceneHeight),
        @"glyphBoundaryMismatches": @(glyphBoundaryMismatches),
        @"root": @{
            @"bounds": @[@0, @0, @256, @256],
            @"backgroundColor": @"CGColorCreateGenericRGB(0.1,0.1,0.2,1)",
            @"nativeBackgroundBGRA": @[@66, @35, @34, @255], @"geometryFlipped": @NO,
        },
        @"imageLayer": @{
            @"class": @"CALayer", @"frame": @[@16, @16, @224, @64],
            @"contents": @"CGImage from CGBitmapContextCreateImage", @"contentsScale": @1,
            @"transform": @"CATransform3DMakeScale(1,-1,1); geometry-only CARenderer row-orientation correction",
            @"nativeBitmapBackgroundBGRA": @[@67, @35, @34, @255],
            @"imageWidth": @(CGImageGetWidth(image)), @"imageHeight": @(CGImageGetHeight(image)),
            @"imageBytesPerRow": @(CGImageGetBytesPerRow(image)),
            @"bitmapContext": @{
                @"width": @224, @"height": @64, @"bitsPerComponent": @8,
                @"bytesPerRow": @896,
                @"bitmapInfo": @"kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little",
                @"background": @"same CGColor as root",
                @"textPosition": @[@0, @16], @"drawingMode": @"kCGTextFill",
            },
            @"text": @"鸿蒙",
            @"attributedStringAttributes": @[@"kCTFontAttributeName", @"kCTForegroundColorAttributeName"],
            @"lineCreation": @"CTLineCreateWithAttributedString",
            @"rasterization": @"CTLineDraw into guest Apple CGBitmapContext",
        },
        @"glyphBoundsDefinition": @"Inside the image frame, any pixel differing from exact bitmap "
            "background BGRA(67,35,34,255); elsewhere any pixel differing from root BGRA(66,35,34,255). "
            "Coordinates are zero-based readback texels.",
        @"glyphBounds": BoundsReport(MeasureNonBackground(pixels, 0, kSceneWidth - 1)),
        @"characterGlyphBounds": @{
            @"hong": BoundsReport(MeasureNonBackground(pixels, 16, 47)),
            @"meng": BoundsReport(MeasureNonBackground(pixels, 48, 79)),
        },
        @"font": FontReport(font), @"samples": SampleReport(pixels),
        @"referenceValidation": generationRun
            ? @"Reference generation only; rerun without --generate-reference for strict validation."
            : @"Every one of 65,536 pixels is compared exactly with the embedded native CoreText-bitmap reference; no tolerance or CATextLayer reference is used.",
        @"source": @"tests/ca_renderer_scene3_coretext.m",
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
            return path ? CheckProbeReport(path) : ProbeReportFailure(@"report path is not UTF-8");
        }
        const BOOL generationRun = argc == 2 && strcmp(argv[1], "--generate-reference") == 0;
        if (argc != 1 && !generationRun) {
            fprintf(stderr, "usage: %s [--generate-reference | --check-probe-report report.json]\n", argv[0]);
            return 64;
        }
        if (!generationRun && !ValidateReferenceTemplate()) return 8;
        @try {
            id<MTLDevice> device = MTLCreateSystemDefaultDevice();
            if (!device) { fprintf(stderr, "scene3 CoreText key error: no Metal device\n"); return 2; }
            MTLTextureDescriptor *descriptor = [MTLTextureDescriptor
                texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                width:kSceneWidth height:kSceneHeight mipmapped:NO];
            descriptor.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
            id<MTLTexture> texture = [device newTextureWithDescriptor:descriptor];
            id<MTLCommandQueue> queue = [device newCommandQueue];
            if (!texture || !queue) { fprintf(stderr, "scene3 CoreText key error: Metal allocation failed\n"); return 3; }
            CARenderer *renderer = [CARenderer rendererWithMTLTexture:texture
                options:@{kCARendererMetalCommandQueue: queue}];
            if (!renderer) { fprintf(stderr, "scene3 CoreText key error: CARenderer refused texture\n"); return 3; }
            NSError *fontError = nil;
            CTFontRef font = CreateBundledFont(&fontError);
            if (!font) {
                fprintf(stderr, "scene3 CoreText key error: bundled font creation failed: %s\n",
                    fontError.localizedDescription.UTF8String ?: "invalid font data");
                return 3;
            }
            NSString *postScriptName = CFBridgingRelease(CTFontCopyPostScriptName(font));
            if (![postScriptName isEqualToString:@"PingFangSC-Regular"] ||
                    CTFontGetSize(font) != 32.0 || CTFontGetUnitsPerEm(font) != 2048) {
                fprintf(stderr, "scene3 CoreText key error: unexpected font: %s %.6fpt upem=%u\n",
                    postScriptName.UTF8String ?: "", CTFontGetSize(font),
                    (unsigned)CTFontGetUnitsPerEm(font));
                CFRelease(font);
                return 3;
            }
            UniChar characters[] = {0x9e3f, 0x8499};
            CGGlyph glyphs[2] = {0};
            if (!CTFontGetGlyphsForCharacters(font, characters, glyphs, 2) ||
                    glyphs[0] != kExpectedGlyphIDs[0] || glyphs[1] != kExpectedGlyphIDs[1]) {
                fprintf(stderr, "scene3 CoreText key error: glyph mapping=(%u,%u), expected=(%u,%u)\n",
                    glyphs[0], glyphs[1], kExpectedGlyphIDs[0], kExpectedGlyphIDs[1]);
                CFRelease(font);
                return 3;
            }
            CALayer *root = CreateScene3(font);
            CALayer *imageLayer = root.sublayers.firstObject;
            CGImageRef image = imageLayer ? (__bridge CGImageRef)imageLayer.contents : NULL;
            if (!root || root.sublayers.count != 1 || [imageLayer class] != [CALayer class] ||
                !CGRectEqualToRect(imageLayer.frame, CGRectMake(16, 16, 224, 64)) ||
                imageLayer.contentsScale != 1.0 || !image || CFGetTypeID(image) != CGImageGetTypeID() ||
                !CATransform3DEqualToTransform(imageLayer.transform, CATransform3DMakeScale(1, -1, 1)) ||
                CGImageGetWidth(image) != 224 || CGImageGetHeight(image) != 64 || root.geometryFlipped) {
                fprintf(stderr, "scene3 CoreText key error: CALayer/CGImage scene invariant changed\n");
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
            if (!fence) { CFRelease(font); return 5; }
            [fence commit];
            [fence waitUntilCompleted];
            NSError *fenceError = fence.error;
            if (fence.status != MTLCommandBufferStatusCompleted || fenceError) {
                fprintf(stderr, "scene3 CoreText key error: fence status=%ld error=%s\n",
                    (long)fence.status, fenceError.localizedDescription.UTF8String ?: "none");
                CFRelease(font);
                return 5;
            }
            usleep(200000);
            NSMutableData *readback = [NSMutableData dataWithLength:kSceneByteCount];
            uint8_t *pixels = readback.mutableBytes;
            if (!pixels) { CFRelease(font); return 6; }
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
            const BOOL hashMatches = generationRun || [actualHash isEqualToString:kExpectedReferenceHash];
            printf("device=%s nonzeroPixels=%zu nonzeroBytes=%zu fnv1a64=%s expected=%s\n",
                device.name.UTF8String, nonzeroPixels, nonzeroBytes, actualHash.UTF8String,
                generationRun ? "generation" : kExpectedReferenceHash.UTF8String);
            for (size_t i = 0; i < sizeof(kSamples) / sizeof(kSamples[0]); i++) {
                const SceneSample sample = kSamples[i];
                const SceneBGRA pixel = ActualPixel(pixels, sample.x, sample.y);
                printf("sample %s (%u,%u) BGRA(%u,%u,%u,%u)\n", sample.name,
                    sample.x, sample.y, pixel.b, pixel.g, pixel.r, pixel.a);
            }
            GlyphBounds all = MeasureNonBackground(pixels, 0, kSceneWidth - 1);
            GlyphBounds hong = MeasureNonBackground(pixels, 16, 47);
            GlyphBounds meng = MeasureNonBackground(pixels, 48, 79);
            printf("glyphBounds all found=%d (%u,%u)-(%u,%u) count=%zu; "
                "hong count=%zu (%u,%u)-(%u,%u); meng count=%zu (%u,%u)-(%u,%u)\n",
                all.found, all.minX, all.minY, all.maxX, all.maxY, all.pixelCount,
                hong.pixelCount, hong.minX, hong.minY, hong.maxX, hong.maxY,
                meng.pixelCount, meng.minX, meng.minY, meng.maxX, meng.maxY);
            const size_t pixelMismatches = generationRun ? 0 : CheckNativePixels(pixels);
            const size_t glyphBoundaryMismatches = generationRun ? 0 : CheckGlyphBounds(pixels);
            NSError *outputError = nil;
            const BOOL artifactsWritten = WriteArtifacts(readback, pixels,
                nonzeroPixels, nonzeroBytes, hash, pixelMismatches,
                glyphBoundaryMismatches, hashMatches, generationRun, font, image, &outputError);
            CFRelease(font);
            if (!artifactsWritten) {
                fprintf(stderr, "scene3 CoreText key error: cannot write artifacts: %s\n",
                    outputError.localizedDescription.UTF8String ?: "unknown I/O error");
                return 6;
            }
            if (generationRun) {
                printf("scene3 CoreText: generated native reference artifacts=%s\n", kArtifactDirectory.UTF8String);
                return 0;
            }
            if (!hashMatches) fprintf(stderr, "scene3 CoreText: FNV-1a64 differs from native reference\n");
            if (pixelMismatches || glyphBoundaryMismatches || !hashMatches) return 4;
            printf("scene3 CoreText: all %u pixels matched the native bitmap reference; "
                "glyph bounds and samples passed; artifacts=%s\n",
                kSceneWidth * kSceneHeight, kArtifactDirectory.UTF8String);
            return 0;
        } @catch (NSException *exception) {
            fprintf(stderr, "scene3 CoreText key error: %s: %s\n",
                exception.name.UTF8String, exception.reason.UTF8String);
            return 7;
        }
    }
}
