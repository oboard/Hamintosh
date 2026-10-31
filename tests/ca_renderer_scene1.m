#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned kSceneWidth = 256;
static const unsigned kSceneHeight = 256;
static const size_t kSceneByteCount = kSceneWidth * kSceneHeight * 4;
static NSString *const kArtifactDirectory = @"artifacts/mac-ca-scene1";

typedef struct {
    uint8_t b, g, r, a;
} SceneBGRA;

typedef struct {
    const char *name;
    unsigned x, y;
} SceneSample;

// These samples are also required in a Harmony hm_ca_renderer_probe report.
// The full-frame hash remains mandatory; samples only make failures diagnosable.
static const SceneSample kSamples[] = {
    {"root", 8, 8},
    {"red", 72, 72},
    {"green", 120, 72},
    {"blue", 72, 120},
    {"yellow", 120, 120},
    {"clipLeft", 47, 72},
    {"clipTop", 72, 47},
    {"clipRight", 144, 72},
    {"clipBottom", 120, 144},
};

static SceneBGRA RootPixel(void) {
    // Apple CARenderer's color-managed BGRA8Unorm value for
    // CGColorCreateGenericRGB(0.1, 0.1, 0.2, 1), as established by scene0.
    return (SceneBGRA){66, 35, 34, 255};
}

static SceneBGRA ExpectedPixel(unsigned x, unsigned y) {
    // container: [48,144) x [48,144). The image starts at root (32,32),
    // so each nearest-sampled central source texel changes at root 96.
    if (x >= 48 && x < 144 && y >= 48 && y < 144) {
        if (y < 96) return x < 96 ? (SceneBGRA){0, 0, 255, 255}
                                  : (SceneBGRA){0, 255, 0, 255};
        return x < 96 ? (SceneBGRA){255, 0, 0, 255}
                      : (SceneBGRA){0, 255, 255, 255};
    }
    return RootPixel();
}

static const char *ExpectedRegion(unsigned x, unsigned y) {
    if (x >= 48 && x < 144 && y >= 48 && y < 144) {
        if (y < 96) return x < 96 ? "red" : "green";
        return x < 96 ? "blue" : "yellow";
    }
    return "background / clipped image";
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
            const uint8_t channels[4] = {pixel.b, pixel.g, pixel.r, pixel.a};
            for (unsigned channel = 0; channel < 4; channel++) {
                if (channels[channel]) count++;
            }
        }
    }
    return count;
}

static void SourcePixel(uint8_t *source, unsigned x, unsigned y, SceneBGRA pixel) {
    const size_t at = ((size_t)y * 4 + x) * 4;
    source[at] = pixel.b;
    source[at + 1] = pixel.g;
    source[at + 2] = pixel.r;
    source[at + 3] = pixel.a;
}

static void ReleaseSourceData(void *info, const void *data, size_t size) {
    (void)info;
    (void)size;
    free((void *)data);
}

static CGImageRef CreateSourceImage(void) {
    // Opaque magenta outside the center is a sentinel: sampling any outer
    // texel instead of contentsRect=(0.25,0.25,0.5,0.5) fails validation.
    uint8_t *source = malloc(4 * 4 * 4);
    if (!source) return NULL;
    for (unsigned y = 0; y < 4; y++) {
        for (unsigned x = 0; x < 4; x++) {
            SourcePixel(source, x, y, (SceneBGRA){255, 0, 255, 255});
        }
    }
    SourcePixel(source, 1, 1, (SceneBGRA){0, 0, 255, 255});   // red, top-left
    SourcePixel(source, 2, 1, (SceneBGRA){0, 255, 0, 255});   // green, top-right
    SourcePixel(source, 1, 2, (SceneBGRA){255, 0, 0, 255});   // blue, bottom-left
    SourcePixel(source, 2, 2, (SceneBGRA){0, 255, 255, 255}); // yellow, bottom-right

    CGDataProviderRef provider = CGDataProviderCreateWithData(
        NULL, source, 4 * 4 * 4, ReleaseSourceData);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!provider || !colorSpace) {
        // The provider owns source only when provider creation succeeded.
        if (!provider) free(source);
        if (provider) CGDataProviderRelease(provider);
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        return NULL;
    }
    const CGBitmapInfo bitmapInfo =
        kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little;
    CGImageRef image = CGImageCreate(4, 4, 8, 32, 16, colorSpace, bitmapInfo,
        provider, NULL, false, kCGRenderingIntentDefault);
    CGDataProviderRelease(provider);
    CGColorSpaceRelease(colorSpace);
    return image;
}

static CALayer *CreateScene1(CGImageRef sourceImage) {
    CALayer *root = [CALayer layer];
    root.bounds = CGRectMake(0, 0, kSceneWidth, kSceneHeight);
    root.position = CGPointMake(kSceneWidth / 2.0, kSceneHeight / 2.0);
    CGColorRef background = CGColorCreateGenericRGB(0.1, 0.1, 0.2, 1);
    root.backgroundColor = background;
    if (background) CGColorRelease(background);
    root.geometryFlipped = NO;

    CALayer *container = [CALayer layer];
    container.frame = CGRectMake(48, 48, 96, 96);
    container.masksToBounds = YES;
    [root addSublayer:container];

    CALayer *imageLayer = [CALayer layer];
    imageLayer.frame = CGRectMake(-16, -16, 128, 128);
    // CARenderer otherwise presents CGImage row zero at the bottom on macOS.
    // Reflection about the layer center preserves its frame and clip geometry.
    imageLayer.transform = CATransform3DMakeScale(1, -1, 1);
    imageLayer.contents = (__bridge id)sourceImage;
    imageLayer.contentsRect = CGRectMake(0.25, 0.25, 0.5, 0.5);
    imageLayer.minificationFilter = kCAFilterNearest;
    imageLayer.magnificationFilter = kCAFilterNearest;
    [container addSublayer:imageLayer];
    return root;
}

static SceneBGRA ActualPixel(const uint8_t *pixels, unsigned x, unsigned y) {
    const size_t at = ((size_t)y * kSceneWidth + x) * 4;
    return (SceneBGRA){pixels[at], pixels[at + 1], pixels[at + 2], pixels[at + 3]};
}

static size_t CheckNativePixels(const uint8_t *pixels) {
    size_t mismatches = 0;
    for (unsigned y = 0; y < kSceneHeight; y++) {
        for (unsigned x = 0; x < kSceneWidth; x++) {
            const SceneBGRA expected = ExpectedPixel(x, y);
            const SceneBGRA actual = ActualPixel(pixels, x, y);
            if (actual.b == expected.b && actual.g == expected.g &&
                actual.r == expected.r && actual.a == expected.a) continue;
            if (mismatches < 16) {
                fprintf(stderr,
                    "scene1 mismatch (%u,%u) %s: got BGRA(%u,%u,%u,%u), "
                    "expected BGRA(%u,%u,%u,%u)\n",
                    x, y, ExpectedRegion(x, y), actual.b, actual.g, actual.r, actual.a,
                    expected.b, expected.g, expected.r, expected.a);
            }
            mismatches++;
        }
    }
    if (mismatches) {
        fprintf(stderr, "scene1: %zu of %u pixels failed strict region validation\n",
            mismatches, kSceneWidth * kSceneHeight);
    }
    return mismatches;
}

static size_t CheckOneBoundary(const uint8_t *pixels, const char *name,
    unsigned x, unsigned y, SceneBGRA expected) {
    const SceneBGRA actual = ActualPixel(pixels, x, y);
    if (actual.b == expected.b && actual.g == expected.g &&
        actual.r == expected.r && actual.a == expected.a) return 0;
    fprintf(stderr,
        "scene1 clip boundary %s (%u,%u): got BGRA(%u,%u,%u,%u), "
        "expected BGRA(%u,%u,%u,%u)\n",
        name, x, y, actual.b, actual.g, actual.r, actual.a,
        expected.b, expected.g, expected.r, expected.a);
    return 1;
}

static size_t CheckClipBoundaries(const uint8_t *pixels) {
    const SceneBGRA root = RootPixel();
    const SceneBGRA red = {0, 0, 255, 255};
    const SceneBGRA green = {0, 255, 0, 255};
    const SceneBGRA blue = {255, 0, 0, 255};
    const SceneBGRA yellow = {0, 255, 255, 255};
    size_t mismatches = 0;
    mismatches += CheckOneBoundary(pixels, "left outside", 47, 72, root);
    mismatches += CheckOneBoundary(pixels, "left inside", 48, 72, red);
    mismatches += CheckOneBoundary(pixels, "top outside", 72, 47, root);
    mismatches += CheckOneBoundary(pixels, "top inside", 72, 48, red);
    mismatches += CheckOneBoundary(pixels, "red last column", 95, 72, red);
    mismatches += CheckOneBoundary(pixels, "green first column", 96, 72, green);
    mismatches += CheckOneBoundary(pixels, "red last row", 72, 95, red);
    mismatches += CheckOneBoundary(pixels, "blue first row", 72, 96, blue);
    mismatches += CheckOneBoundary(pixels, "right inside", 143, 72, green);
    mismatches += CheckOneBoundary(pixels, "right outside", 144, 72, root);
    mismatches += CheckOneBoundary(pixels, "bottom inside", 120, 143, yellow);
    mismatches += CheckOneBoundary(pixels, "bottom outside", 120, 144, root);
    // The un-clipped image would extend through root coordinate 159.
    mismatches += CheckOneBoundary(pixels, "right/bottom clipped extent", 159, 159, root);
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
    const uint8_t channels[4] = {expected.b, expected.g, expected.r, expected.a};
    for (unsigned channel = 0; channel < 4; channel++) {
        id actual = bgra[channel];
        if (![actual isKindOfClass:[NSNumber class]] ||
            [actual unsignedIntValue] != channels[channel]) {
            ProbeReportFailure([NSString stringWithFormat:
                @"sample %@ BGRA channel %u must be %u, got %@ (expected %s)",
                name, channel, channels[channel], actual, ExpectedRegion(sample.x, sample.y)]);
            return NO;
        }
    }
    return YES;
}

// A nonzero-pixel smoke test is explicitly insufficient here. Require the
// exact expected full-frame hash, exact representative colors and diagnostics.
static int CheckProbeReport(NSString *path) {
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
        if (!RequireReportNumber(report, @"scene", 1) ||
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
            !RequireReportNumber(report, @"unimplementedSelectorCount", 0)) return 1;

        id reportError = report[@"error"];
        if (reportError && (![reportError isKindOfClass:[NSString class]] ||
                [reportError length] != 0)) {
            return ProbeReportFailure([NSString stringWithFormat:@"unexpected key error: %@", reportError]);
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
        NSString *expectedHash = ExpectedReferenceHash();
        if (!RequireReportString(report, @"referenceFnv1a64", expectedHash) ||
            !RequireReportString(report, @"readbackFnv1a64", expectedHash)) return 1;
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
    printf("probe report: scene 1 exact full-frame hash, pixels, clip samples, "
        "selectors and key errors passed\n");
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
        *error = [NSError errorWithDomain:@"HarmoniosScene1" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"CGImageDestinationFinalize failed"}];
    }
    CFRelease(destination);
    CGImageRelease(image);
    return success;
}

static BOOL WriteArtifacts(NSData *readback, const uint8_t *pixels,
    size_t nonzeroPixels, size_t nonzeroBytes, uint64_t hash,
    size_t pixelMismatches, size_t boundaryMismatches, NSError **error) {
    NSURL *directory = [NSURL fileURLWithPath:kArtifactDirectory isDirectory:YES];
    if (![[NSFileManager defaultManager] createDirectoryAtURL:directory
            withIntermediateDirectories:YES attributes:nil error:error]) return NO;
    if (![readback writeToURL:[directory URLByAppendingPathComponent:@"reference.bgra"]
            options:NSDataWritingAtomic error:error]) return NO;
    if (!WritePNG([directory URLByAppendingPathComponent:@"reference.png"], readback, error)) {
        if (error && !*error) {
            *error = [NSError errorWithDomain:@"HarmoniosScene1" code:2
                userInfo:@{NSLocalizedDescriptionKey: @"PNG encoding failed"}];
        }
        return NO;
    }
    NSDictionary *metadata = @{
        @"backend": @"Apple Metal (native macOS CARenderer reference)",
        @"scene": @1,
        @"width": @(kSceneWidth),
        @"height": @(kSceneHeight),
        @"pixelFormat": @"BGRA8Unorm",
        @"bytes": @(kSceneByteCount),
        @"bytesPerRow": @(kSceneWidth * 4),
        @"nonzeroPixels": @(nonzeroPixels),
        @"nonzeroBytes": @(nonzeroBytes),
        @"fnv1a": [NSString stringWithFormat:@"%016llx", (unsigned long long)hash],
        @"expectedFnv1a": ExpectedReferenceHash(),
        @"pixelMismatches": @(pixelMismatches),
        @"clipBoundaryMismatches": @(boundaryMismatches),
        @"containerFrame": @[@48, @48, @96, @96],
        @"imageFrame": @[@-16, @-16, @128, @128],
        @"imageTransform": @"CATransform3DMakeScale(1, -1, 1)",
        @"contentsRect": @[@0.25, @0.25, @0.5, @0.5],
        @"filter": @"nearest",
        @"samples": SampleReport(pixels),
        @"source": @"tests/ca_renderer_scene1.m",
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
        @try {
            id<MTLDevice> device = MTLCreateSystemDefaultDevice();
            if (!device) { fprintf(stderr, "scene1 key error: no Metal device\n"); return 2; }
            MTLTextureDescriptor *descriptor = [MTLTextureDescriptor
                texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                width:kSceneWidth height:kSceneHeight mipmapped:NO];
            descriptor.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
            id<MTLTexture> texture = [device newTextureWithDescriptor:descriptor];
            if (!texture) { fprintf(stderr, "scene1 key error: texture creation failed\n"); return 3; }
            id<MTLCommandQueue> queue = [device newCommandQueue];
            if (!queue) { fprintf(stderr, "scene1 key error: command queue creation failed\n"); return 3; }
            CARenderer *renderer = [CARenderer rendererWithMTLTexture:texture
                options:@{kCARendererMetalCommandQueue: queue}];
            if (!renderer) { fprintf(stderr, "scene1 key error: CARenderer refused texture\n"); return 3; }
            CGImageRef sourceImage = CreateSourceImage();
            if (!sourceImage) { fprintf(stderr, "scene1 key error: CGImage creation failed\n"); return 3; }
            renderer.layer = CreateScene1(sourceImage);
            CGImageRelease(sourceImage);
            renderer.bounds = CGRectMake(0, 0, kSceneWidth, kSceneHeight);
            [CATransaction flush];
            [renderer beginFrameAtTime:CACurrentMediaTime() timeStamp:NULL];
            [renderer addUpdateRect:renderer.bounds];
            [renderer render];
            [renderer endFrame];
            id<MTLCommandBuffer> fence = [queue commandBuffer];
            if (!fence) { fprintf(stderr, "scene1 key error: fence creation failed\n"); return 5; }
            [fence commit];
            [fence waitUntilCompleted];
            NSError *fenceError = fence.error;
            if (fence.status != MTLCommandBufferStatusCompleted || fenceError) {
                fprintf(stderr, "scene1 key error: fence status=%ld error=%s\n",
                    (long)fence.status, fenceError.localizedDescription.UTF8String ?: "none");
                return 5;
            }
            NSMutableData *readback = [NSMutableData dataWithLength:kSceneByteCount];
            uint8_t *pixels = readback.mutableBytes;
            if (!pixels) { fprintf(stderr, "scene1 key error: readback allocation failed\n"); return 6; }
            [texture getBytes:pixels bytesPerRow:kSceneWidth * 4
                fromRegion:MTLRegionMake2D(0, 0, kSceneWidth, kSceneHeight) mipmapLevel:0];
            size_t nonzeroPixels = 0;
            size_t nonzeroBytes = 0;
            for (unsigned y = 0; y < kSceneHeight; y++) {
                for (unsigned x = 0; x < kSceneWidth; x++) {
                    const SceneBGRA pixel = ActualPixel(pixels, x, y);
                    const uint8_t channels[4] = {pixel.b, pixel.g, pixel.r, pixel.a};
                    BOOL nonzero = NO;
                    for (unsigned channel = 0; channel < 4; channel++) {
                        if (channels[channel]) {
                            nonzeroBytes++;
                            nonzero = YES;
                        }
                    }
                    if (nonzero) nonzeroPixels++;
                }
            }
            const uint64_t hash = HashPixels(pixels);
            printf("device=%s nonzeroPixels=%zu nonzeroBytes=%zu hash=%016llx\n",
                device.name.UTF8String, nonzeroPixels, nonzeroBytes, (unsigned long long)hash);
            for (size_t i = 0; i < sizeof(kSamples) / sizeof(kSamples[0]); i++) {
                const SceneSample sample = kSamples[i];
                const SceneBGRA pixel = ActualPixel(pixels, sample.x, sample.y);
                printf("sample %s (%u,%u) BGRA(%u,%u,%u,%u)\n", sample.name,
                    sample.x, sample.y, pixel.b, pixel.g, pixel.r, pixel.a);
            }
            const size_t pixelMismatches = CheckNativePixels(pixels);
            const size_t boundaryMismatches = CheckClipBoundaries(pixels);
            NSError *outputError = nil;
            if (!WriteArtifacts(readback, pixels, nonzeroPixels, nonzeroBytes, hash,
                    pixelMismatches, boundaryMismatches, &outputError)) {
                fprintf(stderr, "scene1 key error: cannot write artifacts: %s\n",
                    outputError.localizedDescription.UTF8String ?: "unknown I/O error");
                return 6;
            }
            if (pixelMismatches || boundaryMismatches) return 4;
            printf("scene1: all %u pixels matched background, nearest-sampled four colors "
                "and clip boundaries; artifacts=%s\n", kSceneWidth * kSceneHeight,
                kArtifactDirectory.UTF8String);
            return 0;
        } @catch (NSException *exception) {
            fprintf(stderr, "scene1 key error: %s: %s\n",
                exception.name.UTF8String, exception.reason.UTF8String);
            return 7;
        }
    }
}
