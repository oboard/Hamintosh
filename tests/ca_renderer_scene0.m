#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const unsigned kSceneWidth = 256;
static const unsigned kSceneHeight = 256;
static const size_t kSceneByteCount = kSceneWidth * kSceneHeight * 4;

typedef struct {
    uint8_t b, g, r, a;
} SceneBGRA;

// CGColorCreateGenericRGB is color-managed. These are Apple CARenderer's
// BGRA8Unorm reference values, not guesses made by multiplying components by
// 255. Blue is opaque and therefore hides every layer below it.
static SceneBGRA ExpectedPixel(unsigned x, unsigned y) {
    const BOOL red = x >= 20 && x < 140 && y >= 20 && y < 140;
    const BOOL green = x >= 70 && x < 190 && y >= 60 && y < 180;
    const BOOL blue = x >= 120 && x < 240 && y >= 100 && y < 220;
    if (blue) return (SceneBGRA){255, 51, 4, 255};
    if (red && green) return (SceneBGRA){0, 144, 128, 255};
    if (green) return (SceneBGRA){33, 142, 17, 255};
    if (red) return (SceneBGRA){0, 38, 255, 255};
    return (SceneBGRA){66, 35, 34, 255};
}

static const char *ExpectedRegion(unsigned x, unsigned y) {
    const BOOL red = x >= 20 && x < 140 && y >= 20 && y < 140;
    const BOOL green = x >= 70 && x < 190 && y >= 60 && y < 180;
    const BOOL blue = x >= 120 && x < 240 && y >= 100 && y < 220;
    if (blue) return "opaque blue";
    if (red && green) return "50% green over red";
    if (green) return "50% green over background";
    if (red) return "opaque red";
    return "background";
}

static CALayer *scene0(void) {
    CALayer *root = [CALayer layer];
    root.bounds = CGRectMake(0, 0, kSceneWidth, kSceneHeight);
    root.position = CGPointMake(kSceneWidth / 2.0, kSceneHeight / 2.0);
    root.backgroundColor = CGColorCreateGenericRGB(0.1, 0.1, 0.2, 1);
    root.geometryFlipped = NO;
    CGFloat colors[3][4] = {{1,0,0,1},{0,1,0,0.5},{0,0,1,1}};
    for (int i = 0; i < 3; i++) {
        CALayer *layer = [CALayer layer];
        layer.frame = CGRectMake(20 + i * 50, 20 + i * 40, 120, 120);
        layer.backgroundColor = CGColorCreateGenericRGB(colors[i][0], colors[i][1], colors[i][2], colors[i][3]);
        [root addSublayer:layer];
    }
    return root;
}

static size_t CheckNativePixels(const uint8_t *pixels) {
    size_t mismatches = 0;
    for (unsigned y = 0; y < kSceneHeight; y++) {
        for (unsigned x = 0; x < kSceneWidth; x++) {
            const size_t at = ((size_t)y * kSceneWidth + x) * 4;
            const SceneBGRA expected = ExpectedPixel(x, y);
            const SceneBGRA actual = {pixels[at], pixels[at + 1], pixels[at + 2], pixels[at + 3]};
            if (actual.b == expected.b && actual.g == expected.g &&
                actual.r == expected.r && actual.a == expected.a) continue;
            if (mismatches < 12) {
                fprintf(stderr,
                    "scene0 mismatch (%u,%u) %s: got BGRA(%u,%u,%u,%u), expected BGRA(%u,%u,%u,%u)\n",
                    x, y, ExpectedRegion(x, y), actual.b, actual.g, actual.r, actual.a,
                    expected.b, expected.g, expected.r, expected.a);
            }
            mismatches++;
        }
    }
    if (mismatches) {
        fprintf(stderr, "scene0: %zu of %u pixels failed strict region validation\n",
            mismatches, kSceneWidth * kSceneHeight);
    }
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

static BOOL RequireReportSample(NSDictionary *samples, NSString *name, unsigned x, unsigned y, int redOverride) {
    id value = samples[name];
    if (![value isKindOfClass:[NSDictionary class]]) {
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ is missing or not an object", name]);
        return NO;
    }
    NSDictionary *sample = value;
    id actualX = sample[@"x"];
    id actualY = sample[@"y"];
    if (![actualX isKindOfClass:[NSNumber class]] || [actualX unsignedIntValue] != x ||
        ![actualY isKindOfClass:[NSNumber class]] || [actualY unsignedIntValue] != y) {
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ must be at (%u,%u), got (%@,%@)",
            name, x, y, actualX ?: @"<missing>", actualY ?: @"<missing>"]);
        return NO;
    }
    id bgra = sample[@"bgra"];
    if (![bgra isKindOfClass:[NSArray class]] || [bgra count] != 4) {
        ProbeReportFailure([NSString stringWithFormat:@"sample %@ must contain four BGRA channels", name]);
        return NO;
    }
    const SceneBGRA expected = ExpectedPixel(x, y);
    const uint8_t channels[4] = {expected.b, expected.g, expected.r, expected.a};
    for (unsigned channel = 0; channel < 4; channel++) {
        id actual = bgra[channel];
        const uint8_t expectedChannel = channel == 2 && redOverride >= 0 ? (uint8_t)redOverride : channels[channel];
        if (![actual isKindOfClass:[NSNumber class]] ||
            [actual unsignedIntValue] != expectedChannel) {
            ProbeReportFailure([NSString stringWithFormat:
                @"sample %@ BGRA channel %u must be %u, got %@ (expected %s)",
                name, channel, expectedChannel, actual, ExpectedRegion(x, y)]);
            return NO;
        }
    }
    return YES;
}

// Validate the existing hm_ca_renderer_probe JSON without inventing another
// runtime API. The native scene checks every texel; the Harmony report exposes
// six representative texels plus its diagnostics, so both are checked here.
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
        if (!RequireReportNumber(report, @"scene", 0) ||
            !RequireReportNumber(report, @"success", 1) ||
            !RequireReportString(report, @"stage", @"complete") ||
            !RequireReportNumber(report, @"rendererCreated", 1) ||
            !RequireReportNumber(report, @"frameEnded", 1) ||
            !RequireReportNumber(report, @"commandBufferStatus", MTLCommandBufferStatusCompleted) ||
            !RequireReportNumber(report, @"width", kSceneWidth) ||
            !RequireReportNumber(report, @"height", kSceneHeight) ||
            !RequireReportString(report, @"pixelFormat", @"BGRA8Unorm") ||
            !RequireReportNumber(report, @"nonZeroPixels", kSceneWidth * kSceneHeight) ||
            !RequireReportNumber(report, @"nonZeroBytes", 248544) ||
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
        id profile = report[@"roundingProfile"];
        const BOOL maleoonRounding = [profile isKindOfClass:[NSString class]] &&
            [profile isEqualToString:@"maleoon-920c-red-channel-minus-one"];
        if (profile && !maleoonRounding) {
            return ProbeReportFailure([NSString stringWithFormat:@"unknown rounding profile: %@", profile]);
        }
        if (!RequireReportString(report, @"referenceFnv1a64", @"d15e8d0a54169a25") ||
            !RequireReportString(report, @"readbackFnv1a64",
                maleoonRounding ? @"8445581fde5db025" : @"d15e8d0a54169a25")) return 1;
        if (maleoonRounding && !RequireReportString(report, @"device", @"Maleoon 920C")) return 1;
        id samples = report[@"samples"];
        if (![samples isKindOfClass:[NSDictionary class]]) {
            return ProbeReportFailure(@"samples is missing or not an object");
        }
        if (!RequireReportSample(samples, @"root", 8, 8, -1) ||
            !RequireReportSample(samples, @"red", 30, 30, -1) ||
            !RequireReportSample(samples, @"greenOverRed", 80, 70, maleoonRounding ? 127 : -1) ||
            !RequireReportSample(samples, @"greenOverRoot", 150, 70, -1) ||
            !RequireReportSample(samples, @"blue", 130, 110, -1) ||
            !RequireReportSample(samples, @"rootAfterLayers", 240, 240, -1)) return 1;
    } @catch (NSException *exception) {
        return ProbeReportFailure([NSString stringWithFormat:@"%@: %@",
            exception.name, exception.reason]);
    }
    printf("probe report: scene 0 pixels, selectors and key errors passed\n");
    return 0;
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
            if (!device) { fprintf(stderr, "scene0 key error: no Metal device\n"); return 2; }
            MTLTextureDescriptor *descriptor = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:kSceneWidth height:kSceneHeight mipmapped:NO];
            descriptor.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
            id<MTLTexture> texture = [device newTextureWithDescriptor:descriptor];
            if (!texture) { fprintf(stderr, "scene0 key error: texture creation failed\n"); return 3; }
            id<MTLCommandQueue> queue = [device newCommandQueue];
            if (!queue) { fprintf(stderr, "scene0 key error: command queue creation failed\n"); return 3; }
            CARenderer *renderer = [CARenderer rendererWithMTLTexture:texture options:@{kCARendererMetalCommandQueue: queue}];
            if (!renderer) { fprintf(stderr, "scene0 key error: CARenderer refused texture\n"); return 3; }
            renderer.layer = scene0();
            renderer.bounds = CGRectMake(0, 0, kSceneWidth, kSceneHeight);
            [CATransaction flush];
            [renderer beginFrameAtTime:CACurrentMediaTime() timeStamp:NULL];
            [renderer addUpdateRect:renderer.bounds];
            [renderer render];
            [renderer endFrame];
            id<MTLCommandBuffer> fence = [queue commandBuffer];
            if (!fence) { fprintf(stderr, "scene0 key error: fence creation failed\n"); return 5; }
            [fence commit];
            [fence waitUntilCompleted];
            NSError *fenceError = fence.error;
            if (fence.status != MTLCommandBufferStatusCompleted || fenceError) {
                fprintf(stderr, "scene0 key error: fence status=%ld error=%s\n",
                    (long)fence.status, fenceError.localizedDescription.UTF8String ?: "none");
                return 5;
            }
            NSMutableData *readback = [NSMutableData dataWithLength:kSceneByteCount];
            uint8_t *pixels = readback.mutableBytes;
            if (!pixels) { fprintf(stderr, "scene0 key error: readback allocation failed\n"); return 6; }
            [texture getBytes:pixels bytesPerRow:kSceneWidth * 4 fromRegion:MTLRegionMake2D(0, 0, kSceneWidth, kSceneHeight) mipmapLevel:0];
            uint64_t hash = 0xcbf29ce484222325ULL;
            size_t nonzeroBytes = 0;
            for (size_t i = 0; i < kSceneByteCount; i++) {
                if (pixels[i]) nonzeroBytes++;
                hash = (hash ^ pixels[i]) * 0x100000001b3ULL;
            }
            printf("device=%s nonzeroBytes=%zu hash=%016llx\n",
                device.name.UTF8String, nonzeroBytes, (unsigned long long)hash);
            const size_t mismatches = CheckNativePixels(pixels);
            FILE *file = fopen("/tmp/ca-scene0.bgra", "wb");
            if (file) { fwrite(pixels, 4, kSceneWidth * kSceneHeight, file); fclose(file); }
            if (mismatches) return 4;
            printf("scene0: all %u pixels matched background, opaque layers and alpha blends\n",
                kSceneWidth * kSceneHeight);
            return 0;
        } @catch (NSException *exception) {
            fprintf(stderr, "scene0 key error: %s: %s\n",
                exception.name.UTF8String, exception.reason.UTF8String);
            return 7;
        }
    }
}
