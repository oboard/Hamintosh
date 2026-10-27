#ifndef HARMONIOS_RUNTIME_H
#define HARMONIOS_RUNTIME_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMRuntimeContext: Opaque handle representing an isolated Harmonios
 * compatibility runtime instance.
 */
typedef struct HMRuntimeContext HMRuntimeContext;

/**
 * HMAppDescriptor: Application metadata provided by Harmonios Converter
 * or the launcher host to initialize the iOS execution environment.
 */
typedef struct {
    const char *bundle_id;
    const char *executable;
    const char *app_root;
    const char *data_root;
    uint32_t flags;
} HMAppDescriptor;

/**
 * Stable Runtime Lifecycle ABI
 */
HMRuntimeContext *hm_runtime_create(void);
void hm_runtime_destroy(HMRuntimeContext *ctx);
int hm_app_bootstrap(HMRuntimeContext *ctx, const HMAppDescriptor *descriptor);

/**
 * Syscall Direct Dispatch ABI
 * Used by AOT callsite rewrite: bl hm_syscall_dispatch
 * Replaces high-frequency signal/trap faults with direct branch links.
 */
int64_t hm_syscall_dispatch(HMRuntimeContext *ctx, uint32_t number, const uint64_t *args);

/**
 * High-frequency Direct BSD Calls
 */
int64_t hm_bsd_open(HMRuntimeContext *ctx, const char *path, int32_t flags, int32_t mode);
int64_t hm_bsd_read(HMRuntimeContext *ctx, int32_t fd, void *buf, size_t count);
int64_t hm_bsd_close(HMRuntimeContext *ctx, int32_t fd);
int64_t hm_bsd_mmap(HMRuntimeContext *ctx, void *addr, size_t len, int32_t prot, int32_t flags, int32_t fd, int64_t offset);
int64_t hm_bsd_munmap(HMRuntimeContext *ctx, void *addr, size_t len);

/**
 * High-frequency Direct Mach IPC Calls
 */
uint32_t hm_mach_msg(
    HMRuntimeContext *ctx,
    void *msg,
    uint32_t option,
    uint32_t send_size,
    uint32_t rcv_size,
    uint32_t rcv_name,
    uint32_t timeout,
    uint32_t notify
);

uint32_t hm_mach_port_allocate(HMRuntimeContext *ctx, uint32_t target_task, uint32_t right, uint32_t *name);
uint32_t hm_mach_port_deallocate(HMRuntimeContext *ctx, uint32_t target_task, uint32_t name);

#ifdef __cplusplus
}
#endif

#endif /* HARMONIOS_RUNTIME_H */
