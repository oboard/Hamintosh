#ifndef harmonios_H
#define harmonios_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint64_t slice_offset;
    uint64_t slice_size;
    uint64_t entry_offset;
} HmProbePlan;
typedef struct HmProcess HmProcess;
typedef struct {
    int64_t number;
    uint64_t arguments[8];
    uint64_t result[2];
    uint64_t nzcv;
} HmDarwinTrap;
HmProcess *hm_process_create(uint32_t pid, uint32_t parent_pid, uint64_t thread_id);
void hm_process_set_executable(HmProcess *process, const char *path, size_t length);
void hm_process_set_display(HmProcess *process, uint32_t width, uint32_t height,
    float scale, float native_scale);
uint64_t hm_process_tsd_base(const HmProcess *process);
uint64_t hm_process_resume_pc(const HmProcess *process, uint64_t pc);
typedef uint32_t (*HmVmProtect)(const void *, uint64_t, uint64_t, uint32_t, uint32_t);
void hm_process_set_vm_protect(HmProcess *process, HmVmProtect callback, const void *context);
typedef uint32_t (*HmGetEntropy)(const void *, uint64_t, uint64_t);
void hm_process_set_getentropy(HmProcess *process, HmGetEntropy callback);
typedef uint32_t (*HmCopyOut)(const void *, uint64_t, const uint8_t *, size_t);
typedef uint32_t (*HmCopyIn)(const void *, uint64_t, uint8_t *, size_t);
void hm_process_set_memory(HmProcess *process, HmCopyIn read, HmCopyOut write, uint64_t cache_base);
typedef uint32_t (*HmClock)(const void *, uint32_t, uint64_t *);
typedef void (*HmConsole)(const void *, uint32_t, const uint8_t *, size_t);
void hm_process_set_console(HmProcess *process, HmConsole callback);
void hm_process_set_clock(HmProcess *process, HmClock callback);
typedef uint32_t (*HmVmMap)(const void *, uint64_t *, uint64_t, uint64_t, uint32_t, uint32_t);
void hm_process_set_vm_map(HmProcess *process, HmVmMap callback);
typedef uint32_t (*HmMapFile)(const void *, uint64_t *, uint64_t, uint32_t, int32_t, uint64_t);
void hm_process_set_map_file(HmProcess *process, HmMapFile callback);
typedef uint32_t (*HmVmDeallocate)(const void *, uint64_t, uint64_t);
void hm_process_set_vm_deallocate(HmProcess *process, HmVmDeallocate callback);
typedef uint32_t (*HmOpen)(const void *, int32_t, const uint8_t *, size_t, uint32_t, uint32_t, int32_t *);
typedef uint32_t (*HmClose)(const void *, int32_t);
typedef uint32_t (*HmDuplicate)(const void *, int32_t, int32_t *);
void hm_process_set_files(HmProcess *process, HmOpen open, HmClose close, HmDuplicate duplicate);
typedef uint32_t (*HmFileRead)(const void *, int32_t, uint8_t *, size_t, int64_t, size_t *);
typedef uint32_t (*HmFileSeek)(const void *, int32_t, int64_t, uint32_t, int64_t *);
void hm_process_set_file_io(HmProcess *process, HmFileRead read, HmFileSeek seek);
typedef uint32_t (*HmFileStat)(const void *, int32_t, const uint8_t *, size_t,
    uint32_t, uint8_t *, size_t);
void hm_process_set_file_stat(HmProcess *process, HmFileStat callback);
typedef uint32_t (*HmCodeSignatureBlob)(const void *, uint32_t, uint64_t, uint64_t);
void hm_process_set_code_signature(HmProcess *process, HmCodeSignatureBlob callback);
typedef uint32_t (*HmResolveFileId)(const void *, uint64_t, uint64_t, uint8_t *, size_t *);
void hm_process_set_resolve_file_id(HmProcess *process, HmResolveFileId callback);
void hm_process_destroy(HmProcess *process);
int32_t hm_darwin_dispatch(const HmProcess *process, HmDarwinTrap *frame);
int32_t hm_build_boot_stack(uint8_t *stack, size_t len, uint64_t header,
    const char *executable, uint64_t *stack_pointer);
typedef uint64_t (*HmSignPointer)(uint64_t pointer, uint64_t storage,
    uint16_t diversity, uint8_t key, uint8_t address_diversity);
int32_t hm_apply_bootstrap_rebases(const uint8_t *original, size_t len,
    uint8_t *mapped, size_t span, HmSignPointer sign, uint64_t *count);
int32_t hm_reset_bootstrap_data(const uint8_t *original, size_t len, uint8_t *mapped, size_t span);
int32_t hm_reset_app_data(const uint8_t *original, size_t len, uint8_t *mapped, size_t span);
const char *hm_runtime_greeting(void);
int32_t hm_probe_plan(const uint8_t *data, size_t len, HmProbePlan *out);
int32_t hm_validate_aot_image(const uint8_t *original, size_t len,
    const uint8_t *mapped, size_t span, uint64_t *entry_offset);
char *hm_inspect_json(const char *executable_path, const char *sysroot_path);
void hm_string_free(char *value);
#ifdef __cplusplus
}
#endif
#endif
