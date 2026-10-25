cmake_minimum_required(VERSION 3.16)
project(Harmintosh LANGUAGES CXX ASM)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(DEFINED PACKAGE_FIND_FILE)
    include(${PACKAGE_FIND_FILE})
endif()

get_filename_component(HM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
find_program(CARGO_EXECUTABLE cargo HINTS "$ENV{HOME}/.cargo/bin" REQUIRED)
if(OHOS_ARCH STREQUAL "arm64-v8a" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(HM_RUST_TARGET aarch64-unknown-linux-ohos)
elseif(OHOS_ARCH STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(HM_RUST_TARGET x86_64-unknown-linux-ohos)
else()
    message(FATAL_ERROR "Unsupported HarmonyOS architecture: ${OHOS_ARCH}")
endif()

set(HM_CARGO_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust")
set(HM_RUST_LIBRARY "${HM_CARGO_DIR}/${HM_RUST_TARGET}/release/libharmintosh_runtime.a")
file(GLOB_RECURSE HM_RUST_SOURCES CONFIGURE_DEPENDS "${HM_ROOT}/runtime/src/*.rs")
add_custom_command(OUTPUT "${HM_RUST_LIBRARY}"
    COMMAND "${CMAKE_COMMAND}" -E env "CARGO_TARGET_DIR=${HM_CARGO_DIR}"
        "${CARGO_EXECUTABLE}" build --manifest-path "${HM_ROOT}/runtime/Cargo.toml"
        --target "${HM_RUST_TARGET}" --release --lib --locked
    DEPENDS ${HM_RUST_SOURCES} "${HM_ROOT}/runtime/Cargo.toml" "${HM_ROOT}/runtime/Cargo.lock"
    COMMENT "Building Rust Mach-O runtime for ${HM_RUST_TARGET}" VERBATIM)
add_custom_target(harmintosh_rust_build DEPENDS "${HM_RUST_LIBRARY}")
add_library(harmintosh_runtime STATIC IMPORTED)
set_target_properties(harmintosh_runtime PROPERTIES IMPORTED_LOCATION "${HM_RUST_LIBRARY}")
add_dependencies(harmintosh_runtime harmintosh_rust_build)

set(HM_NATIVE_SOURCES napi_init.cpp "${HM_ROOT}/native/platform/execution_probe.cpp"
    "${HM_ROOT}/native/platform/cache_image.cpp" "${HM_ROOT}/native/platform/code_signature.cpp" "${HM_ROOT}/native/platform/guest_files.cpp"
    "${HM_ROOT}/native/platform/data_pager.cpp" "${HM_ROOT}/native/graphics/bgra_frame.cpp"
    "${HM_ROOT}/native/graphics/harmony_surface.cpp")
if(HM_RUST_TARGET STREQUAL "aarch64-unknown-linux-ohos")
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(HM_PACKED_PROBE "${CMAKE_CURRENT_BINARY_DIR}/packed_probe.S")
    add_custom_command(OUTPUT "${HM_PACKED_PROBE}"
        COMMAND "${Python3_EXECUTABLE}" "${HM_ROOT}/tools/pack_probe.py"
            "${HM_ROOT}/tests/fixtures/return42.macho" "${HM_PACKED_PROBE}"
        DEPENDS "${HM_ROOT}/tools/pack_probe.py" "${HM_ROOT}/tools/prepare_ipa.py"
            "${HM_ROOT}/tests/fixtures/return42.macho" VERBATIM)
    list(APPEND HM_NATIVE_SOURCES "${HM_PACKED_PROBE}")
    set(HM_DARWIN_DIR "${CMAKE_CURRENT_BINARY_DIR}/darwin")
    add_custom_command(OUTPUT "${HM_DARWIN_DIR}/darwin_probes.S" "${HM_DARWIN_DIR}/darwin_probes.h"
        COMMAND "${Python3_EXECUTABLE}" "${HM_ROOT}/tools/pack_darwin_probe.py" "${HM_DARWIN_DIR}"
        DEPENDS "${HM_ROOT}/tools/pack_darwin_probe.py" "${HM_ROOT}/tools/prepare_ipa.py" VERBATIM)
    list(APPEND HM_NATIVE_SOURCES "${HM_DARWIN_DIR}/darwin_probes.S" "${HM_DARWIN_DIR}/darwin_probes.h")
    list(APPEND HM_NATIVE_SOURCES "${HM_ROOT}/native/abi/pac_probe.S")
    list(APPEND HM_NATIVE_SOURCES "${HM_ROOT}/native/abi/guest_stack.S")
    list(APPEND HM_NATIVE_SOURCES "${HM_ROOT}/native/abi/pac_sign.S")
    get_filename_component(HM_LLVM_DIR "${CMAKE_ASM_COMPILER}" DIRECTORY)
    set(HM_BOOTSTRAP_DIR "${CMAKE_CURRENT_BINARY_DIR}/bootstrap")
    add_custom_command(OUTPUT "${HM_BOOTSTRAP_DIR}/bootstrap.macho"
        COMMAND "${Python3_EXECUTABLE}" "${HM_ROOT}/tools/make_bootstrap_fixture.py" "${HM_BOOTSTRAP_DIR}"
            --clang "${CMAKE_ASM_COMPILER}" --objcopy "${HM_LLVM_DIR}/llvm-objcopy"
        DEPENDS "${HM_ROOT}/tools/make_bootstrap_fixture.py" VERBATIM)
    add_custom_command(OUTPUT "${HM_BOOTSTRAP_DIR}/packed_bootstrap.S" "${HM_BOOTSTRAP_DIR}/packed_bootstrap.h"
            "${HM_BOOTSTRAP_DIR}/packed_bootstrap.ld"
        COMMAND "${Python3_EXECUTABLE}" "${HM_ROOT}/tools/pack_macho.py"
            "${HM_BOOTSTRAP_DIR}/bootstrap.macho" "${HM_BOOTSTRAP_DIR}" --role bootstrap
        DEPENDS "${HM_BOOTSTRAP_DIR}/bootstrap.macho" "${HM_ROOT}/tools/pack_macho.py" ${HM_RUST_SOURCES} VERBATIM)
    list(APPEND HM_NATIVE_SOURCES "${HM_BOOTSTRAP_DIR}/packed_bootstrap.S" "${HM_BOOTSTRAP_DIR}/packed_bootstrap.h")
    set(HM_APPLE_DYLD "${HM_ROOT}/artifacts/ios27-system/bootstrap/dyld")
    if(EXISTS "${HM_APPLE_DYLD}")
        set(HM_DYLD_DIR "${CMAKE_CURRENT_BINARY_DIR}/apple-dyld")
        add_custom_command(OUTPUT "${HM_DYLD_DIR}/packed_dyld.S" "${HM_DYLD_DIR}/packed_dyld.h"
                "${HM_DYLD_DIR}/packed_dyld.ld"
            COMMAND "${Python3_EXECUTABLE}" "${HM_ROOT}/tools/prepare_bootstrap.py"
                "${HM_APPLE_DYLD}" "${HM_ROOT}/artifacts/ios27-system/cache/dyld_shared_cache_arm64e" "${HM_DYLD_DIR}"
            DEPENDS "${HM_APPLE_DYLD}" "${HM_ROOT}/tools/prepare_bootstrap.py" "${HM_ROOT}/tools/pack_macho.py"
                "${HM_ROOT}/tools/pack_cache.py" ${HM_RUST_SOURCES} VERBATIM)
        list(APPEND HM_NATIVE_SOURCES "${HM_DYLD_DIR}/packed_dyld.S" "${HM_DYLD_DIR}/packed_dyld.h")
    endif()
    set(HM_TARGET_IMAGE "${HM_ROOT}/harmintosh/src/main/resources/rawfile/target/executable")
    if(EXISTS "${HM_TARGET_IMAGE}")
        set(HM_AOT_DIR "${CMAKE_CURRENT_BINARY_DIR}/aot")
        set(HM_TARGET_CACHE_DEPENDENCY)
        if(EXISTS "${HM_ROOT}/artifacts/ios27-system/cache/dyld_shared_cache_arm64e")
            set(HM_TARGET_CACHE_DEPENDENCY "${HM_ROOT}/artifacts/ios27-system/cache/dyld_shared_cache_arm64e")
        endif()
        add_custom_command(OUTPUT "${HM_AOT_DIR}/packed_target.S" "${HM_AOT_DIR}/packed_target.h"
                "${HM_AOT_DIR}/packed_target.ld"
            COMMAND "${Python3_EXECUTABLE}" "${HM_ROOT}/tools/pack_macho.py" "${HM_TARGET_IMAGE}" "${HM_AOT_DIR}"
            DEPENDS "${HM_ROOT}/tools/pack_macho.py" "${HM_ROOT}/tools/pack_cache.py"
                "${HM_TARGET_IMAGE}" ${HM_TARGET_CACHE_DEPENDENCY} ${HM_RUST_SOURCES} VERBATIM)
        list(APPEND HM_NATIVE_SOURCES "${HM_AOT_DIR}/packed_target.S" "${HM_AOT_DIR}/packed_target.h")
    endif()
endif()
add_library(harmintosh SHARED ${HM_NATIVE_SOURCES})
target_compile_definitions(harmintosh PRIVATE _GNU_SOURCE)
if(DEFINED HM_DARWIN_DIR)
    target_include_directories(harmintosh PRIVATE "${HM_DARWIN_DIR}")
endif()
if(DEFINED HM_BOOTSTRAP_DIR)
    target_include_directories(harmintosh PRIVATE "${HM_BOOTSTRAP_DIR}")
    target_link_options(harmintosh PRIVATE "-Wl,-T,${HM_BOOTSTRAP_DIR}/packed_bootstrap.ld")
    set_property(TARGET harmintosh APPEND PROPERTY LINK_DEPENDS "${HM_BOOTSTRAP_DIR}/packed_bootstrap.ld")
endif()
if(DEFINED HM_AOT_DIR)
    target_include_directories(harmintosh PRIVATE "${HM_AOT_DIR}")
    target_compile_definitions(harmintosh PRIVATE HM_HAS_AOT_TARGET=1)
    target_link_options(harmintosh PRIVATE "-Wl,-T,${HM_AOT_DIR}/packed_target.ld")
    set_property(TARGET harmintosh APPEND PROPERTY LINK_DEPENDS "${HM_AOT_DIR}/packed_target.ld")
endif()
if(DEFINED HM_DYLD_DIR)
    target_include_directories(harmintosh PRIVATE "${HM_DYLD_DIR}")
    target_compile_definitions(harmintosh PRIVATE HM_HAS_BOOT_DYLD=1)
    target_link_options(harmintosh PRIVATE "-Wl,-T,${HM_DYLD_DIR}/packed_dyld.ld")
    set_property(TARGET harmintosh APPEND PROPERTY LINK_DEPENDS "${HM_DYLD_DIR}/packed_dyld.ld")
endif()
target_include_directories(harmintosh PRIVATE "${HM_ROOT}/native/include" "${HM_ROOT}/native/platform"
    "${HM_ROOT}/native/graphics")
set(HM_CACHE_ELF "${HM_ROOT}/artifacts/ios27-aot/libhm_ioscache.so")
if(HM_RUST_TARGET STREQUAL "aarch64-unknown-linux-ohos" AND EXISTS "${HM_CACHE_ELF}")
    add_library(hm_ioscache SHARED IMPORTED)
    set_target_properties(hm_ioscache PROPERTIES IMPORTED_LOCATION "${HM_CACHE_ELF}")
    target_compile_definitions(harmintosh PRIVATE HM_HAS_IOS_CACHE=1)
    target_link_libraries(harmintosh PRIVATE hm_ioscache)
endif()
target_link_libraries(harmintosh PRIVATE harmintosh_runtime libace_napi.z.so libhilog_ndk.z.so
    native_window dl m)
target_link_options(harmintosh PRIVATE "-Wl,--exclude-libs,ALL")
