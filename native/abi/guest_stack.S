.text
.p2align 2
.global hm_enter_guest_stack
.hidden hm_enter_guest_stack
.type hm_enter_guest_stack,%function
// int hm_enter_guest_stack(entry, stackPointer, expectedMachHeader)
// A conforming guest callee preserves x19; faults leave through the C++ signal guard.
hm_enter_guest_stack:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x29, sp
    mov x19, sp
    mov x9, x0
    mov x0, x2
    mov sp, x1
    blr x9
    mov sp, x19
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size hm_enter_guest_stack, .-hm_enter_guest_stack

.p2align 2
.global hm_enter_apple_dyld
.hidden hm_enter_apple_dyld
.type hm_enter_apple_dyld,%function
// Enter the standalone __dyld_start like a kernel launch. Apple dyld owns
// the later transition and register ABI for its matching cached image.
hm_enter_apple_dyld:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x19, sp
    mov x9, x0
    mov sp, x1
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x5, #0
    mov x6, #0
    mov x7, #0
    mov x8, #0
    blr x9
    mov sp, x19
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size hm_enter_apple_dyld, .-hm_enter_apple_dyld

.p2align 2
.global hm_boot_stack_probe_entry
.hidden hm_boot_stack_probe_entry
.type hm_boot_stack_probe_entry,%function
hm_boot_stack_probe_entry:
    ldr x8, [sp]
    cmp x8, x0
    b.ne .Lfail
    ldr x8, [sp, #8]
    cmp x8, #1
    b.ne .Lfail
    ldr x8, [sp, #16]
    ldrb w8, [x8]
    cmp w8, #47
    b.ne .Lfail
    ldr x8, [sp, #24]
    cbnz x8, .Lfail
    ldr x8, [sp, #32]
    ldrb w8, [x8]
    cmp w8, #77
    b.ne .Lfail
    ldr x8, [sp, #40]
    ldrb w8, [x8]
    cmp w8, #77
    b.ne .Lfail
    ldr x8, [sp, #48]
    ldrb w8, [x8]
    cmp w8, #77
    b.ne .Lfail
    ldr x8, [sp, #56]
    cbnz x8, .Lfail
    ldr x8, [sp, #64]
    ldrb w8, [x8]
    cmp w8, #101
    b.ne .Lfail
    ldr x8, [sp, #72]
    ldrb w8, [x8]
    cmp w8, #112
    b.ne .Lfail
    ldr x8, [sp, #80]
    cbnz x8, .Lfail
    mov w0, #42
    ret
.Lfail:
    mov w0, #-1
    ret
.size hm_boot_stack_probe_entry, .-hm_boot_stack_probe_entry
.section .note.GNU-stack,"",%progbits
