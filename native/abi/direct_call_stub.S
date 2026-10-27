// Direct syscall entry point for AOT callsite rewrite.
// Bypasses the signal/trap handler by directly invoking the runtime dispatcher.
.text
.p2align 2
.global hm_direct_syscall_entry
.hidden hm_direct_syscall_entry
.type hm_direct_syscall_entry,%function
hm_direct_syscall_entry:
    sub sp, sp, #96
    stp x29, x30, [sp, #0]
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    str x27, [sp, #80]

    add x7, sp, #88
    mov x6, x5
    mov x5, x4
    mov x4, x3
    mov x3, x2
    mov x2, x1
    mov x1, x0
    uxtw x0, w16

    bl hm_direct_dispatch

    ldr x1, [sp, #88]
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldr x27, [sp, #80]
    ldp x29, x30, [sp, #0]
    add sp, sp, #96
    ret
.size hm_direct_syscall_entry, .-hm_direct_syscall_entry
.section .note.GNU-stack,"",%progbits
