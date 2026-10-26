// Hardware capability check for the ARM64e signing/authenticated-branch boundary.
// It uses only our own code and the current process keys.
.arch armv8.3-a
.arch_extension pauth
.text
.p2align 2
.global hm_pac_probe_entry
.hidden hm_pac_probe_entry
.type hm_pac_probe_entry,%function
hm_pac_probe_entry:
    pacibsp
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x0, .Ltarget
    mov x1, #0x484d
    pacia x0, x1
    blraa x0, x1
    cmp w0, #42
    b.ne .Lreturn
    // Exercise the same IA/zero authentication helper used for guest IMPs.
    adr x0, .Ltarget
    paciza x0
    bl hm_pac_auth_function
    blr x0
.Lreturn:
    ldp x29, x30, [sp], #16
    autibsp
    ret
.Ltarget:
    mov w0, #42
    ret
.size hm_pac_probe_entry, .-hm_pac_probe_entry
.section .note.GNU-stack,"",%progbits
