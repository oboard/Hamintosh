.arch armv8.3-a
.arch_extension pauth
.text
.p2align 2
.global hm_pac_sign_pointer
.hidden hm_pac_sign_pointer
.type hm_pac_sign_pointer,%function
// x0 = pointer, x1 = modifier, w2 = key (IA=0, IB=1, DA=2, DB=3).
hm_pac_sign_pointer:
    cmp w2,#0
    b.eq .Lia
    cmp w2,#1
    b.eq .Lib
    cmp w2,#2
    b.eq .Lda
    pacdb x0,x1
    ret
.Lia:
    pacia x0,x1
    ret
.Lib:
    pacib x0,x1
    ret
.Lda:
    pacda x0,x1
    ret
.size hm_pac_sign_pointer,.-hm_pac_sign_pointer
.section .note.GNU-stack,"",%progbits

.text
.p2align 2
.global hm_pac_strip_instruction
.hidden hm_pac_strip_instruction
.type hm_pac_strip_instruction,%function
// Strip a saved return address for diagnostic symbolication only.
hm_pac_strip_instruction:
    xpaci x0
    and x0, x0, #0x0000ffffffffffff
    ret
.size hm_pac_strip_instruction,.-hm_pac_strip_instruction

.text
.p2align 2
.global hm_pac_strip_data
.hidden hm_pac_strip_data
.type hm_pac_strip_data,%function
hm_pac_strip_data:
    xpacd x0
    and x0, x0, #0x0000ffffffffffff
    ret
.size hm_pac_strip_data,.-hm_pac_strip_data

.text
.p2align 2
.global hm_pac_auth_function
.hidden hm_pac_auth_function
.type hm_pac_auth_function,%function
// Authenticate an ARM64e C/IMP function pointer with its ABI IA/zero modifier.
// A failed authentication remains invalid and faults at the guarded call.
hm_pac_auth_function:
    autiza x0
    ret
.size hm_pac_auth_function,.-hm_pac_auth_function
