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
