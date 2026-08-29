.text
.globl entry
entry:
    subq $40, %rsp
    callq _RNvCsfLIs8pB8Vef_7___rustc25___rdl_alloc_error_handler
    addq $40, %rsp
    retq

.globl rust_eh_personality
rust_eh_personality:
    retq
