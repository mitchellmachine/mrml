.text
.globl memcpy
memcpy:
    movq %rcx, %rax
    testq %r8, %r8
    je .Lmemcpy_done
.Lmemcpy_loop:
    movb (%rdx), %r9b
    movb %r9b, (%rcx)
    incq %rdx
    incq %rcx
    decq %r8
    jne .Lmemcpy_loop
.Lmemcpy_done:
    retq

.globl memset
memset:
    movq %rcx, %rax
    testq %r8, %r8
    je .Lmemset_done
.Lmemset_loop:
    movb %dl, (%rcx)
    incq %rcx
    decq %r8
    jne .Lmemset_loop
.Lmemset_done:
    retq

.globl memmove
memmove:
    movq %rcx, %rax
    cmpq %rdx, %rcx
    jbe .Lmemmove_forward
    leaq (%rdx,%r8), %r9
    cmpq %r9, %rcx
    jae .Lmemmove_forward
    testq %r8, %r8
    je .Lmemmove_done
    addq %r8, %rcx
    addq %r8, %rdx
.Lmemmove_backward_loop:
    decq %rcx
    decq %rdx
    movb (%rdx), %r9b
    movb %r9b, (%rcx)
    decq %r8
    jne .Lmemmove_backward_loop
    retq
.Lmemmove_forward:
    testq %r8, %r8
    je .Lmemmove_done
.Lmemmove_forward_loop:
    movb (%rdx), %r9b
    movb %r9b, (%rcx)
    incq %rdx
    incq %rcx
    decq %r8
    jne .Lmemmove_forward_loop
.Lmemmove_done:
    retq

.globl memcmp
memcmp:
    testq %r8, %r8
    je .Lmemcmp_equal
.Lmemcmp_loop:
    movzbl (%rcx), %eax
    movzbl (%rdx), %r9d
    cmpl %r9d, %eax
    jne .Lmemcmp_done
    incq %rcx
    incq %rdx
    decq %r8
    jne .Lmemcmp_loop
.Lmemcmp_equal:
    xorl %eax, %eax
    retq
.Lmemcmp_done:
    subl %r9d, %eax
    retq

.globl _RNvCsfLIs8pB8Vef_7___rustc17rust_begin_unwind
_RNvCsfLIs8pB8Vef_7___rustc17rust_begin_unwind:
    int3
.Lpanic_halt:
    jmp .Lpanic_halt

.globl strlen
strlen:
    xorl %eax, %eax
.Lstrlen_loop:
    cmpb $0, (%rcx,%rax)
    je .Lstrlen_done
    incq %rax
    jmp .Lstrlen_loop
.Lstrlen_done:
    retq

.globl _Unwind_Resume
_Unwind_Resume:
    int3
.Lunwind_halt:
    jmp .Lunwind_halt

.globl _RNvCsfLIs8pB8Vef_7___rustc12___rust_alloc
_RNvCsfLIs8pB8Vef_7___rustc12___rust_alloc:
    xorl %eax, %eax
    retq

.globl _RNvCsfLIs8pB8Vef_7___rustc14___rust_dealloc
_RNvCsfLIs8pB8Vef_7___rustc14___rust_dealloc:
    retq

.globl _RNvCsfLIs8pB8Vef_7___rustc14___rust_realloc
_RNvCsfLIs8pB8Vef_7___rustc14___rust_realloc:
    xorl %eax, %eax
    retq

.globl _RNvCsfLIs8pB8Vef_7___rustc26___rust_alloc_error_handler
_RNvCsfLIs8pB8Vef_7___rustc26___rust_alloc_error_handler:
    int3
.Lalloc_error_halt:
    jmp .Lalloc_error_halt

.section .data$shim,"dw"
.globl _RNvCsfLIs8pB8Vef_7___rustc35___rust_no_alloc_shim_is_unstable_v2
_RNvCsfLIs8pB8Vef_7___rustc35___rust_no_alloc_shim_is_unstable_v2:
    .byte 0
