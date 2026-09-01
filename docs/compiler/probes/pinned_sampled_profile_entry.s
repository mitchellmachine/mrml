.section .rdata,"dr"
.Lprofile_name:
    .asciz "sampled.profraw"

.text
.globl entry
entry:
    subq $40, %rsp
    leaq .Lprofile_name(%rip), %rcx
    callq __llvm_profile_set_filename
    xorl %ecx, %ecx
    xorl %edx, %edx
    xorl %r8d, %r8d
    callq profiled_condition
    cmpq $2, %rax
    jne .Lexecution_failed
    movl $1, %ecx
    movl $1, %edx
    xorl %r8d, %r8d
    callq profiled_condition
    cmpq $1, %rax
    jne .Lexecution_failed
    callq __llvm_profile_write_file
    testl %eax, %eax
    jne .Lwrite_failed
    movl $42, %eax
    addq $40, %rsp
    retq
.Lexecution_failed:
    movl $81, %eax
    addq $40, %rsp
    retq
.Lwrite_failed:
    movl $82, %eax
    addq $40, %rsp
    retq
