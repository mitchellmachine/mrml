.section .rdata,"dr"
.Lprofile_name:
    .asciz "value.profraw"

.text
.globl entry
entry:
    subq $40, %rsp
    leaq .Lprofile_name(%rip), %rcx
    callq __llvm_profile_set_filename
    movl $7, %ecx
    leaq .Lcallback(%rip), %rdx
    callq profile_indirect
    cmpq $8, %rax
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
.Lcallback:
    leaq 1(%rcx), %rax
    retq
