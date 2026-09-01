.section .rdata,"dr"
.Lprofile_name:
    .asciz "profile.profraw"

.text
.globl entry
entry:
    subq $40, %rsp
    leaq .Lprofile_name(%rip), %rcx
    callq __llvm_profile_set_filename
    xorl %ecx, %ecx
    callq profiled_value
    cmpq $1, %rax
    jne .Lfirst_failed
    movl $7, %ecx
    callq profiled_value
    cmpq $2, %rax
    jne .Lsecond_failed
    callq __llvm_profile_write_file
    testl %eax, %eax
    jne .Lwrite_failed
    movl $42, %eax
    addq $40, %rsp
    retq
.Lfirst_failed:
    movl $81, %eax
    addq $40, %rsp
    retq
.Lsecond_failed:
    movl $82, %eax
    addq $40, %rsp
    retq
.Lwrite_failed:
    movl $83, %eax
    addq $40, %rsp
    retq
