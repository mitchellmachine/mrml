.text
.globl entry
entry:
    subq $40, %rsp
    xorl %ecx, %ecx
    callq profiled_value
    cmpq $1, %rax
    jne .Lfirst_failed
    movl $7, %ecx
    callq profiled_value
    cmpq $2, %rax
    jne .Lsecond_failed
    callq __llvm_profile_write_file
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
