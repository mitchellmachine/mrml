.text
.globl entry
entry:
    subq $40, %rsp
    callq __llvm_profile_write_file
    addq $40, %rsp
    movl $42, %eax
    retq
