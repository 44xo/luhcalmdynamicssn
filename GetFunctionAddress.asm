section .text
global GetFunctionAddress

GetFunctionAddress:
    sub rsp, 200h
    mov [rsp + 40h], rbp
    mov [rsp + 48h], rdi
    mov [rsp + 50h], rsi
    mov [rsp + 58h], rbx
    mov [rsp + 60h], rcx
    mov [rsp + 68h], r12
    mov [rsp + 70h], r13
    mov [rsp + 78h], r14
    mov [rsp + 80h], r15

    ; Initialize some registers and retrieve the Thread Information Block (TIB)
    xor rax, rax
    lea rsi, [rax + 0x60]
    mov rbx, gs:[rsi]
    mov rbx, [rbx + 0x18] ; PEB
    mov rbx, [rbx + 0x10] ; LDR
    mov rbx, [rbx + 0x30] ; InMemoryOrderModuleList

    ; Loop through the modules in the InMemoryOrderModuleList
FindModule:
    mov rsi, [rbx + 0x28]
    mov rdx, [rsp + 60h]
    cmp rsi, rdx
    jne NotTheModule
    mov rbx, [rbx]
    test rbx, rbx
    jz End
    jmp FindModule

NotTheModule:
    mov rbx, [rbx]
    test rbx, rbx
    jz End

    jmp FindModule

End:
    xor rax, rax
    mov rax, [rsi + 0x1C] ; Export Directory RVA
    add rax, rsi
    mov rsi, rax
    mov rax, [rsi + 0x20] ; AddressOfNames RVA
    add rax, rsi
    mov r9, rax
    mov rcx, [rsi + 0x18] ; NumberOfNames
    xor r10, r10
    xor r11, r11

FindFunction:
    mov eax, [r9 + r11 * 4]
    add rax, rsi
    mov rdx, [rsp + 60h]
    mov r8, rax
    mov ecx, 0xFFFFFFFF
    repe cmpsb
    je Found
    inc r11
    cmp r11, rcx
    jb FindFunction

Found:
    mov eax, [rsi + 0x24]
    add rax, rsi
    mov r9, rax
    mov eax, [r9 + r11 * 2]
    and eax, 0xFFFF
    mov r9, [rsi + 0x1C]
    add r9, rsi
    mov eax, [r9 + rax * 4]
    add rax, rsi

    ; Function epilogue: Restore saved registers and free stack space
    mov rbp, [rsp + 40h]
    mov rdi, [rsp + 48h]
    mov rsi, [rsp + 50h]
    mov rbx, [rsp + 58h]
    mov r12, [rsp + 68h]
    mov r13, [rsp + 70h]
    mov r14, [rsp + 78h]
    mov r15, [rsp + 80h]
    add rsp, 200h
    ret
