.data
    extern SleepEx : PROC
    public QuadSleep

.code

QuadSleep proc
    sub rsp, 28h               ;0x28
    lea r10, exit
    push r10                   ;0x30
    push r9                    ;0x38

    mov r10, 0FFFFFFFFh
    push r10                   ; first arg ;0x40
    push rcx                   ;0x48
    mov r10, 1
    push r10                   ; second arg ;0x50
    push rdx                   ;0x58

    lea r10, [rdx + 1]
    push r10                   ;0x60

    sub rsp, 28h               ;0x88
    push r8                    ;0x90
    push r9                    ;0x98
    mov r10, 0FFFFFFFFh
    push r10                   ; first arg ;0xA0
    push rcx                   ;0xA8
    mov r10, 1
    push r10                   ; second arg ;0xB0
    push rdx                   ;0xB8

    lea r10, [rdx + 1]
    push r10                   ;0xC0

    sub rsp, 28h               ;0xE8
    push r8                    ;0xF0
    push r9                    ;0xF8
    mov r10, 0FFFFFFFFh
    push r10                   ; first arg ;0x100
    push rcx                   ;0x108
    mov r10, 1
    push r10                   ; second arg ;0x110
    push rdx                   ;0x118

    lea r10, [rdx + 1]
    push r10                   ;0x120

    sub rsp, 28h               ;0x148
    push r8                    ;0x150
    mov rcx, 0FFFFFFFFh        ; first arg
    mov rdx, 1                 ; second arg

    jmp r9

exit:
    add rsp, 28h
    ret
QuadSleep endp

END