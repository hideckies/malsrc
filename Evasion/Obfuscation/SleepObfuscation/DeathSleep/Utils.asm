.data
    public GetRsp
    public MoveRsp

.code

GetRsp proc
    mov rax, rsp
    add rax, 8
    ret
GetRsp endp

MoveRsp proc
    mov r8, [rsp]
    add rsp, 8

    mov r9, rcx

    mov rcx, 28h
    add rcx, rdx

    add r9, rcx

    ; Backup rsi, rdi
    mov r10, rsi
    mov r11, rdi

    mov rsi, rsp

    ; rdi holds the source address
    mov rdi, rsi
    sub rdi, r9

    ; rdi holds the destination address
    ; repeat operation movsb rcx times
    rep movsb

    ; restore rsi, rdi
    mov rsi, r10
    mov rdi, r11

    sub rsp, r9
    jmp r8
MoveRsp endp

END