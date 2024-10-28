; Resources
;   - https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_exitfunk.asm
exitfunc:
    mov ebx, 0x0A2A1DE0         ; This is EXITFUNC that is specified by user. The hash of kernel32.dll!ExitThread.
    mov r10d, 0x9DBD95A6        ; The hash of kernel32.dll!GetVersion.
    call rbp                    ; Call GetVersion();
    add rsp, 0x28               ; Cleanup the default param space on stack
    cmp al, byte 6              ; If we are not running on Windows Vista, 2008 or 7
    jl short call_exitfunc      ; Call the exit function
    cmp bl, 0xE0                ; If we are trying a call to kernel32.dll!ExitThread on Windows vista, 2008 or 7
    jne short call_exitfunc
    mov ebx, 0x6F721347         ; The hash of ntdll.dll!RtlExitUserThread.
; Call the exitfunc
call_exitfunc:
    push byte 0
    pop rcx                     ; Set the exit function parameter
    mov r10d, ebx               ; Place the correct EXITFUNC into r10d
    call rbp                    ; Call EXITFUNC(0)
