.data
	extern NtCreateFileSSN:DWORD

.code
	NtCreateFile proc
		mov r10, rcx
		mov eax, NtCreateFileSSN
		syscall
		ret
	NtCreateFile endp
end