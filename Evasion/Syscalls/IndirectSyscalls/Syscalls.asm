.data
	extern NtCreateFileSSN:DWORD
	extern NtCreateFileSyscall:QWORD

.code
	NtCreateFile proc
		mov r10, rcx
		mov eax, NtCreateFileSSN
		jmp qword ptr NtCreateFileSyscall
		ret
	NtCreateFile endp
end