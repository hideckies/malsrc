; Resources
;	- https://github.com/Maldev-Academy/HellHall/blob/main/Hell'sHall/Hell'sHall/AsmHell.asm

PUBLIC SetConfig
PUBLIC HellsHall

.data
	dwSSN DWORD 0h	; SYSCALL SSN
	qAddr QWORD 0h	; `syscall` instruction address

.code
	SetConfig PROC
		mov dwSSN, ecx
		mov qAddr, rdx
		ret
	SetConfig ENDP

	HellsHall PROC
		mov r10, rcx
		mov eax, dwSSN
		jmp qword ptr [qAddr]
		ret
	HellsHall ENDP

end