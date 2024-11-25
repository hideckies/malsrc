; Resources
;	- https://github.com/am0nsec/HellsGate/blob/master/HellsGate/hellsgate.asm

PUBLIC HellsGate
PUBLIC HellDescent

.data
	wSystemCall DWORD 000h

.code 
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	HellDescent ENDP
end