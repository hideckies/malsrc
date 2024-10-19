/*
Title: Detect Debugger with Debug Registers
Resources:
	- https://anti-debug.checkpoint.com/techniques/process-memory.html#hardware-breakpoints
*/
#include <Windows.h>
#include <stdio.h>

VOID DetectDebuggerWithDebugRegisters() {
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &ctx)) {
		return;
	}

	if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
		printf("Debugger found! Exit the process.\n");
		ExitProcess(-1);
	}
}
