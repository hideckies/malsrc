#ifndef NTQUEUEAPCTHREADEXGADGETINJECTION_HPP
#define TQUEUEAPCTHREADEXGADGETINJECTION_HPP

#include <Windows.h>

#define MAX_GADGETS 512
#define RANDOM_NUM(min, max) (rand() % (max + 1 - min) + min)

BOOL ValidGadget(PBYTE pAddr);
LPVOID FindGadget(HANDLE hProcess, LPCWSTR lpModuleName);
BOOL NtQueueApcThreadExGadgetInjection();

#endif // TQUEUEAPCTHREADEXGADGETINJECTION_HPP