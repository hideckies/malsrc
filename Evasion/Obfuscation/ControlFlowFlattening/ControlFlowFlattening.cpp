/*
Title: Control Flow Flattening
Resources:
    - https://news.sophos.com/en-us/2022/05/04/attacking-emotets-control-flow-flattening/
    - https://zerotistic.blog/posts/cff-remover/
*/
#include <Windows.h>
#include <stdio.h>

VOID ControlFlowFlattening() {
    /*
    * 
    * Original code:
    * 
    * for (int i = 0; i < 10; i++) {
    *   printf("Hello World!\n");
    * }
    * 
    */

    int i = 0;
    int state = 0;

    while (1) {
        switch (state) {
        case 0:
            i = 0;
            state = 1;
            break;

        case 1:
            if (i >= 10)
                state = 4;
            else
                state = 2;
            break;

        case 2:
            printf("Hello, World!\n");
            state = 3;
            break;

        case 3:
            i++;
            state = 1;
            break;

        case 4:
            return;
        }
    }
}
