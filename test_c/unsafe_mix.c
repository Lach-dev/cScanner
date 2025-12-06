// unsafe_mix.c
#include <stdio.h>
#include <string.h>

void process(char *input1, char *input2) {
    char buf1[10];
    char buf2[20];

    strcpy(buf1, input1);             // overflow possible
    sprintf(buf2, "%s", input2);      // flagged (sprintf)
    printf(input1);                   // format string vuln
}
