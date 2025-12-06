// nested_calls.c
#include <stdio.h>
#include <string.h>

void tricky(char *user) {
    char buffer[16];

    if (strlen(user) > 5)
        strcpy(buffer, user);      // unsafe, nested in if statement

    printf(user);                  // vuln, no literal
}
