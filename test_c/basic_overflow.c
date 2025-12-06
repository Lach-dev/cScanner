// basic_overflow.c
#include <string.h>

void handle_user(char *name, char *suffix) {
    char buffer[32];

    strcpy(buffer, name);      // unsafe
    strcat(buffer, suffix);    // unsafe
}
