// format_string.c
#include <stdio.h>

void log_msg(char *msg) {
    printf(msg);              // vuln
}

void ok_msg() {
    printf("Fixed: %d\n", 123);  // safe
}
