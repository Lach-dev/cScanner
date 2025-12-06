// multi_buffer.c
#include <string.h>

void do_stuff(char *a, char *b) {
    char x[4];
    char y[10];

    memcpy(x, a, 6);      // overflow (6 > 4)
    memcpy(y, b, 20);     // overflow (20 > 10)
}
