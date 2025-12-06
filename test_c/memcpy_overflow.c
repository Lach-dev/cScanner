// memcpy_overflow.c
#include <string.h>

void copy_data(char *src) {
    char small[8];

    memcpy(small, src, 16);   // 16 > 8 : overflow
}
