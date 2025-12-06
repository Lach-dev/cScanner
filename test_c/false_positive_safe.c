// false_positive_safe.c
#include <stdio.h>
#include <string.h>

void safe_examples() {
    char buf[32];

    snprintf(buf, sizeof(buf), "Hello %s", "World");  // safe replacement
    printf("Value: %d\n", 42);                        // literal first arg
    memcpy(buf, "abcd", 4);                           // fits buffer
}
