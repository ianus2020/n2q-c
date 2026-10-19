/* Deliberately invalid operations to test the sanitizer gate, never library code. */
#include <limits.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "control")) return 0;
    if (!strcmp(argv[1], "undefined")) {
        volatile int value = INT_MAX;
        volatile int result = value + 1;
        (void)result;
        return 0;
    }
    if (!strcmp(argv[1], "address")) {
        unsigned char *memory = malloc(32);
        if (!memory) return 2;
        memory[0] = 0;
        volatile unsigned char *stale = memory;
        free(memory);
        return *stale;
    }
    return 2;
}
