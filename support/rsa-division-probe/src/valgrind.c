#include <valgrind/memcheck.h>

void mark_secret(void *pointer, unsigned long bytes) {
    VALGRIND_MAKE_MEM_UNDEFINED(pointer, bytes);
}

void release_output(void *pointer, unsigned long bytes) {
    VALGRIND_MAKE_MEM_DEFINED(pointer, bytes);
}

unsigned long property_errors(void) { return VALGRIND_COUNT_ERRORS; }
unsigned long property_running(void) { return RUNNING_ON_VALGRIND; }
