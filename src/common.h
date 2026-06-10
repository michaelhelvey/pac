#ifndef _MOD_COMMON_H
#define _MOD_COMMON_H

#include <stdlib.h>

typedef struct string_view_t {
    char *ptr;
    size_t len;
} string_view_t;

#define str_view_literal(str) { .ptr = str, .len = sizeof(str) - 1 }

#ifdef DEBUG
#define debug_assert(a) assert(a)
#else
#define debug_assert(a) \
    do {                \
    } while (0)
#endif

#endif // _MOD_COMMON_H
