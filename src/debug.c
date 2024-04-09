#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "debug.h"

void print_with_prefix(const char *prefix, const char *msg, va_list vargs) {
        if (prefix)
                fprintf(stderr, "%s ", prefix);

        vfprintf(stderr, msg, vargs);
        fprintf(stderr, "\n");
}

void LOG(const char *msg, ...) {
        va_list args;

        va_start(args, msg);
        print_with_prefix("[DEBUG]", msg, args);
        va_end(args);
}

void ERROR(const char *msg, ...) {
        va_list args;

        va_start(args, msg);
        print_with_prefix("[ERROR]", msg, args);
        va_end(args);
}
