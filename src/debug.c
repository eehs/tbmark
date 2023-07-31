#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "debug.h"

void LOG(const char *msg, ...) {
	va_list args;
        char formatted_msg[MSG_MAX];

        va_start(args, msg);
        snprintf(formatted_msg, strlen(msg) + 9, "[INFO] %s", msg);
        vfprintf(stdout, formatted_msg, args);

        va_end(args);
}

void ERROR(const char *msg, ...) {
	va_list args;
        char formatted_msg[MSG_MAX];

        va_start(args, msg);
        snprintf(formatted_msg, strlen(msg) + 10, "[ERROR] %s", msg);
        vfprintf(stderr, formatted_msg, args);

        va_end(args);
}
