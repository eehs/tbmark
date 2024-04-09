#ifndef TBMARK_DEBUG_H
#define TBMARK_DEBUG_H

#include <errno.h>

char *strerror(int errnum);
void printf_with_prefix(const char *prefix, const char *msg, va_list vargs);

#define __printf __attribute__((format(printf, 1, 2)))
void __printf LOG(const char *msg, ...);
void __printf ERROR(const char *msg, ...);

#define ASSERT_EXIT(res) \
	if (!(res)) { \
		(ERROR("\e[31m%s\e[0m @ %s:%d (%s)\n", strerror(errno), __func__, __LINE__, __FILE__)); \
		exit(1); \
	} \

#define ASSERT_RET(res) \
	if (!(res)) { \
		(ERROR("\e[31m%s\e[0m @ %s:%d (%s)\n", strerror(errno), __func__, __LINE__, __FILE__)); \
		return -1; \
	} \

#define ASSERT_NULL(res) \
	if (!(res)) { \
		(ERROR("\e[31m%s\e[0m @ %s:%d (%s)\n", strerror(errno), __func__, __LINE__, __FILE__)); \
		return NULL; \
	} \

#endif // TBMARK_DEBUG_H
