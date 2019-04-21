#ifndef H_GPGSETUP_UTIL
#define H_GPGSETUP_UTIL

#include <unistd.h>

static inline ssize_t full_write(int fd, const void *buf, size_t count)
{
	ssize_t r, t = 0;
	while (count && (r = write(fd, buf, count))) {
		if (r == -1)
			return -1;
		t += r;
		buf += r;
		count -= r;
	}
	return t;
}

#endif // H_GPGSETUP_UTIL
