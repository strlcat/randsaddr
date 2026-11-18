/*
 * This code was written by Rys Andrey. It is now in public domain.
 * Original source to which it belongs: randsaddr repository.
 */

#include <stddef.h>
#include <string.h>

extern size_t ras_strlcpy(char *, const char *, size_t);

size_t ras_strlcat(char *dst, const char *src, size_t size)
{
	size_t dstlen = strnlen(dst, size);
	if (dstlen == size) return dstlen + strlen(src);
	return dstlen + ras_strlcpy(dst+dstlen, src, size-dstlen);
}
