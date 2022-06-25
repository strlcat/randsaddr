/*
 * This code was written by Rys Andrey. It is now in public domain.
 * Original source to which it belongs: randsaddr repository.
 */

#include <stddef.h>
#include <string.h>

size_t ras_strlcpy(char *dst, const char *src, size_t size)
{
	size_t len, srclen;
	srclen = strlen(src);
	if (size-- <= 0) return srclen;
	len = (size < srclen) ? size : srclen;
	memmove(dst, src, len);
	dst[len] = '\0';
	return srclen;
}
