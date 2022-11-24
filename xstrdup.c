#include "xmalloc.h"
#include <string.h>

char *ras_strdup(const char *s)
{
	size_t sz = strlen(s);
	char *res = ras_malloc(sz+1);
	if (!res) return NULL;
	memcpy(res, s, sz);
	return res;
}
