#ifndef _RANDSADDR_H
#define _RANDSADDR_H

#include <stdint.h>
#include "tfdef.h"
#include "tfe.h"
#include "tfprng.h"
#include "xmalloc.h"

#define NOSIZE ((size_t)-1)

#define STAT_ARRAY_SZ(x) (sizeof(x)/sizeof(*x))
#define CSTR_SZ(x) (sizeof(x)-1)

extern int mkrandaddr6(void *, const void *, size_t);
extern void mkeui64addr(void *, const void *);
extern int mkrandaddr4(void *, const void *, size_t);

extern uint8_t prng_getrandc(void);

extern int addr_type(const char *);

extern size_t prng_index(size_t from, size_t to);

#endif
