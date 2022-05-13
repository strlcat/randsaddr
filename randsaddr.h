#ifndef _RANDSADDR_H
#define _RANDSADDR_H

#include <stdint.h>
#include <stddef.h>
#include "tfdef.h"
#include "tfe.h"
#include "tfprng.h"
#include "xmalloc.h"

enum { NO, YES };
enum { RAT_NONE, RAT_IPV4, RAT_IPV6 };

typedef _Bool ras_yesno;
typedef short ras_atype;

#define NOSIZE ((size_t)-1)

#define STAT_ARRAY_SZ(x) (sizeof(x)/sizeof(*x))
#define CSTR_SZ(x) (sizeof(x)-1)

extern ras_yesno mkrandaddr6(void *, const void *, size_t);
extern void mkeui64addr(void *, const void *);
extern ras_yesno mkrandaddr4(void *, const void *, size_t);

extern uint8_t prng_getrandc(void);

extern ras_atype addr_type(const char *);
extern ras_yesno compare_prefix(ras_atype, const void *, const void *, size_t);

extern size_t prng_index(size_t, size_t);

#endif
