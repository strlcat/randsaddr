#ifndef _RANDSADDR_H
#define _RANDSADDR_H

#include <stdint.h>
#include "tfdef.h"
#include "tfe.h"
#include "tfprng.h"

#define NOSIZE ((size_t)-1)

extern int mkrandaddr6(void *, const void *, size_t);
extern void mkeui64addr(void *, const void *);
extern int mkrandaddr4(void *, const void *, size_t);

uint8_t prng_getrandc(void);

#endif
