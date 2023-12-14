/*
 * randsaddr: randomize source address of outgoing sockets.
 *
 * randsaddr is copyrighted:
 * Copyright (C) 2023 Rys Andrey. All rights reserved.
 *
 * randsaddr is licensed to you under the terms of std. MIT/X11 license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "randsaddr.h"

/* ok let's keep it private for now. */
struct maclist {
	uint8_t macpfx[3];
};

static struct maclist *maclist;

static int fgetstr(char *out, size_t len, FILE *fp)
{
	if (fgets(out, (size_t)len, fp)) {
		out[strcspn(out, "\r\n")] = 0;
		return 1;
	}
	return 0;
}

void read_mac_list(const char *path)
{
	FILE *fp = fopen(path, "r");
	struct maclist mac;
	size_t idx;
	char *s, ln[256];

	if (!fp) ras_fatal("cannot open mac list file \"%s\": %s", path, strerror(errno));

	while (1) {
		ln[0] = 0;
		if (!fgetstr(ln, sizeof(ln), fp)) break;

		s = strchr(ln, ' ');
		if (!s) s = strchr(ln, '\t');
		if (!s) continue;
		if (ras_str_empty(ln)) continue;
		if (ln[0] == '#') continue;
		*s = 0; s++;
		if (strlen(ln) != CSTR_SZ("000000")) continue;

		idx = DYN_ARRAY_SZ(maclist);
		maclist = ras_realloc(maclist, (idx+1) * sizeof(struct maclist));

		ras_strlcpy(s, &ln[0], CSTR_SZ("00")+1);
		mac.macpfx[0] = (uint8_t)strtoul(s, NULL, 16);
		ras_strlcpy(s, &ln[1*CSTR_SZ("00")], CSTR_SZ("00")+1);
		mac.macpfx[1] = (uint8_t)strtoul(s, NULL, 16);
		ras_strlcpy(s, &ln[2*CSTR_SZ("00")], CSTR_SZ("00")+1);
		mac.macpfx[2] = (uint8_t)strtoul(s, NULL, 16);
		memcpy(&maclist[idx], &mac, sizeof(struct maclist));
	}

	fclose(fp);
}

int ras_amendeui64addr(void *d_addr, const void *s_addr)
{
	uint8_t *ud_addr = (uint8_t *)d_addr;
	size_t midx, ridx;

	if (!maclist) return 0;

	midx = DYN_ARRAY_SZ(maclist);
	ridx = ras_prng_index(0, midx-1);
	memcpy(&ud_addr[8], &maclist[ridx].macpfx, sizeof(((struct maclist *)NULL)->macpfx));

	return 1;
}
