#include <string.h>

size_t ras_strltxstr(char *str, size_t n, int *nr_reps, const char *from, const char *to)
{
	size_t sl, fl, tl, step;
	int l_nr_reps;
	char *s, *d;

	sl = strnlen(str, n);
	if (sl == 0 || sl == n) goto _err;

	fl = strlen(from);
	if (fl == 0) goto _err;
	if (!to) {
		to = "";
		tl = 0;
	}
	else tl = strlen(to);

	/* This does not make sense */
	if (fl == tl && !strcmp(from, to)) goto _err;
	/*
	 * Replacing "amp" with "kiloampere" will still leave "amp"
	 * inside the replaced string, which will trigger another
	 * replace and over and over... prevent that by jumping to
	 * the end of the substituted string so replacement occurs
	 * only once and not recursively.
	 */
	if (tl > fl) step = tl;
	else step = 0;

	l_nr_reps = 0; d = str;
	while (1) {
		if (nr_reps && *nr_reps != -1 && l_nr_reps >= *nr_reps) break;
		s = strstr(d, from);
		if (!s) break;
		d = s + step;
		if (tl == fl) memcpy(s, to, tl);
		else if (tl < fl) {
			memcpy(s, to, tl);
			memmove(s+tl, s+fl, sl-(s-str)-fl);
			memset(s+(sl-(s-str)-fl+tl), 0, fl-tl);
			sl -= (fl-tl);
			if (sl < tl) break;
		}
		else if (tl > fl) {
			sl += (tl-fl);
			/* resized str does not fit - fail. */
			if (sl >= n) break;
			memmove(s+tl, s+fl, sl-(s-str)-tl);
			memcpy(s, to, tl);
		}
		l_nr_reps++;
	}

	if (nr_reps) *nr_reps = l_nr_reps;
	if (l_nr_reps && sl < n) str[sl] = '\0';
	/* return new string length, ceil to size if does not fit */
_err:	return sl > n ? n : sl;
}

size_t ras_strlxstr(char *str, size_t n, const char *from, const char *to)
{
	return ras_strltxstr(str, n, NULL, from, to);
}

size_t ras_strxstr(char *str, const char *from, const char *to)
{
	size_t x = strlen(str)+1;
	size_t y = ras_strltxstr(str, x, NULL, from, to);
	return y == x ? x-1 : y;
}
