#include <stdio.h>
#include <randsaddr.h>

int main(int argc, char **argv)
{
	char *sarg;
	ras_fntyp fnt;
	struct s_addr sa;
	char res[RAS_ADDRLEN];
	int c;

	opterr = 0;
	fnt = RFN_UNKNOWN;
	while ((c = getopt(argc, argv, "46")) != -1) {
		switch (c) {
			case '4':
				fnt = RFN_RNDADDR4;
				break;
			case '6':
				fnt = RFN_RNDADDR6;
				break;
			default:
_us:				puts("usage: rndaddr [-46] RANDSADDR_STRSPEC");
				puts("See randsaddr.so project's README.md.");
				return 1;
		}
	}

	if (!argv[optind]) {
		if (fnt == RFN_RNDADDR4) sarg = "0.0.0.0/0";
		else if (fnt == RFN_RNDADDR6) sarg = "::/0";
		else goto _us;
	}
	else sarg = argv[optind];

	if (fnt == RFN_UNKNOWN) {
		/* naive try in case if only one range was specified */
		ras_atype at = ras_addr_type(sarg);
		if (at == RAT_IPV4) fnt = RFN_RNDADDR4;
		else if (at == RAT_IPV6) fnt = RFN_RNDADDR6;
	}

	ras_init(sarg);
	if (ras_bind_random(fnt, -1, 0, &sa) == NO) {
		fprintf(stderr, "rndaddr: %s: invalid specification string\n", sarg);
		return 2;
	}

	memset(res, 0, sizeof(res));
	switch (sa.atype) {
		case RAT_IPV6:
			if (inet_ntop(AF_INET6, &sa.inet6, res, sizeof(res)) == NULL) {
				fprintf(stderr, "rndaddr: %s: error decoding IPv6 address\n", sarg);
				return 3;
			}
			break;
		case RAT_IPV4:
			if (inet_ntop(AF_INET, &sa.inet4, res, sizeof(res)) == NULL) {
				fprintf(stderr, "rndaddr: %s: error decoding IPv4 address\n", sarg);
				return 3;
			}
			break;
		default:
			fprintf(stderr, "rndaddr: %s: unknown IP address type\n", sarg);
			return 255;
	}

	printf("%s\n", res);

	return 0;
}
