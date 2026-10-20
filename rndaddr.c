#include <stdio.h>
#include <randsaddr.h>

int main(int argc, char **argv)
{
	char *sarg;
	ras_fntyp fnt;
	ras_opts opts;
	struct s_addr sa;
	char res[RAS_ADDRLEN];
	int c;

	opterr = 0;
	fnt = RFN_UNKNOWN;
	opts = ROP_NONE;
	while ((c = getopt(argc, argv, "46uz")) != -1) {
		switch (c) {
			case '4':
				fnt = RFN_RNDADDR4;
				break;
			case '6':
				fnt = RFN_RNDADDR6;
				break;
			case 'z': opts |= ROP_FULLBYTES; break;
			case 'u': opts |= ROP_EUI64; break;
			default:
_us:				puts("usage: rndaddr [-46zu] RANDSADDR_STRSPEC");
				puts("example ipv4: rndaddr -4 172.16.0.0/12");
				puts("example ipv6: rndaddr -6 fd89:3072:4000::/34");
				puts("  -z: ensure there are no zero nibbles");
				puts("  -u: (ipv6) generate and embed EUI64");
				puts("See randsaddr.so project's README.md");
				puts("for more info about RANDSADDR_STRSPEC syntax.");
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

	ras_set_opts(opts);
	ras_init(fnt, sarg);
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
