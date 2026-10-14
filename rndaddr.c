#include <stdio.h>
#include <randsaddr.h>

int main(int argc, char **argv)
{
	struct s_addr sa;
	char res[RAS_ADDRLEN];

	ras_init(argv[1]);
	if (ras_bind_random(RFN_RNDADDR, -1, 0, &sa) == NO) {
		fprintf(stderr, "rndaddr: %s: invalid specification string\n", argv[1]);
		return 2;
	}

	memset(res, 0, sizeof(res));
	switch (sa.atype) {
		case RAT_IPV6:
			if (inet_ntop(AF_INET6, &sa.inet6, res, sizeof(res)) == NULL) {
				fprintf(stderr, "rndaddr: %s: error decoding IPv6 address\n", argv[1]);
				return 3;
			}
			break;
		case RAT_IPV4:
			if (inet_ntop(AF_INET, &sa.inet4, res, sizeof(res)) == NULL) {
				fprintf(stderr, "rndaddr: %s: error decoding IPv4 address\n", argv[1]);
				return 3;
			}
			break;
		default:
			fprintf(stderr, "rndaddr: %s: unknown IP address type\n", argv[1]);
			return 255;
	}

	printf("%s\n", res);

	return 0;
}
