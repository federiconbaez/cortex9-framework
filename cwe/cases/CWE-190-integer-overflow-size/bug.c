#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
	(void)argv;
	unsigned short n = 65535;
	n = n + argc; /* wraps to a tiny allocation size */
	char *buf = malloc(n);
	memset(buf, 'A', 64);
	free(buf);
	return 0;
}
