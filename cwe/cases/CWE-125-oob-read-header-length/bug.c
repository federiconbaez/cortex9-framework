#include <stdio.h>
#include <stdlib.h>
/* Length byte taken from the "packet" itself, as in a header parser. */
int main(int argc, char **argv) {
	(void)argv;
	unsigned char *pkt = malloc(8);
	for (int i = 0; i < 8; i++) pkt[i] = (unsigned char)(i + argc + 30);
	unsigned len = pkt[0];
	printf("%d\n", pkt[len]);
	free(pkt);
	return 0;
}
