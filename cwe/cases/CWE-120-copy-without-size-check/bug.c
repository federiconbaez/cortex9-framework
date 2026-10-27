#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
	(void)argv;
	char src[32];
	memset(src, 'B', sizeof src);
	char dst[8];
	memcpy(dst, src, (size_t)(8 * (argc + 1)));
	printf("%c\n", dst[0]);
	return 0;
}
