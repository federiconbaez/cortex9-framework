#include <stdlib.h>
int main(void) {
	char *p = malloc(4096);
	p[0] = 1;
	p = 0;
	return 0;
}
