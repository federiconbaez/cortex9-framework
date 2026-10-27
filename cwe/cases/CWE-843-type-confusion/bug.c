#include <stdio.h>
struct a { long x; };
struct b { char *s; };
int main(void) {
	struct a v = { 0x41 };
	void *p = &v;
	printf("%c\n", ((struct b *)p)->s[0]);
	return 0;
}
