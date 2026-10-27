#include <pthread.h>
#include <stdio.h>
static long counter;
static void *work(void *arg) {
	(void)arg;
	for (int i = 0; i < 100000; i++) counter++;
	return 0;
}
int main(void) {
	pthread_t a, b;
	pthread_create(&a, 0, work, 0);
	pthread_create(&b, 0, work, 0);
	pthread_join(a, 0);
	pthread_join(b, 0);
	printf("%ld\n", counter);
	return 0;
}
