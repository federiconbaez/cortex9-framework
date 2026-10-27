int main(int argc, char **argv) {
	(void)argv;
	int x = 7;
	int *p = 0;
	if (argc > 5) p = &x;
	return *p;
}
