int main(int argc, char **argv) {
	(void)argv;
	int a[4] = {0};
	a[argc + 3] = 1;
	return a[0];
}
