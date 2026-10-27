#include <fcntl.h>
#include <unistd.h>
int main(void) {
	if (access("/tmp", R_OK) == 0) {
		/* window: the path can be swapped here */
		int fd = open("/tmp", O_RDONLY);
		if (fd >= 0) close(fd);
	}
	return 0;
}
