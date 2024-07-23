#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main() {
	int fd = open("flag.txt", O_RDWR);
	char p[400];
	read(fd, p, sizeof(p));
	write(1, p, sizeof(p));
}
