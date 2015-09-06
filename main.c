#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdarg.h>

void do_error(char *msg, ...) {
	va_list argp;
  
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
}

int set_tun(char *dev, int flags) {
	struct ifreq ifr;
	int fd, err;

	if((fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

int main(int argc, char *argv[]) {
	int flags = IFF_TUN;
	char if_name[IFNAMSIZ];
	int tap_fd;

	strncpy(if_name, "tun0", IFNAMSIZ-1);

	/* Initialize tun/tap interface */
	if ((tap_fd = set_tun(if_name, flags | IFF_NO_PI)) < 0 ) {
		do_error("Error connecting to tun/tap interface %s!\n", if_name);
		exit(1);
	}

	return 0;
}
