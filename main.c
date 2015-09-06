#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <getopt.h>

#define DEF_PORT	5059
#define DEF_IFNAME	"tun0"

/* Common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

static int debug = 0;

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

void usage(char *name) {
	fprintf(stderr, "Usage: %s -i <interface> [-c <address>] [-p <port>] [-a] [-v]\n\n", name);
	fprintf(stderr, "Options\n");
	fprintf(stderr, "  -i <interface>  Use specific interface (Default: " DEF_IFNAME ")\n");
	fprintf(stderr, "  -c <address>    Connect to remote VPN server (Enables client mode)\n");
	fprintf(stderr, "  -p <port>       Bind to port or connect to port (Default: %u)\n", DEF_PORT);
	fprintf(stderr, "  -a              Use TAP interface (Default: TUN)\n");
	fprintf(stderr, "  -v              Verbose output\n");
	fprintf(stderr, "  -h              This help text\n");
}

int main(int argc, char *argv[]) {
	int flags = IFF_TUN;
	char if_name[IFNAMSIZ] = DEF_IFNAME;
	char remote_ip[16];
	int tap_fd, option, server = 1;
	unsigned short int port = DEF_PORT;
	int header_len = IP_HDR_LEN;

	/* Check command line options */
	while((option = getopt(argc, argv, "i:c:p:ahv"))>0){
		switch(option) {
			case 'v':
				debug = 1;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 'i':
				strncpy(if_name, optarg, IFNAMSIZ-1);
				break;
			case 'c':
				server = 0;
				strncpy(remote_ip, optarg, 15);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'a':
				flags = IFF_TAP;
				header_len = ETH_HDR_LEN;
				break;
			default:
				do_error("Unknown option %c\n", option);
				usage(argv[0]);
			}
	}

	/* Initialize tun/tap interface */
	if ((tap_fd = set_tun(if_name, flags | IFF_NO_PI)) < 0 ) {
		do_error("Error connecting to tun/tap interface %s!\n", if_name);
		exit(1);
	}

	return 0;
}
