#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <sodium.h>

#include "endian.h"
#include "logger.h"
#include "conf.h"
#include "util.h"

#define BUFSIZE				2048
#define CERTSIZE			128
#define DEF_PORT			5059
#define DEF_IFNAME			"tun0"
#define DEF_ROUTER_ADDR		"10.7.0.1"
#define DEF_NETMASK			"255.255.255.0"

#define PACKET_MAGIC		0xdeadbaba

const static unsigned char version[] = "CarbonVPN 0.7 - See Github";

typedef struct {
	unsigned short port;
	char *if_name;
	char *ip;
	char *ip_netmask;
	unsigned short debug;
} config_t;

enum mode {
	HANDSHAKE = 1,
	STREAM,
	PING,
};

struct wrapper {
	unsigned int client_id;
	int packet_chk;
	unsigned short data_len;
	unsigned char mode;
} __attribute__ ((packed));

int parse_config(void *_pcfg, const char *section, const char *name, const char *value) {
	config_t *pcfg = (config_t*)_pcfg;

	if (!strcmp(name, "port")) {
		pcfg->port = atoi(value);
	} else if (!strcmp(name, "interface")) {
		pcfg->if_name = strdup(value);
	} else if (!strcmp(name, "router")) {
		pcfg->ip = strdup(value);
	} else if (!strcmp(name, "netmask")) {
		pcfg->ip_netmask = strdup(value);
	} else if (!strcmp(name, "debug")) {
		pcfg->debug = value[0] == 't' ? 1 : 0;
	} else {
		return 0;
	}
	return 1;
}

int create_socket() {
	int sock_fd = 0;

	if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0))<0){
		lprint("[erro] Cannot create socket\n");
		return -1;
	}

 	return sock_fd;
}

int set_tun(char *dev, int flags) {
	struct ifreq ifr;
	int fd, err;

	if((fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		lprint("[erro] Cannot create interface\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
		lprint("[erro] Cannot set interface\n");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

int set_ip(char *ifname, char *ip_addr) {
	struct ifreq ifr;
	struct sockaddr_in sin;
	int sock_fd = create_socket();

	sin.sin_family = AF_INET;

	inet_pton(AF_INET, ip_addr, &sin.sin_addr);

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr)); 

	/* Set interface address */
	if (ioctl(sock_fd, SIOCSIFADDR, &ifr)<0) {
		lprint("[erro] Cannot set ip address\n");
		return -1;
	}            

	return sock_fd;
}

int set_netmask(int sock_fd, char *ifname, char *ip_addr_mask ) {
	struct ifreq ifr;

	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	memset(&ifr, 0, sizeof(ifr));
	sin->sin_family = AF_INET;
	
	inet_pton(AF_INET, ip_addr_mask, &sin->sin_addr);
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	if (ioctl(sock_fd, SIOCSIFNETMASK, &ifr)<0) {
		lprint("[erro] Cannot set netmask\n");
		return -1;
	}

	return sock_fd;
}

int fd_read(int fd, char *buf, int n){
	int nread;

	if((nread = read(fd, buf, n))<0){
		lprint("[warn] Cannot read device\n");
		return -1;
	}
	return nread;
}

int fd_write(int fd, char *buf, int n){
	int nwrite;

	if((nwrite = write(fd, buf, n))<0){
		lprint("[warn] Cannot write device\n");
		return -1;
	}
	return nwrite;
}

int fd_count(int fd, char *buf, int n) {
	int nread, left = n;

	/* Read until buffer is 0 */
	while (left > 0) {
		if (!(nread = fd_read(fd, buf, left))){
			return 0;
		}else {
			left -= nread;
			buf += nread;
		}
	}
	return n;
}

void usage(char *name) {
	fprintf(stderr, "Usage: %s [OPTIONS]\n", name);
	fprintf(stderr, "Options\n");
	fprintf(stderr, "  -f <file>       Read options from config file\n");
	fprintf(stderr, "  -i <interface>  Use specific interface (Default: " DEF_IFNAME ")\n");
	fprintf(stderr, "  -c <address>    Connect to remote VPN server (Enables client mode)\n");
	fprintf(stderr, "  -p <port>       Bind to port or connect to port (Default: %u)\n", DEF_PORT);
	fprintf(stderr, "  -a              Use TAP interface (Default: TUN)\n");
	fprintf(stderr, "  -v              Verbose output\n");
	fprintf(stderr, "  -h              This help text\n");
	fprintf(stderr, "\n%s\n", version);
}

int main(int argc, char *argv[]) {
	int flags = IFF_TUN;
	char remote_ip[16];
	char config_file[64];
	int tap_fd, sock_fd, net_fd, option, server = 1, config = 0;
	struct sockaddr_in local, remote;
	config_t cfg = {
		.port = DEF_PORT,
		.if_name = strdup(DEF_IFNAME),
		.ip = strdup(DEF_ROUTER_ADDR),
		.ip_netmask = strdup(DEF_NETMASK),
		.debug = 0
	};

	/* Start log */
	start_log();

	/* Initialize NaCl */
	sodium_init();

	/* Check command line options */
	while ((option = getopt(argc, argv, "f:i:c:p:ahv"))>0){
		switch (option) {
			case 'v':
				cfg.debug = 1;
				break;
			case 'h':
				usage(argv[0]);
				return 1;
			case 'i':
				cfg.if_name = strdup(optarg);
				break;
			case 'c':
				server = 0;
				strncpy(remote_ip, optarg, 15);
				break;
			case 'p':
				cfg.port = atoi(optarg);
				break;
			case 'a':
				flags = IFF_TAP;
				break;
			case 'f':
				config = 1;
				strncpy(config_file, optarg, 63);
				break;
			default:
				fprintf(stderr, "Unknown option %c\n", option);
				usage(argv[0]);
				return 1;
			}
	}

	argv += optind;
	argc -= optind;

	if (argc > 0) {
		/* Generate new CA */
		if (!strcmp(argv[0], "genca")) {
			unsigned char pk[crypto_sign_PUBLICKEYBYTES];
			unsigned char sk[crypto_sign_SECRETKEYBYTES];
			unsigned char cert[CERTSIZE];
			unsigned char cert_signed[crypto_sign_BYTES + CERTSIZE];
			unsigned char thumb[crypto_hash_sha256_BYTES];
			unsigned long long cert_signed_len;

			randombytes_buf(cert, CERTSIZE);
			crypto_sign_keypair(pk, sk);
			crypto_sign(cert_signed, &cert_signed_len, cert, CERTSIZE, sk);
			crypto_hash_sha256(thumb, cert_signed, cert_signed_len);

			puts("Generating CA");
			printf("Algorithm: %s\n", crypto_sign_primitive());
			printf("Private certificate: ");
			print_hex(cert, CERTSIZE);
			printf("Public key: ");
			print_hex(pk, sizeof(pk));
			printf("Private key: ");
			print_hex(sk, sizeof(sk));
			printf("Public certificate: ");
			print_hex(cert_signed, cert_signed_len);
			printf("Signature: ");
			print_hex(thumb, crypto_hash_sha256_BYTES);

			sodium_memzero(cert, sizeof(cert));
			sodium_memzero(sk, sizeof(sk));
			return 0;
		}
	}

	/* Parse config */
	if (config) {
		lprint("[info] Loading config from file\n");
		if (conf_parse(config_file, parse_config, &cfg) < 0) {
			lprintf("[erro] Cannot open %s\n", config_file);
			goto error;
		}
	}

	/* Initialize tun/tap interface */
	if ((tap_fd = set_tun(cfg.if_name, flags | IFF_NO_PI)) < 0 ) {
		lprintf("[erro] Cannot connect to %s\n", cfg.if_name);
		goto error;
	}

	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0))<0) {
		lprint("[erro] Cannot create socket\n");
		goto error;
	}

	/* Client or server mode */
	if (!server) {
		/* Assign the destination address */
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(remote_ip);
		remote.sin_port = htons(cfg.port);

		/* Connection request */
		if (connect(sock_fd, (struct sockaddr*)&remote, sizeof(remote))<0){
			lprint("[erro] Cannot connect to server\n");
			goto error;
		}

		net_fd = sock_fd;
		lprintf("[info] Connected to server %s\n", inet_ntoa(remote.sin_addr));
	} else {
		/* Server, set local addr */
		int sock = set_ip(cfg.if_name, cfg.ip);
		set_netmask(sock, cfg.if_name, cfg.ip_netmask);

		/* Avoid EADDRINUSE */
		int _opval = 1;
		if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&_opval, sizeof(_opval)) < 0){
			lprint("[erro] Cannot set socket options\n");
			goto error;
		}

		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = htonl(INADDR_ANY);
		local.sin_port = htons(cfg.port);
		if (bind(sock_fd, (struct sockaddr*)&local, sizeof(local)) < 0){
			lprintf("[erro] Cannot bind to port %d\n", cfg.port);
			goto error;
		}

		if (listen(sock_fd, 5) < 0){
			lprint("[erro] Cannot listen on socket\n");
			goto error;
		}

		lprint("[info] Accepting connections\n");

		/* Wait for request */
		socklen_t remotelen = sizeof(remote);
		memset(&remote, 0, remotelen);
		if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0){
			lprint("[erro] Cannot accept connection\n");
			goto error;
		}

		lprintf("[info] Client connected from %s\n", inet_ntoa(remote.sin_addr));
	}

	int maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;
	while(1) {
		char buffer[BUFSIZE];
		unsigned short nread, nwrite;
		fd_set rd_set;
		struct wrapper encap;

		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set);
		FD_SET(net_fd, &rd_set);

		/* Listen on fds */
		int ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
		if (ret < 0 && errno == EINTR){
			continue;
		}

		if (ret < 0) {
			lprint("[warn] No devices in list\n");
			goto error;
		}

		/* Action on TUN */
		if(FD_ISSET(tap_fd, &rd_set)){
			nread = fd_read(tap_fd, buffer, BUFSIZE);

			printf("Read %d bytes from tun\n", nread);

			encap.client_id = htonl(1);
			encap.packet_chk = htonl(PACKET_MAGIC);
			encap.data_len = htons(nread);
			encap.mode = STREAM;

			/* Write packet */
			nwrite = fd_write(net_fd, (char *)&encap, sizeof(encap));
			nwrite = fd_write(net_fd, buffer, nread);

			printf("Wrote %d bytes to socket\n", nwrite);
		}

		/* Action on socket */
		if(FD_ISSET(net_fd, &rd_set)){
			nread = fd_count(net_fd, (char *)&encap, sizeof(encap));
			if(nread == 0) {
				close(net_fd);
				continue;
			}

			if (ntohl(encap.packet_chk) == PACKET_MAGIC) {
				printf("Read %d bytes from socket\n", nread);

				/* Read packet */
				nread = fd_count(net_fd, buffer, ntohs(encap.data_len));
				nwrite = fd_write(tap_fd, buffer, nread);

				printf("Wrote %d bytes to tun\n", nwrite);
			} else {
				printf("Packet dropped\n");
			}
		}
	}

error:
	free(cfg.if_name);
	free(cfg.ip);
	free(cfg.ip_netmask);

	stop_log();

	return 0;
}
