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
#define CERTSIZE			32
#define DEF_PORT			5059
#define DEF_IFNAME			"tun0"
#define DEF_ROUTER_ADDR		"10.7.0.1"
#define DEF_NETMASK			"255.255.255.0"
#define DEF_MAX_CLIENTS		20
#define PACKET_MAGIC		0xdeadbaba

const static unsigned char version[] = "CarbonVPN 0.8 - See Github";

typedef struct {
	unsigned short port;
	char *if_name;
	char *ip;
	char *ip_netmask;
	unsigned char debug;
	unsigned char max_conn;
	unsigned char cacert[crypto_sign_BYTES + CERTSIZE];
	unsigned char capk[crypto_sign_PUBLICKEYBYTES];
	unsigned char cask[crypto_sign_SECRETKEYBYTES];
	unsigned char pk[crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
} config_t;

enum mode {
	CLIENT_HELLO = 1,
	SERVER_HELLO,
	STREAM,
	PING,
	PING_BACK,
};

struct handshake {
	char pubkey[crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES];
	char ip[16];
	char netmask[16];
} __attribute__ ((packed));

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
	} else if (!strcmp(name, "max_clients")) {
		pcfg->max_conn = atoi(value);
	} else if (!strcmp(name, "cacert")) {
		if (strlen(value) == (2*(crypto_sign_BYTES + CERTSIZE))) {
			hextobin(pcfg->cacert, (unsigned char *)value, crypto_sign_BYTES + CERTSIZE);
		}
	} else if (!strcmp(name, "capublickey")) {
		if (strlen(value) == (2*crypto_sign_PUBLICKEYBYTES)) {
			hextobin(pcfg->capk, (unsigned char *)value, crypto_sign_PUBLICKEYBYTES);
		}
	} else if (!strcmp(name, "caprivatekey")) {
		if (strlen(value) == (2*crypto_sign_SECRETKEYBYTES)) {
			hextobin(pcfg->cask, (unsigned char *)value, crypto_sign_SECRETKEYBYTES);
		}
	} else if (!strcmp(name, "publickey")) {
		if (strlen(value) == (2*(crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES))) {
			hextobin(pcfg->pk, (unsigned char *)value, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES);
		}
	} else if (!strcmp(name, "privatekey")) {
		if (strlen(value) == (2*crypto_box_SECRETKEYBYTES)) {
			hextobin(pcfg->sk, (unsigned char *)value, crypto_box_SECRETKEYBYTES);
		}
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

	memset(&ifr, 0, sizeof(ifr));
	sin.sin_family = AF_INET;

	inet_pton(AF_INET, ip_addr, &sin.sin_addr);

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr)); 

	/* Set interface address */
	if (ioctl(sock_fd, SIOCSIFADDR, &ifr)<0) {
		lprint("[erro] Cannot set ip address\n");
		return -1;
	}

	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr)<0) {
		lprint("[erro] Cannot get interface\n");
		return -1;
	}

	/* Ensure the interface is up */
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr)<0) {
		lprint("[erro] Cannot set interface\n");
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

char *incr_ip(char *ip_addr, unsigned char increment) {
	struct sockaddr_in sin;
	static char ip[INET_ADDRSTRLEN];

	inet_pton(AF_INET, ip_addr, &sin.sin_addr);

	unsigned long nlenh = ntohl(sin.sin_addr.s_addr);
	nlenh += increment;
	sin.sin_addr.s_addr = htonl(nlenh);

	inet_ntop(AF_INET, &sin.sin_addr, ip, INET6_ADDRSTRLEN);
	return ip;
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
	fprintf(stderr, "Usage: %s [OPTIONS] [COMMANDS]\n", name);
	fprintf(stderr, "Options\n");
	fprintf(stderr, "  -f <file>       Read options from config file\n");
	fprintf(stderr, "  -i <interface>  Use specific interface (Default: " DEF_IFNAME ")\n");
	fprintf(stderr, "  -c <address>    Connect to remote VPN server (Enables client mode)\n");
	fprintf(stderr, "  -p <port>       Bind to port or connect to port (Default: %u)\n", DEF_PORT);
	fprintf(stderr, "  -a              Use TAP interface (Default: TUN)\n");
	fprintf(stderr, "  -v              Verbose output\n");
	fprintf(stderr, "  -h              This help text\n\n");
	fprintf(stderr, "Commands\n");
	fprintf(stderr, "  genca           Generate CA certificate\n");
	fprintf(stderr, "  gencert         Create and sign certificate\n");
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
		.debug = 0,
		.max_conn = DEF_MAX_CLIENTS
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

	/* Parse config */
	if (config) {
		lprint("[info] Loading config from file\n");
		if (conf_parse(config_file, parse_config, &cfg) < 0) {
			lprintf("[erro] Cannot open %s\n", config_file);
			goto error;
		}
	}

	if (argc > 0) {
		if (!strcmp(argv[0], "genca")) {
			/* Generate new CA */
			unsigned char pk[crypto_sign_PUBLICKEYBYTES];
			unsigned char sk[crypto_sign_SECRETKEYBYTES];
			unsigned char cert[CERTSIZE];
			unsigned char cert_signed[crypto_sign_BYTES + CERTSIZE];
			unsigned char fp[crypto_generichash_BYTES];
			unsigned long long cert_signed_len;

			randombytes_buf(cert, CERTSIZE);
			crypto_sign_keypair(pk, sk);
			crypto_sign(cert_signed, &cert_signed_len, cert, CERTSIZE, sk);
			crypto_generichash(fp, crypto_generichash_BYTES, cert_signed, cert_signed_len, pk, crypto_sign_PUBLICKEYBYTES);

			if (cfg.debug) {
				printf("Generating CA with %s-%s-SHA256\n", randombytes_implementation_name(), crypto_sign_primitive());
				printf("Private certificate: \t");
				print_hex(cert, CERTSIZE);
				printf("Public key: \t\t");
				print_hex(pk, crypto_sign_PUBLICKEYBYTES);
				printf("Private key: \t\t");
				print_hex(sk, crypto_sign_SECRETKEYBYTES);
				printf("Public certificate: \t");
				print_hex(cert_signed, cert_signed_len);
				printf("Fingerprint: \t\t");
				print_hex(fp, crypto_generichash_BYTES);
				putchar('\n');
			}

			puts("Add the following lines the config file:");
			printf("cacert = ");
			print_hex(cert_signed, cert_signed_len);
			printf("capublickey = ");
			print_hex(pk, crypto_sign_PUBLICKEYBYTES);
			printf("caprivatekey = ");
			print_hex(sk, crypto_sign_SECRETKEYBYTES);

			sodium_memzero(cert, sizeof(cert));
			sodium_memzero(sk, sizeof(sk));
			return 0;
		} else if (!strcmp(argv[0], "gencert")) {
			/* Generate new client keypair */
			unsigned char pk[crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES];
			unsigned char sk[crypto_box_SECRETKEYBYTES];
			unsigned char fp[crypto_generichash_BYTES];
			unsigned char pk_signed[crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES];
			unsigned long long pk_signed_len;
			char q;

			crypto_generichash(fp, crypto_generichash_BYTES, cfg.cacert, (crypto_sign_BYTES + CERTSIZE), cfg.capk, crypto_sign_PUBLICKEYBYTES);
			crypto_box_keypair(pk, sk);
			strncat((char *)pk, (char *)fp, crypto_generichash_BYTES);

			printf("Sign key with CA [y/N]? ");
			scanf("%c", &q);
			if (q != 'Y' && q != 'y')
				return 1;

			crypto_sign(pk_signed, &pk_signed_len, pk, crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES, cfg.cask);

			if (cfg.debug) {
				printf("Generating keypair with %s\n", crypto_box_primitive());
				printf("Appended public key: \t");
				print_hex(pk, crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES);
				printf("Private key: \t\t");
				print_hex(sk, crypto_box_SECRETKEYBYTES);
				printf("Fingerprint: \t\t");
				print_hex(fp, crypto_generichash_BYTES);
				printf("Signed public key: \t");
				print_hex(pk_signed, pk_signed_len);
				putchar('\n');
			}

			puts("Add the following lines the config file:");
			printf("publickey = ");
			print_hex(pk_signed, pk_signed_len);
			printf("privatekey = ");
			print_hex(sk, crypto_box_SECRETKEYBYTES);

			sodium_memzero(sk, sizeof(sk));
			return 0;
		} else {
			fprintf(stderr, "Unknown command %s\n", argv[0]);
			return 1;
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

		/* Check if server is responding */
		struct wrapper encap;
		encap.client_id = htonl(1);
		encap.packet_chk = htonl(PACKET_MAGIC);
		encap.data_len = 0;
		encap.mode = PING;

		fd_write(net_fd, (char *)&encap, sizeof(encap));

		/* Notify server */
		encap.client_id = htonl(1);
		encap.packet_chk = htonl(PACKET_MAGIC);
		encap.data_len = 0;
		encap.mode = CLIENT_HELLO;

		struct handshake client_key;
		memcpy(client_key.pubkey, cfg.pk, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES);

		fd_write(net_fd, (char *)&encap, sizeof(encap));
		fd_write(net_fd, (char *)&client_key, sizeof(client_key));
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

			if (cfg.debug) lprintf("[dbug] Read %d bytes from tun\n", nread);

			encap.client_id = htonl(1);
			encap.packet_chk = htonl(PACKET_MAGIC);
			encap.data_len = htons(nread);
			encap.mode = STREAM;

			/* Write packet */
			nwrite = fd_write(net_fd, (char *)&encap, sizeof(encap));
			nwrite = fd_write(net_fd, buffer, nread);

			if (cfg.debug) lprintf("[dbug] Wrote %d bytes to socket\n", nwrite);
		}

		/* Action on socket */
		if(FD_ISSET(net_fd, &rd_set)){
			nread = fd_count(net_fd, (char *)&encap, sizeof(encap));
			if(nread == 0) {
				close(net_fd);
				continue;
			}

			if (ntohl(encap.packet_chk) == PACKET_MAGIC) {
				if (cfg.debug) lprintf("[dbug] Read %d bytes from socket\n", nread);

				if (encap.mode == CLIENT_HELLO) {
					/* Read packet */
					struct handshake client_key;
					nread = fd_count(net_fd, (char *)&client_key, sizeof(client_key));
					printf("Client key: ");
					print_hex((unsigned char *)client_key.pubkey, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES);

					encap.client_id = htonl(1);
					encap.packet_chk = htonl(PACKET_MAGIC);
					encap.data_len = 0;
					encap.mode = SERVER_HELLO;

					if (cfg.debug) lprintf("[dbug] Client %d Public key %s\n", 1, client_key.pubkey);

					memcpy(client_key.pubkey, cfg.pk, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES);
					strncpy(client_key.ip, incr_ip(cfg.ip, 1), 15);
					strncpy(client_key.netmask, cfg.ip_netmask, 15);

					fd_write(net_fd, (char *)&encap, sizeof(encap));
					fd_write(net_fd, (char *)&client_key, sizeof(client_key));

					lprintf("[info] Client %d assigned %s\n", 1, client_key.ip);
				} else if (encap.mode == SERVER_HELLO) { /* TODO: This could already be encrypted */
					/* Read packet */
					struct handshake client_key;
					nread = fd_count(net_fd, (char *)&client_key, sizeof(client_key));
					printf("Server key: ");
					print_hex((unsigned char *)client_key.pubkey, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES);

					int sock = set_ip(cfg.if_name, client_key.ip);
					set_netmask(sock, cfg.if_name, client_key.netmask);

					lprintf("[info] Assgined %s/%s\n", client_key.ip, client_key.netmask);
				} else if (encap.mode == STREAM) {
					/* Read packet */
					nread = fd_count(net_fd, buffer, ntohs(encap.data_len));
					nwrite = fd_write(tap_fd, buffer, nread);

					if (cfg.debug) lprintf("[dbug] Wrote %d bytes to tun\n", nwrite);
				} else if (encap.mode == PING) {
					/* Ping back */
					encap.client_id = htonl(1);
					encap.packet_chk = htonl(PACKET_MAGIC);
					encap.data_len = 0;
					encap.mode = PING_BACK;

					fd_write(net_fd, (char *)&encap, sizeof(encap));
				} else if (encap.mode == PING_BACK) {
					/* Log pingback */
					lprintf("[info] Server pingback\n");
				} else {
					if (cfg.debug) lprintf("[dbug] Packet dropped\n");
				}
			} else {
				if (cfg.debug) lprintf("[dbug] Packet dropped\n");
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
