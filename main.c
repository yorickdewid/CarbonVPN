#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <sodium.h>
#include <ev.h>

#include "endian.h"
#include "logger.h"
#include "conf.h"
#include "vector.h"
#include "util.h"

#define BUFSIZE				2048
#define CERTSIZE			32
#define ADDRSIZE			16
#define DEF_PORT			5059
#define DEF_IFNAME			"tun0"
#define DEF_ROUTER_ADDR		"10.7.0.1"
#define DEF_NETMASK			"255.255.255.0"
#define DEF_MAX_CLIENTS		20
#define PACKET_MAGIC		0xdeadbaba
#define PACKET_CNT			1024

EV_P;
const static unsigned char version[] = "CarbonVPN 0.2 - See Github";
static volatile int active = 1;
static int total_clients = 0;
vector_t vector_clients;

//TMP - this will be in the client struct {
int _tmp_tap_fd, _tmp_sock_fd;
static int pcnt = PACKET_CNT;
unsigned char st_pk[crypto_box_PUBLICKEYBYTES];
unsigned char st_sk[crypto_box_SECRETKEYBYTES];

unsigned char cl_lt_pk[crypto_box_PUBLICKEYBYTES];
unsigned char sshk[crypto_box_BEFORENMBYTES];
// }

static struct sock_ev_client *conn_client = NULL;

typedef struct {
	unsigned short port;
	unsigned short server;
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

config_t cfg;

enum mode {
	CLIENT_HELLO = 1,
	SERVER_HELLO,
	INIT_EPHEX,
	RESP_EPHEX,
	STREAM,
	PING,
	PING_BACK,
};

struct sock_ev_client {
	ev_io io;
	int fd;
	int index;
};

struct handshake {
	char pubkey[crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES];
	char ip[ADDRSIZE];
	char netmask[ADDRSIZE];
} __attribute__ ((packed));

struct wrapper {
	unsigned int client_id;
	int packet_chk;
	unsigned int packet_cnt;
	unsigned short data_len;
	unsigned char mode;
	unsigned char nonce[crypto_box_NONCEBYTES];
} __attribute__ ((packed));

int parse_config(void *_pcfg, const char *section, const char *name, const char *value) {
	config_t *pcfg = (config_t*)_pcfg;

	if (!strcmp(name, "port")) {
		pcfg->port = atoi(value);
	} else if (!strcmp(name, "interface")) {
		free(pcfg->if_name);
		pcfg->if_name = strdup(value);
	} else if (!strcmp(name, "router")) {
		free(pcfg->ip);
		pcfg->ip = strdup(value);
	} else if (!strcmp(name, "netmask")) {
		free(pcfg->ip_netmask);
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

int setnonblock(int fd) {
	int flags;

	flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	return fcntl(fd, F_SETFL, flags);
}

int create_socket() {
	int sock_fd = 0;

	if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0))<0){
		lprint("[erro] Cannot create socket\n");
		return -1;
	}

 	return sock_fd;
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

int fd_read(int fd, unsigned char *buf, int n){
	int read;
redo:
	read = recv(fd, buf, n, 0);
	if (read < 0) {
		if (EAGAIN == errno) {
			goto redo; //TODO
		} else {
			perror("read error");
			printf("errno %d\n", errno);
		}
		return read;
	}

	if (read == 0) {
		close(fd);
		total_clients--; // Decrement total_clients count
		if (!cfg.server) {
			lprint("[info] Server disconnected\n");
			ev_io_stop(EV_A_ &conn_client->io);
			free(conn_client);
			conn_client = NULL;
			ev_break(EV_A_ EVBREAK_ALL);
		} else {
			int i;
			struct sock_ev_client *client = NULL;
			for (i=0; i<vector_clients.size; ++i) { //TODO
				client = (struct sock_ev_client *)vector_get(&vector_clients, i);
				ev_io_stop(EV_A_ &client->io);
				lprintf("[info] Client %d removed\n", client->index);
				free(client);
			}

			lprint("[info] Client disconnected\n");
			lprintf("[info] %d client(s) connected\n", total_clients);
		}
	}
	return read;
}

void sig_handler(int dummy) {
	lprint("[info] Shutdown daemon\n");
	active = 0;
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

int tun_init(char *dev, int flags) {
	struct ifreq ifr;
	int fd, err;

	if((fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
		lprint("[erro] Cannot create interface\n");
		return -1;
	}

	if (setnonblock(fd)<0) {
		lprint("[erro] Cannot set nonblock\n");
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

/* Read client message */
void read_cb(EV_P_ struct ev_io *watcher, int revents){
	unsigned char buffer[BUFSIZE];
	unsigned char cbuffer[crypto_box_MACBYTES + BUFSIZE];
	struct wrapper encap;
	ssize_t read;

	if (EV_ERROR & revents) {
		perror("got invalid event");
		return;
	}

	struct sock_ev_client *client = (struct sock_ev_client *)watcher;

	read = fd_read(client->fd, (unsigned char *)&encap, sizeof(encap));
	if (read <= 0)
		return;

	int sesscnt = ntohl(encap.packet_cnt);
	if (cfg.debug) lprintf("[dbug] Packet count %u\n", sesscnt);

	if (ntohl(encap.packet_chk) != PACKET_MAGIC) {
		if (cfg.debug) lprintf("[dbug] Packet dropped\n");
		return;
	}

	if (cfg.debug) lprintf("[dbug] Read %d bytes from socket\n", read);

	switch (encap.mode) {
		case CLIENT_HELLO: {
			struct handshake client_key;
			read = fd_read(client->fd, (unsigned char *)&client_key, sizeof(client_key));

			unsigned char pk_unsigned[crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES];
			unsigned long long pk_unsigned_len;
			if (crypto_sign_open(pk_unsigned, &pk_unsigned_len, (const unsigned char *)client_key.pubkey, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES, cfg.capk) != 0) {
				lprintf("[erro] Client authentication mismatch\n");
			} else {
				lprintf("[info] Client authentication verified\n");
			
				unsigned char ca_fp[crypto_generichash_BYTES];
				unsigned char cl_fp[crypto_generichash_BYTES];
				memcpy(cl_lt_pk, pk_unsigned, crypto_box_PUBLICKEYBYTES);
				memcpy(cl_fp, pk_unsigned+crypto_box_PUBLICKEYBYTES, crypto_generichash_BYTES);

				crypto_generichash(ca_fp, crypto_generichash_BYTES, cfg.cacert, (crypto_sign_BYTES + CERTSIZE), cfg.capk, crypto_sign_PUBLICKEYBYTES);

				if (!memcmp(ca_fp, cl_fp, crypto_generichash_BYTES)) {
					lprintf("[info] Client signature verified\n");

					encap.client_id = htonl(1);
					encap.packet_chk = htonl(PACKET_MAGIC);
					encap.packet_cnt = htonl(pcnt--);
					encap.data_len = 0;
					encap.mode = SERVER_HELLO;

					memcpy(client_key.pubkey, cfg.pk, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES);
					strncpy(client_key.ip, incr_ip(cfg.ip, 1), 15);
					strncpy(client_key.netmask, cfg.ip_netmask, 15);

					send(client->fd, (unsigned char *)&encap, sizeof(encap), 0);
					send(client->fd, (unsigned char *)&client_key, sizeof(client_key), 0);

					lprintf("[info] Client %d assigned %s\n", 1, client_key.ip);
				} else {
					lprintf("[erro] Client signature mismatch\n");
				}
			}
			break;
		}
		case SERVER_HELLO: {
			struct handshake client_key;
			read = fd_read(client->fd, (unsigned char *)&client_key, sizeof(client_key));

			unsigned char pk_unsigned[crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES];
			unsigned long long pk_unsigned_len;
			if (crypto_sign_open(pk_unsigned, &pk_unsigned_len, (const unsigned char *)client_key.pubkey, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES, cfg.capk) != 0) {
				lprintf("[erro] Server authentication mismatch\n");
			} else {
				lprintf("[info] Server authentication verified\n");
			
				unsigned char ca_fp[crypto_generichash_BYTES];
				unsigned char cl_fp[crypto_generichash_BYTES];
				memcpy(cl_lt_pk, pk_unsigned, crypto_box_PUBLICKEYBYTES);
				memcpy(cl_fp, pk_unsigned+crypto_box_PUBLICKEYBYTES, crypto_generichash_BYTES);

				crypto_generichash(ca_fp, crypto_generichash_BYTES, cfg.cacert, (crypto_sign_BYTES + CERTSIZE), cfg.capk, crypto_sign_PUBLICKEYBYTES);

				if (!memcmp(ca_fp, cl_fp, crypto_generichash_BYTES)) {
					lprintf("[info] Server signature verified\n");

					unsigned char nonce[crypto_box_NONCEBYTES];
					unsigned char ciphertext[crypto_box_MACBYTES + crypto_box_PUBLICKEYBYTES];
					randombytes_buf(nonce, crypto_box_NONCEBYTES);
					crypto_box_keypair(st_pk, st_sk);

					pcnt = PACKET_CNT;
					crypto_box_easy(ciphertext, st_pk, crypto_box_PUBLICKEYBYTES, nonce, cl_lt_pk, cfg.sk);

					encap.client_id = htonl(1);
					encap.packet_chk = htonl(PACKET_MAGIC);
					encap.packet_cnt = htonl(pcnt--);
					encap.data_len = 0;
					encap.mode = INIT_EPHEX;
					memcpy(encap.nonce, nonce, crypto_box_NONCEBYTES);

					send(client->fd, (unsigned char *)&encap, sizeof(encap), 0);
					send(client->fd, (unsigned char *)&ciphertext, sizeof(ciphertext), 0);

					int sock = set_ip(cfg.if_name, client_key.ip);
					set_netmask(sock, cfg.if_name, client_key.netmask);

					lprintf("[info] Assgined %s/%s\n", client_key.ip, client_key.netmask);
				} else {
					lprintf("[erro] Server signature mismatch\n");
				}
			}
			break;
		}
		case INIT_EPHEX: {
			unsigned char cl_st_pk[crypto_box_PUBLICKEYBYTES];
			unsigned char ciphertext[crypto_box_MACBYTES + crypto_box_PUBLICKEYBYTES];
			read = fd_read(client->fd, (unsigned char *)&ciphertext, sizeof(ciphertext));

			if (crypto_box_open_easy(cl_st_pk, ciphertext, crypto_box_MACBYTES + crypto_box_PUBLICKEYBYTES, encap.nonce, cl_lt_pk, cfg.sk) != 0) {
				if (cfg.debug) lprintf("[dbug] Ephemeral key exchange failed\n");
			} else {
				lprintf("[info] Ephemeral key exchanged\n");

				unsigned char nonce[crypto_box_NONCEBYTES];
				randombytes_buf(nonce, crypto_box_NONCEBYTES);
				crypto_box_keypair(st_pk, st_sk);

				pcnt = PACKET_CNT;
				crypto_box_beforenm(sshk, cl_st_pk, st_sk);
				crypto_box_easy(ciphertext, st_pk, crypto_box_PUBLICKEYBYTES, nonce, cl_lt_pk, cfg.sk);

				encap.client_id = htonl(1);
				encap.packet_chk = htonl(PACKET_MAGIC);
				encap.packet_cnt = htonl(pcnt--);
				encap.data_len = 0;
				encap.mode = RESP_EPHEX;
				memcpy(encap.nonce, nonce, crypto_box_NONCEBYTES);

				send(client->fd, (unsigned char *)&encap, sizeof(encap), 0);
				send(client->fd, (unsigned char *)&ciphertext, sizeof(ciphertext), 0);
			}
			break;
		}
		case RESP_EPHEX: {
			unsigned char cl_st_pk[crypto_box_PUBLICKEYBYTES];
			unsigned char ciphertext[crypto_box_MACBYTES + crypto_box_PUBLICKEYBYTES];
			read = fd_read(client->fd, (unsigned char *)&ciphertext, sizeof(ciphertext));

			if (crypto_box_open_easy(cl_st_pk, ciphertext, crypto_box_MACBYTES + crypto_box_PUBLICKEYBYTES, encap.nonce, cl_lt_pk, cfg.sk) != 0) {
				if (cfg.debug) lprintf("[dbug] Ephemeral key exchange failed\n");
			} else {
				lprintf("[info] Ephemeral key exchanged\n");

				crypto_box_beforenm(sshk, cl_st_pk, st_sk);
			}
			break;
		}
		case STREAM: {
			read = fd_read(client->fd, (unsigned char *)&cbuffer, ntohs(encap.data_len));

			if (crypto_box_open_easy_afternm(buffer, cbuffer, ntohs(encap.data_len), encap.nonce, sshk) != 0) {
				if (cfg.debug) lprintf("[dbug] Unable to decrypt packet\n");
			} else {
				int nwrite;

				if((nwrite = write(_tmp_tap_fd, buffer, read))<0){
					lprint("[warn] Cannot write device\n");
					return;
				}

				if (cfg.debug) lprintf("[dbug] Wrote %d bytes to tun\n", nwrite);
			}
			break;
		}
		case PING:
			encap.client_id = htonl(1);
			encap.packet_chk = htonl(PACKET_MAGIC);
			encap.packet_cnt = htonl(pcnt--);
			encap.data_len = 0;
			encap.mode = PING_BACK;

			send(client->fd, (unsigned char *)&encap, sizeof(encap), 0);
			break;
		case PING_BACK:
			lprintf("[info] Server pingback\n");
			break;
		default:
			if (cfg.debug) lprintf("[dbug] Packet dropped\n");

	}

	if (sesscnt == 1) {
		lprintf("[info] Ephemeral keypair expired\n");

		unsigned char nonce[crypto_box_NONCEBYTES];
		unsigned char ciphertext[crypto_box_MACBYTES + crypto_box_PUBLICKEYBYTES];
		randombytes_buf(nonce, crypto_box_NONCEBYTES);
		crypto_box_keypair(st_pk, st_sk);

		pcnt = PACKET_CNT;
		crypto_box_easy(ciphertext, st_pk, crypto_box_PUBLICKEYBYTES, nonce, cl_lt_pk, cfg.sk);

		encap.client_id = htonl(1);
		encap.packet_chk = htonl(PACKET_MAGIC);
		encap.packet_cnt = htonl(pcnt--);
		encap.data_len = 0;
		encap.mode = INIT_EPHEX;
		memcpy(encap.nonce, nonce, crypto_box_NONCEBYTES);

		if (send(client->fd, (unsigned char *)&encap, sizeof(encap), 0)<0) {
			perror("send");
			return;
		}

		if (send(client->fd, (unsigned char *)&ciphertext, sizeof(ciphertext), 0)<0) {
			perror("send");
			return;
		}
	}
}

/* Accept client requests */
void tun_cb(EV_P_ struct ev_io *watcher, int revents) {
	unsigned char buffer[BUFSIZE];
	unsigned char cbuffer[crypto_box_MACBYTES + BUFSIZE];
	unsigned short nread;

	if((nread = read(watcher->fd, buffer, BUFSIZE))<0){
		lprint("[warn] Cannot read device\n");
		return;
	}

	if (cfg.debug) lprintf("[dbug] Read %d bytes from tun\n", nread);

	unsigned char nonce[crypto_box_NONCEBYTES];
	randombytes_buf(nonce, crypto_box_NONCEBYTES);
	crypto_box_easy_afternm(cbuffer, buffer, nread, nonce, sshk);

	struct wrapper encap;
	encap.client_id = htonl(1);
	encap.packet_chk = htonl(PACKET_MAGIC);
	encap.packet_cnt = htonl(pcnt--);
	encap.data_len = htons(crypto_box_MACBYTES + nread);
	encap.mode = STREAM;
	memcpy(encap.nonce, nonce, crypto_box_NONCEBYTES);

	/* Write packet */
	if (send(_tmp_sock_fd, (unsigned char *)&encap, sizeof(encap), 0)<0){
		perror("send");
		return;
	}

	if (send(_tmp_sock_fd, cbuffer, crypto_box_MACBYTES + nread, 0)<0) {
		perror("send2");
		return;
	}

	if (cfg.debug) lprintf("[dbug] Wrote %d bytes to socket\n", crypto_box_MACBYTES + nread);
}

/* Accept client requests */
void accept_cb(EV_P_ struct ev_io *watcher, int revents) {
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int sd;
	struct sock_ev_client *client = (struct sock_ev_client *)malloc(sizeof(struct sock_ev_client));
	
	if (EV_ERROR & revents) {
		perror("got invalid event");
		return;
	}

	// Accept client request
	sd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);
	if (sd < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("accept error");
			return;
		}
	}

	// Set it non-blocking
	if (setnonblock(sd)<0) {
		perror("echo server socket nonblock");
		return;
	}

	_tmp_sock_fd = sd;
	client->fd = sd;
	client->index = ++total_clients; // Increment total_clients count
	lprint("[info] Successfully connected with client\n");
	lprintf("[info] %d client(s) connected\n", total_clients);

	vector_append(&vector_clients, (void *)client);

	// Initialize and start watcher to read client requests
	ev_io_init(&client->io, read_cb, sd, EV_READ);
	ev_io_start(EV_A_ &client->io);
}

int client_connect(EV_P_ char *remote_addr) {
	int sd;
 	struct sockaddr_in remote;
 	struct wrapper encap;
 	conn_client = (struct sock_ev_client *)malloc(sizeof(struct sock_ev_client));

 	// Create client socket
	if ((sd = socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("socket error");
		return -1;
	}

	// Set it non-blocking
	if (setnonblock(sd)<0) {
		perror("echo server socket nonblock");
		return -1;
	}

	_tmp_sock_fd = sd;
	conn_client->fd = sd;
	conn_client->index = 0;

	// initialize the send callback, but wait to start until there is data to write
	ev_io_init(&conn_client->io, read_cb, sd, EV_READ);
	ev_io_start(EV_A_ &conn_client->io);

	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(DEF_PORT);
	remote.sin_addr.s_addr = inet_addr(remote_addr);

	int res = connect(sd, (struct sockaddr *)&remote, sizeof(remote));
	if (res < 0) {
		if (errno != EINPROGRESS) {
			perror("connect error");
			return -1;
		}
	}
	lprintf("[info] Connected to server %s\n", inet_ntoa(remote.sin_addr));

retry:
	encap.client_id = htonl(1);
	encap.packet_chk = htonl(PACKET_MAGIC);
	encap.packet_cnt = htonl(pcnt--);
	encap.data_len = 0;
	encap.mode = PING;

	if (send(conn_client->fd, (unsigned char *)&encap, sizeof(encap), 0)<0){
		perror("send PING");
		goto retry;
	}

	encap.client_id = htonl(1);
	encap.packet_chk = htonl(PACKET_MAGIC);
	encap.packet_cnt = htonl(pcnt--);
	encap.data_len = 0;
	encap.mode = CLIENT_HELLO;

	struct handshake client_key;
	memcpy(client_key.pubkey, cfg.pk, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES);

	if (send(conn_client->fd, (unsigned char *)&encap, sizeof(encap), 0)<0){
		perror("send encap");
		return -1;
	}

	if (send(conn_client->fd, (unsigned char *)&client_key, sizeof(client_key), 0)<0){
		perror("send key");
		return -1;
	}

  	return sd;
}

int server_init(int max_queue) {
	int sd;
	struct sockaddr_in addr;

	// Create server socket
	if ((sd = socket(AF_INET, SOCK_STREAM, 0))<0){
		perror("socket error");
		return -1;
	}

	// Set it non-blocking
	if (setnonblock(sd)<0) {
		perror("echo server socket nonblock");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(DEF_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	// Bind socket to address
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr))<0) {
		perror("bind error");
		return -1;
	}

	// Start listing on the socket
	if (listen(sd, max_queue)<0) {
		perror("listen error");
		return -1;
	}

	return sd;
}

int main(int argc, char *argv[]) {
	int flags = IFF_TUN;
	char remote_ip[ADDRSIZE];
	char config_file[NAME_MAX];
	int sock_fd, option, config = 0;
	loop = EV_DEFAULT;
	struct ev_io w_accept, w_tun;

	memset(sshk, 0, crypto_box_BEFORENMBYTES);
	memset(&cfg, 0, sizeof(config_t));
	
	cfg.server = 1;
	cfg.port = DEF_PORT;
	cfg.if_name = strdup(DEF_IFNAME);
	cfg.ip = strdup(DEF_ROUTER_ADDR);
	cfg.ip_netmask = strdup(DEF_NETMASK);
	cfg.debug = 0;
	cfg.max_conn = DEF_MAX_CLIENTS;

	// Start log
	start_log();

	// Initialize NaCl
	sodium_init();

	// Initialize client pool
	vector_init(&vector_clients);

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
				free(cfg.if_name);
				cfg.if_name = strdup(optarg);
				break;
			case 'c':
				cfg.server = 0;
				strncpy(remote_ip, optarg, ADDRSIZE-1);
				break;
			case 'p':
				cfg.port = atoi(optarg);
				break;
			case 'a':
				flags = IFF_TAP;
				break;
			case 'f':
				config = 1;
				strncpy(config_file, optarg, NAME_MAX-1);
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

			if (isnull(cfg.cacert, crypto_sign_BYTES + CERTSIZE)) {
				lprintf("[erro] No CA certificate in config, see genca\n");
				return 1;
			}

			if (isnull(cfg.capk, crypto_sign_PUBLICKEYBYTES)) {
				lprintf("[erro] No CA public key in config, see genca\n");
				return 1;
			}

			if (isnull(cfg.cask, crypto_sign_SECRETKEYBYTES)) {
				lprintf("[erro] No CA private key in config, see genca\n");
				return 1;
			}

			crypto_generichash(fp, crypto_generichash_BYTES, cfg.cacert, (crypto_sign_BYTES + CERTSIZE), cfg.capk, crypto_sign_PUBLICKEYBYTES);
			crypto_box_keypair(pk, sk);
			strncat((char *)pk, (char *)fp, crypto_generichash_BYTES); //TODO: memset with offset

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

	if (isnull(cfg.cacert, crypto_sign_BYTES + CERTSIZE)) {
		lprintf("[erro] No CA certificate in config, see genca\n");
		goto error;
	}

	if (isnull(cfg.capk, crypto_sign_PUBLICKEYBYTES)) {
		lprintf("[erro] No CA public key in config, see genca\n");
		goto error;
	}

	if (isnull(cfg.pk, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_generichash_BYTES)) {
		lprintf("[erro] No client public key in config, see gencert\n");
		goto error;
	}

	if (isnull(cfg.sk, crypto_box_SECRETKEYBYTES)) {
		lprintf("[erro] No client private key in config, see gencert\n");
		goto error;
	}

#if 0
	// Handle shutdown correct
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		lprint("[erro] Cannot hook signal\n");
		goto error;
	}

	if (signal(SIGTERM, sig_handler) == SIG_ERR) {
		lprint("[erro] Cannot hook signal\n");
		goto error;
	}

	if (signal(SIGUSR1, sig_handler) == SIG_ERR) {
		lprint("[erro] Cannot hook signal\n");
		goto error;
	}
#endif

	/* Initialize tun/tap interface */
	_tmp_tap_fd = tun_init(cfg.if_name, flags | IFF_NO_PI);

	// Initialize and start watcher to read tun interface
	ev_io_init(&w_tun, tun_cb, _tmp_tap_fd, EV_READ);
	ev_io_start(EV_A_ &w_tun);

	/* Client or server mode */
	if (!cfg.server) {
		/* Assign the destination address */
		client_connect(EV_A_ remote_ip);
	} else {
		/* Server, set local addr */
		int sock = set_ip(cfg.if_name, cfg.ip);
		set_netmask(sock, cfg.if_name, cfg.ip_netmask);

		sock_fd = server_init(DEF_MAX_CLIENTS);

		// Initialize and start a watcher to accepts client requests
		ev_io_init(&w_accept, accept_cb, sock_fd, EV_READ);
		ev_io_start(EV_A_ &w_accept);
	}

	// Start infinite loop
	lprint("[info] Starting events\n");
	ev_loop(EV_A_ 0);

error:
	ev_loop_destroy(loop);

	free(cfg.if_name);
	free(cfg.ip);
	free(cfg.ip_netmask);

	sodium_memzero(sshk, sizeof(sshk));
	sodium_memzero(st_sk, crypto_box_SECRETKEYBYTES);

	vector_free(&vector_clients);

	stop_log();

	return 0;
}
