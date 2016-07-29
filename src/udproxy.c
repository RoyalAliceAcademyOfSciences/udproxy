/*
 ============================================================================
 Name        : udproxy.c
 Author      : MiniLight
 Version     :
 Copyright   : GPLv3
 Description : a simple proxy server for UDP
 ============================================================================
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <uv.h>

#include "utlist.h"

#define UDPROXY_MN	htonl(0x20160603)

#ifdef DEBUG
#define LOG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define LOG(x, ...) if (enable_verbose) { printf(x, ##__VA_ARGS__); }
#endif
#define ERROR(x, ...) fprintf(stderr, x, ##__VA_ARGS__)

typedef struct establishPacket
{
	uint magic_number;
	uint remote_addr;
	u_int16_t remote_port;
} EstablishPacket;

typedef struct proxyPortMap
{
	struct sockaddr client_addr;
	struct sockaddr remote_addr;
	uv_udp_t remote_sock;
	u_char new;
	struct timeval timeout;
	struct proxyPortMap *next, *prev;
} ProxyPortMap;

typedef struct clientAddr
{
	uint ipaddr_local;
	u_int16_t port_local;
	uint ipaddr_remote;
	u_int16_t port_remote;
} ClientAddr;

typedef struct clientPortMap
{
	ClientAddr peer_addr;
	//connect to proxy, local side socket.
	uv_udp_t local_sock;
	u_char new;
	u_char unhandshaked;
	uv_buf_t waiting_handshake_data;
	struct timeval timeout;
	struct clientPortMap *next, *prev;
} ClientPortMap;

static ProxyPortMap * proxy_map_head = NULL;
static ClientPortMap * client_map_head = NULL;

static int enable_verbose = 0;
static int enable_isclient = 0;
static int enable_addzero = 0;

static uv_loop_t * loop = NULL;

static uv_timer_t rm_timeout_timer;
static uint udp_timeout_new = 30;
static uint udp_timeout_established = 180;
static u_int16_t queue_num = 0;

static struct sockaddr proxy_sockaddr;

static uv_udp_t udproxy_socket;
static uv_poll_t nfqueue_handle;
static int raw_sock;

static void udproxy_on_send(uv_udp_send_t* req, int status)
{
	if (enable_verbose && status)
	{
		ERROR("on_send() error!\n");
	}

	//free() memory ponits after send
	int i;
	for (i = 0; i < req->nbufs; i++)
		free(((char**)req->data)[i]);
	free(req->data);

	free(req);
}

static int udproxy_udp_send(uv_udp_t* handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr* addr)
{
	uv_udp_send_t* req = malloc(sizeof(uv_udp_send_t));

	//tell on_send(), which memory points need to free()
	req->data = malloc(sizeof(char*) * nbufs);
	int i;
	for(i=0;i<nbufs;i++)
		((char**)req->data)[i] = bufs[i].base;

	return uv_udp_send(req, handle, bufs, nbufs, addr, udproxy_on_send);
}

static int client_find_by_addr(ClientPortMap * e, ClientAddr * peer_addr)
{
	return memcmp(&e->peer_addr, peer_addr, sizeof(ClientAddr));
}

static int client_find_by_sock(ClientPortMap * e, uv_udp_t * local_sock)
{
	return &e->local_sock - local_sock;
}

static int proxy_find_by_addr(ProxyPortMap * e, const struct sockaddr * client_addr)
{
	return memcmp(&e->client_addr, client_addr, sizeof(struct sockaddr_in));
}

static int proxy_find_by_sock(ProxyPortMap * e, uv_udp_t * remote_sock)
{
	return &e->remote_sock - remote_sock;
}

static void alloc_buffer(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
	buf->base = malloc(size);
	buf->len = size;
}

static uv_buf_t copy_buffer(const uv_buf_t * buf, size_t suggested_size)
{
	uv_buf_t result;
	result.base = malloc(suggested_size);
	result.len = suggested_size;
	memcpy(result.base, buf->base, suggested_size);
	return result;
}

static void rm_timeout_proxy(uv_timer_t* handle)
{
	if (!proxy_map_head)
		return;

	struct timeval timestamp;
	gettimeofday(&timestamp, NULL);

	ProxyPortMap *elt, *tmp;
	DL_FOREACH_SAFE(proxy_map_head,elt,tmp)
	{
		if (elt->timeout.tv_sec - timestamp.tv_sec < 0)
		{
			LOG("connection timout\n");
			if (elt->prev)
				DL_DELETE(proxy_map_head, elt);
			else
				proxy_map_head = NULL;
			uv_udp_recv_stop(&elt->remote_sock);
			uv_close((uv_handle_t*) &elt->remote_sock, NULL);
			free(elt);
		}
	}
}

static void rm_timeout_client(uv_timer_t* handle)
{
	if (!client_map_head)
		return;

	struct timeval timestamp;
	gettimeofday(&timestamp, NULL);

	ClientPortMap *elt, *tmp;
	DL_FOREACH_SAFE(client_map_head,elt,tmp)
	{
		if (elt->timeout.tv_sec - timestamp.tv_sec < 0)
		{
			LOG("connection timout\n");
			uv_udp_recv_stop(&elt->local_sock);
			uv_close((uv_handle_t*) &elt->local_sock, NULL);
			if (elt->unhandshaked)
				free(elt->waiting_handshake_data.base);

			if (elt->prev)
				DL_DELETE(client_map_head, elt);
			else
				client_map_head = NULL;
			free(elt);
		}
	}
}

static void on_read_from_remote(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
	if (!addr)
	{
		free(buf->base);
		return;
	}

	ProxyPortMap * map;
	DL_SEARCH(proxy_map_head, map, handle, proxy_find_by_sock)
			;

	if (map)
	{
		uv_buf_t send_data = copy_buffer(buf, nread);
		udproxy_udp_send(&udproxy_socket, &send_data, 1, &map->client_addr);

		map->new = 0;
		gettimeofday(&map->timeout, NULL);
		map->timeout.tv_sec += udp_timeout_established;
	}

	free(buf->base);
}

static void on_read_from_client(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* src_addr, unsigned flags)
{
	if (!src_addr)
	{
		free(buf->base);
		return;
	}

	ProxyPortMap * map;
	DL_SEARCH(proxy_map_head, map, src_addr, proxy_find_by_addr)
			;

	if (!map)
	{
		EstablishPacket * ep = (EstablishPacket*) buf->base;
		if (nread != sizeof(EstablishPacket) || ep->magic_number != UDPROXY_MN)
		{
			ERROR("new connection packet error.\n");
			free(buf->base);
			return;
		}

		map = malloc(sizeof(ProxyPortMap));
		bzero(map, sizeof(ProxyPortMap));
		DL_APPEND(proxy_map_head, map);

		map->new = 1;

		memcpy(&map->client_addr, src_addr, sizeof(struct sockaddr));

		struct sockaddr_in * remote_addr = (struct sockaddr_in*) (&map->remote_addr);
		remote_addr->sin_addr.s_addr = ep->remote_addr;
		remote_addr->sin_port = ep->remote_port;
		remote_addr->sin_family = AF_INET;

		uv_udp_init(loop, &map->remote_sock);
		uv_udp_recv_start(&map->remote_sock, alloc_buffer, on_read_from_remote);
		LOG("new connection established.\n");

		//tell the src: connection established.
		uv_buf_t send_data = copy_buffer(buf, nread);
		udproxy_udp_send(handle, &send_data, 1, src_addr);
	}
	else
	{
		uv_buf_t send_data = copy_buffer(buf, nread);
		udproxy_udp_send(&map->remote_sock, &send_data, 1, &map->remote_addr);
	}

	//time update
	gettimeofday(&map->timeout, NULL);
	if (map->new)
		map->timeout.tv_sec += udp_timeout_new;
	else
		map->timeout.tv_sec += udp_timeout_established;

	free(buf->base);
	return;
}

static char * proxy_get_udp_packet(char* data, size_t d_size, size_t * result_size, uint saddr, uint daddr, u_int16_t sport, u_int16_t dport)
{
	struct pseudo_udphdr
	{
		u_int32_t source;
		u_int32_t dest;
		u_int8_t zero; //reserved, check http://www.rhyshaden.com/udp.htm
		u_int8_t protocol;
		u_int16_t udp_length;
	};

	*result_size = d_size + sizeof(struct iphdr) + sizeof(struct udphdr);

	//set all header pointer
	char * result = malloc(*result_size);
	struct iphdr *ip4h = (struct iphdr *) result;
	struct udphdr *udph = (struct udphdr *) (((char*) ip4h) + sizeof(struct iphdr));
	struct pseudo_udphdr *pudph = (struct pseudo_udphdr *) (((char*) udph) - sizeof(struct pseudo_udphdr));
	char *udp_data = ((char*) udph) + sizeof(struct udphdr);

	//copy data
	memcpy(udp_data, data, d_size);

	//set udp header
	udph->dest = dport;
	udph->source = sport;
	udph->len = htons(d_size + sizeof(struct udphdr));

	//set udp pseudo header
	pudph->dest = daddr;
	pudph->source = saddr;
	pudph->zero = 0;
	pudph->protocol = IPPROTO_UDP;    //IPPROTO_RAW;    /* protocol at L4 */
	pudph->udp_length = udph->len;

	//checksum
	udph->check = 0;
	u_int16_t *addr = (u_int16_t *) pudph;
	int len = sizeof(struct pseudo_udphdr) + ntohs(pudph->udp_length);
	u_int32_t sum = 0;
	while (len > 1)
	{
		sum += *addr++;
		len -= 2;
	}
	if (len == 1)
	{
		//Prepare for different architectures
		if (enable_addzero)
		{
			u_int8_t tmp = *(u_int8_t *) addr;
			u_int16_t last = (u_int16_t) (tmp << 8);        // add 0
			sum += last;
		}
		else
			sum += *(u_int8_t*) addr;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);  //add carry
	udph->check = ~sum;

	//set ipv4 header
	ip4h->ihl = 5; //header length
	ip4h->version = 4;
	ip4h->tos = 0x0;
	ip4h->id = 0;
	ip4h->frag_off = htons(0x4000); /* DF */
	ip4h->ttl = 64; /* default value */
	ip4h->protocol = IPPROTO_UDP;    //IPPROTO_RAW;    /* protocol at L4 */
	ip4h->check = 0; /* not needed in iphdr */
	ip4h->saddr = saddr;
	ip4h->daddr = daddr;

	return result;
}

static void on_read_from_proxy(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
	if (!addr)
	{
		free(buf->base);
		return;
	}

	ClientPortMap * map;
	DL_SEARCH(client_map_head, map, handle, client_find_by_sock)
			;

	if (map)
	{
		EstablishPacket * ep = (EstablishPacket*) buf->base;
		//is Handshake packet, timeout do NOT need update
		if (map->unhandshaked && nread == sizeof(EstablishPacket) && ep->magic_number == UDPROXY_MN)
		{
			map->unhandshaked = 0;
			LOG("RECV HS PKT: 0x%08x %05d\n", ep->remote_addr, ntohs(ep->remote_port));
			udproxy_udp_send(&map->local_sock, &map->waiting_handshake_data, 1, &proxy_sockaddr);
		}
		else
		{
			uint saddr = map->peer_addr.ipaddr_remote, daddr = map->peer_addr.ipaddr_local;
			u_int16_t sport = map->peer_addr.port_remote, dport = map->peer_addr.port_local;
			size_t udp_packet_size;
			char * udp_packet = proxy_get_udp_packet(buf->base, nread, &udp_packet_size, saddr, daddr, sport, dport);

			struct sockaddr_in daddr_in;
			bzero(&daddr_in, sizeof(daddr_in));
			daddr_in.sin_family = AF_INET;
			daddr_in.sin_addr.s_addr = daddr;

			LOG("RAW SOCK SED: F[0x%08x %05d] T[0x%08x %05d]\n", saddr, ntohs(sport), daddr, ntohs(dport));
			if (sendto(raw_sock, udp_packet, udp_packet_size, 0, (struct sockaddr *) &daddr_in, (socklen_t) sizeof(daddr_in)) < 0)
				ERROR("raw socket sendto()\n");

			free(udp_packet);

			//update time
			map->new = 0;
			gettimeofday(&map->timeout, NULL);
			map->timeout.tv_sec += udp_timeout_established;
		}
	}

	free(buf->base);
}

static int on_read_from_nfqueue(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	uint id = ntohl(ph->packet_id);

	LOG("NFQUE HWP:0x%04x HOK:%u ID:%u\n", ntohs(ph->hw_protocol), ph->hook, id);

	u_char *pkg_data;
	uint pkg_data_len = nfq_get_payload(nfa, &pkg_data);
	struct iphdr *ip4h = (struct iphdr *) pkg_data;
	struct udphdr *udph = (struct udphdr *) (pkg_data + (ip4h->ihl * 4));

	u_char *udp_data = ((u_char*) udph) + sizeof(struct udphdr);
	size_t udp_size = pkg_data_len - sizeof(struct udphdr) - (ip4h->ihl * 4);

	//save IP & port
	ClientAddr peer_addr;
	peer_addr.ipaddr_local = ip4h->saddr;
	peer_addr.port_local = udph->source;
	peer_addr.ipaddr_remote = ip4h->daddr;
	peer_addr.port_remote = udph->dest;

//	LOG("UDP size: %d\n", udp_size);

	ClientPortMap * map;
	DL_SEARCH(client_map_head, map, &peer_addr, client_find_by_addr)
			;

	if (!map)
	{
		map = malloc(sizeof(ClientPortMap));
		bzero(map, sizeof(ClientPortMap));
		DL_APPEND(client_map_head, map);

		map->new = 1;
		map->unhandshaked = 1;
		map->peer_addr = peer_addr;

		uv_udp_init(loop, &map->local_sock);
		uv_udp_recv_start(&map->local_sock, alloc_buffer, on_read_from_proxy);

		map->waiting_handshake_data.base = malloc(4096);
	}

	//save data to waiting buffer and send Handshake packet
	if (map->unhandshaked)
	{
		memcpy(map->waiting_handshake_data.base, udp_data, udp_size);
		map->waiting_handshake_data.len = udp_size;

		//create Handshake packet
		uv_buf_t handshake_buf = uv_buf_init(malloc(sizeof(EstablishPacket)), sizeof(EstablishPacket));
		EstablishPacket * ep = (EstablishPacket*) handshake_buf.base;
		ep->magic_number = UDPROXY_MN;
		ep->remote_addr = ip4h->daddr;
		ep->remote_port = udph->dest;

		LOG("SEND HS PKT: 0x%08x %05d\n", ep->remote_addr, ntohs(ep->remote_port));
		//send Handshake packet
		udproxy_udp_send(&map->local_sock, &handshake_buf, 1, &proxy_sockaddr);
	}
	else
	{
		uv_buf_t buf = uv_buf_init(malloc(udp_size), udp_size);
		memcpy(buf.base, udp_data, udp_size);
		udproxy_udp_send(&map->local_sock, &buf, 1, &proxy_sockaddr);
	}

	//time update
	gettimeofday(&map->timeout, NULL);
	if (map->new)
		map->timeout.tv_sec += udp_timeout_new;
	else
		map->timeout.tv_sec += udp_timeout_established;

	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static void on_nfqueue_readable(uv_poll_t* handle, int status, int events)
{
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if ((rv = recv(handle->io_watcher.fd, buf, sizeof(buf), 0)) && rv >= 0)
		nfq_handle_packet(handle->data, buf, rv);
}

void as_server()
{
	LOG("server startup\n");
	uv_timer_init(loop, &rm_timeout_timer);
	uv_timer_start(&rm_timeout_timer, rm_timeout_proxy, 1000, 1000);

	uv_udp_init(loop, &udproxy_socket);
	if (uv_udp_bind(&udproxy_socket, &proxy_sockaddr, 0) != 0)
	{
		ERROR("port bind error\n");
		exit(1);
	}

	struct sockaddr_in name;
	int name_len = sizeof(name);
	uv_udp_getsockname(&udproxy_socket, (struct sockaddr*) &name, &name_len);

	LOG("server listening: %s:%d\n", inet_ntoa(name.sin_addr), ntohs(name.sin_port));
	uv_udp_recv_start(&udproxy_socket, alloc_buffer, on_read_from_client);
}

void as_client()
{
	LOG("client startup\n");
	uv_timer_init(loop, &rm_timeout_timer);
	uv_timer_start(&rm_timeout_timer, rm_timeout_client, 1000, 1000);

	struct sockaddr_in * proxy_sockaddr_in = (struct sockaddr_in *) &proxy_sockaddr;
	LOG("connect to proxy server: %s:%d\n", inet_ntoa(proxy_sockaddr_in->sin_addr), ntohs(proxy_sockaddr_in->sin_port));

	//Prepare for different architectures
	u_int16_t test[] =
	{ 0x1234 };
	enable_addzero = ((u_int32_t) ((u_int16_t) (*(u_int8_t *) test) << 8)) == 0x00001200;        // need add 0
	LOG("addzero checksum enable: %d\n", enable_addzero);

	//Create a raw socket of type IPPROTO
	LOG("opening raw socket\n");
	raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_sock == -1)
	{
		//socket creation failed, may be because of non-root privileges
		ERROR("Failed to create raw socket");
		exit(1);
	}

	int opt = IP_PMTUDISC_DONT;
	setsockopt(raw_sock, IPPROTO_IP, IP_MTU_DISCOVER, &opt, sizeof(opt));

	LOG("opening library handle\n");
	struct nfq_handle *h = nfq_open();
	if (!h)
	{
		ERROR("error during nfq_open()\n");
		exit(1);
	}

	LOG("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		ERROR("error during nfq_unbind_pf()\n");
		exit(1);
	}

	LOG("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		ERROR("error during nfq_bind_pf()\n");
		exit(1);
	}

	LOG("binding this socket to queue '%d'\n", queue_num);
	struct nfq_q_handle *qh = nfq_create_queue(h, queue_num, &on_read_from_nfqueue, NULL);
	if (!qh)
	{
		ERROR("error during nfq_create_queue()\n");
		exit(1);
	}

	LOG("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		ERROR("can't set packet_copy mode\n");
		exit(1);
	}

	uv_poll_init(loop, &nfqueue_handle, nfq_fd(h));
	nfqueue_handle.data = h;
	uv_poll_start(&nfqueue_handle, UV_READABLE, on_nfqueue_readable);

//	LOG("unbinding from queue '%d'\n", queue_num);
//	nfq_destroy_queue(qh);
//
//#ifdef INSANE
//	/* normally, applications SHOULD NOT issue this command, since
//	 * it detaches other programs/sockets from AF_INET, too ! */
//	LOG("unbinding from AF_INET\n");
//	nfq_unbind_pf(h, AF_INET);
//#endif
//
//	LOG("closing library handle\n");
//	nfq_close(h);
}

void print_help()
{
	printf("Usage:\n"
			"udproxy --port|-p [--verbose|-v] [--clientmode|-c --address|-a] [--queue num|-q]\n");
}

int main(int argc, char **argv)
{
	bzero(&proxy_sockaddr, sizeof(proxy_sockaddr));
	struct sockaddr_in * proxy_sockaddr_in = (struct sockaddr_in *) &proxy_sockaddr;
	proxy_sockaddr_in->sin_family = AF_INET;

	int i = 1;
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{
			print_help();
			exit(0);
		}
		else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
		{
			enable_verbose = 1;
		}
		else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--clientmode") == 0)
		{
			enable_isclient = 1;
		}
		else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--address") == 0)
		{
			if (i + 1 < argc)
			{
				proxy_sockaddr_in->sin_addr.s_addr = inet_addr(argv[i + 1]);
				i++;
			}
			else
			{
				ERROR("Invalid arguments.\n");
				print_help();
				exit(0);
			}
		}
		else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0)
		{
			if (i + 1 < argc)
			{
				proxy_sockaddr_in->sin_port = htons(atoi(argv[i + 1]));
				i++;
			}
			else
			{
				ERROR("Invalid arguments.\n");
				print_help();
				exit(0);
			}
		}
		else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--queue") == 0)
		{
			if (i + 1 < argc)
			{
				queue_num = atoi(argv[i + 1]);
				i++;
			}
			else
			{
				ERROR("Invalid arguments.\n");
				print_help();
				exit(0);
			}
		}
	}

	loop = uv_default_loop();

	if (enable_isclient == 1)
		as_client();
	else
		as_server();

	return uv_run(loop, UV_RUN_DEFAULT);
}
