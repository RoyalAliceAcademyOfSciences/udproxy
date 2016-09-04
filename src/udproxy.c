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

// magic number
#define UDPROXY_MN		htonl(0x20160603)
// max length of fastopen payload
#define UDPROXY_FO_MAX		1350
// handshake timeout in sec
#define UDPROXY_PING_MAX 	4

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
	u_char data[];
} EstablishPacket;

typedef struct proxyPortMap
{
	struct sockaddr client_addr;
	struct sockaddr remote_addr;
	uv_udp_t remote_sock;
	u_char new;
	u_char unhandshaked;
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
	struct timeval time_handshake;
	uv_buf_t waiting_handshake_data;
	struct timeval timeout;
	struct clientPortMap *next, *prev;
} ClientPortMap;

typedef struct clientDnatMap
{
	uint mask;
	uint subnet;
	u_int16_t port;
	uint ipaddr_nat_dest;
	u_int16_t port_nat_dest;
	struct clientDnatMap *next, *prev;
} ClientDnatMap;

static ProxyPortMap * proxy_map_head = NULL;
static ClientPortMap * client_map_head = NULL;
static ClientDnatMap * client_dnatmap_head = NULL;

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

/*
 * ==========================
 * find port map
 * ==========================
 */
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
/*
 * ==========================
 * find port map
 * ==========================
 */

// match ip in dnat map
static int client_dnat_find_by_addr(ClientDnatMap *e, const struct sockaddr_in * naddr)
{
	if((e->subnet == (e->mask & naddr->sin_addr.s_addr)) && (e->port == naddr->sin_port || e->port == 0))
		return 0;
	return -1;
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
			if (elt->waiting_handshake_data.len > 0)
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
	EstablishPacket * ep = (EstablishPacket*) buf->base;

	ProxyPortMap * map;
	DL_SEARCH(proxy_map_head, map, src_addr, proxy_find_by_addr)
			;

	if (!map)
	{
		if (ep->magic_number != UDPROXY_MN || nread < sizeof(EstablishPacket))
		{
			ERROR("new connection packet error.\n");
			free(buf->base);
			return;
		}

		map = malloc(sizeof(ProxyPortMap));
		bzero(map, sizeof(ProxyPortMap));
		DL_APPEND(proxy_map_head, map);

		map->new = 1;
		map->unhandshaked = 1;

		memcpy(&map->client_addr, src_addr, sizeof(struct sockaddr));

		struct sockaddr_in * remote_addr = (struct sockaddr_in*) (&map->remote_addr);
		remote_addr->sin_addr.s_addr = ep->remote_addr;
		remote_addr->sin_port = ep->remote_port;
		remote_addr->sin_family = AF_INET;

		uv_udp_init(loop, &map->remote_sock);
		uv_udp_recv_start(&map->remote_sock, alloc_buffer, on_read_from_remote);
		LOG("new connection open.\n");
	}

	if(map->unhandshaked)
	{
		if(ep->magic_number == UDPROXY_MN && nread >= sizeof(EstablishPacket))
		{
			//is fastopen packet, send the payload data
			if(nread > sizeof(EstablishPacket))
			{
				uint ep_data_len = nread - sizeof(EstablishPacket);
				uv_buf_t send_data;
				send_data.base = malloc(ep_data_len);
				send_data.len = ep_data_len;
				memcpy(send_data.base, ep->data, ep_data_len);
				udproxy_udp_send(&map->remote_sock, &send_data, 1, &map->remote_addr);
			}
			//tell the client: connection established.
			uv_buf_t handshake_report = copy_buffer(buf, sizeof(EstablishPacket));
			udproxy_udp_send(handle, &handshake_report, 1, src_addr);
		}
		// no more handshake packet, connection established.
		else
		{
			map->unhandshaked = 0;
			uv_buf_t send_data = copy_buffer(buf, nread);
			udproxy_udp_send(&map->remote_sock, &send_data, 1, &map->remote_addr);
		}
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
		if (map->unhandshaked)
		{
			map->unhandshaked = 0;
			EstablishPacket * ep = (EstablishPacket*)buf->base;
			//is Handshake report packet
			if (nread == sizeof(EstablishPacket) && ep->magic_number == UDPROXY_MN)
			{
				LOG("RECV HS PKT: 0x%08x %05d\n", ep->remote_addr,ntohs(ep->remote_port));

				//prepare for non-fastopen Handshake packet
				if(map->waiting_handshake_data.len > 0)
				{
					udproxy_udp_send(&map->local_sock, &map->waiting_handshake_data, 1, &proxy_sockaddr);
					map->waiting_handshake_data.len = 0;
				}

				free(buf->base);
				//timeout do NOT need update
				return;
			}
		}

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
		map->time_handshake.tv_sec = 0;
		map->peer_addr = peer_addr;
		map->waiting_handshake_data.len = 0;

		uv_udp_init(loop, &map->local_sock);
		uv_udp_recv_start(&map->local_sock, alloc_buffer, on_read_from_proxy);
	}

	uv_buf_t buf;
	if (map->unhandshaked)
	{
		struct timeval now;
		gettimeofday(&now, NULL);
		if(now.tv_sec - map->time_handshake.tv_sec >= UDPROXY_PING_MAX)
		{
			EstablishPacket * ep;

			// non-fastopen, save data to waiting buffer
			if(sizeof(EstablishPacket)+udp_size > UDPROXY_FO_MAX)
			{
				// create non-fastopen Handshake packet
				buf = uv_buf_init(malloc(sizeof(EstablishPacket)), sizeof(EstablishPacket));
				ep = (EstablishPacket*) buf.base;

				if(map->waiting_handshake_data.len > 0)
					free(map->waiting_handshake_data.base);
				map->waiting_handshake_data.len = udp_size;
				map->waiting_handshake_data.base = malloc(udp_size);
				// copy non-fastopen data packet to waiting send field
				memcpy(map->waiting_handshake_data.base, udp_data, udp_size);
			}
			// fastopen
			else
			{
				buf = uv_buf_init(malloc(sizeof(EstablishPacket)+udp_size), sizeof(EstablishPacket)+udp_size);
				ep = (EstablishPacket*) buf.base;
				memcpy(ep->data, udp_data, udp_size);
			}

			ep->magic_number = UDPROXY_MN;
			ep->remote_addr = ip4h->daddr;
			ep->remote_port = udph->dest;

			// DNAT match search
			if(client_dnatmap_head)
			{
				struct sockaddr_in naddr;
				naddr.sin_addr.s_addr = ip4h->daddr;
				naddr.sin_port = udph->dest;
				ClientDnatMap * dnat = NULL;
				DL_SEARCH(client_dnatmap_head, dnat, &naddr, client_dnat_find_by_addr)
						;

				// replace IP address and port, if matched
				if(dnat)
				{
					ep->remote_addr = dnat->ipaddr_nat_dest;
					ep->remote_port = dnat->port_nat_dest;
				}
			}

			// log Handshake packet
			LOG("SEND HS PKT: 0x%08x %05d\n", ep->remote_addr, ntohs(ep->remote_port));
			// update handshake time
			map->time_handshake = now;
		}
		else
		{
			buf = uv_buf_init(malloc(udp_size), udp_size);
			memcpy(buf.base, udp_data, udp_size);
		}
	}
	else
	{
		buf = uv_buf_init(malloc(udp_size), udp_size);
		memcpy(buf.base, udp_data, udp_size);
	}
	// send handshake packet or raw data
	udproxy_udp_send(&map->local_sock, &buf, 1, &proxy_sockaddr);

	// time update
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
		//if enable "-c" startup as a client, else as a proxy server
		else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--clientmode") == 0)
		{
			enable_isclient = 1;
		}
		//set proxy server address
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
		//set proxy server port
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
		//set nfqueue number
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
		//set DNAT items
		else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dnat") == 0)
		{
			if (i + 1 < argc)
			{
				uint subnet ,nat_dest;
				// DNAT from ip address part
				uint subnet_part[4];
				// DNAT to ip address part
				uint nat_dest_part[4];
				// DNAT from ip address subnet CIDR
				uint subnet_cidr;
				uint subnet_port, nat_dest_port;

				// add DNAT items to the map client_dnatmap_head;
				int ret = sscanf(argv[i + 1],
						//0.0.0.0/0:53-8.8.8.8:53
						"%d.%d.%d.%d/%d:%d-%d.%d.%d.%d:%d",
						&subnet_part[0], &subnet_part[1], &subnet_part[2], &subnet_part[3],
						&subnet_cidr,
						&subnet_port,
						&nat_dest_part[0], &nat_dest_part[1], &nat_dest_part[2], &nat_dest_part[3],
						&nat_dest_port);
				if(ret==11)
				{
					ClientDnatMap * dnat = malloc(sizeof(ClientDnatMap));

					nat_dest = nat_dest_part[0] | nat_dest_part[1] << 8 | nat_dest_part[2] << 16 | nat_dest_part[3] << 24;
					dnat->ipaddr_nat_dest = nat_dest;

					dnat->mask = (0xFFFFFFFFUL << (32 - subnet_cidr)) & 0xFFFFFFFFUL;
					subnet = subnet_part[0] | subnet_part[1] << 8 | subnet_part[2] << 16 | subnet_part[3] << 24;
					dnat->subnet = subnet & dnat->mask;

					dnat->port = htons(subnet_port);
					dnat->port_nat_dest = htons(nat_dest_port);

					DL_APPEND(client_dnatmap_head, dnat);
				}
//				else

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
