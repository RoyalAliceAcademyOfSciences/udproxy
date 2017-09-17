/*
 * client.c
 *
 *  Created on: Nov 13, 2016
 *      Author: MiniLight
 */

#include "common.h"
#include "netpacketkits.h"

#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

// max length of fastopen payload
#define UDPROXY_FO_MAX		1350
// handshake timeout in sec
#define UDPROXY_PING_MAX 	4

static uint udp_timeout_new = 30;
static uint udp_timeout_established = 180;
static uint enable_verbose = 0;
static uv_loop_t * loop = NULL;
static uv_timer_t rm_timeout_timer;

static u_int16_t queue_num = 0;
static int raw_sock;
static uv_poll_t nfqueue_handle;
static struct sockaddr proxy_sockaddr;

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
	u_char protocol;
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

static ClientPortMap * client_map_head = NULL;
static ClientDnatMap * client_dnatmap_head = NULL;

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
// match ip in dnat map
static int client_dnat_find_by_addr(ClientDnatMap *e, const struct sockaddr_in * naddr)
{
	//for Debug
//	LOG("SUBNET:0x%08x MATCPRT:%05d\n", e->subnet, e->port);
//	LOG("MASKIP:0x%08x DESTPRT:%05d\n", e->mask & naddr->sin_addr.s_addr, naddr->sin_port);
//	LOG("SNMASK:0x%08x DESTIP:0x%08x\n", e->mask, naddr->sin_addr.s_addr);
	if((e->subnet == (e->mask & naddr->sin_addr.s_addr)) && (e->port == naddr->sin_port || e->port == 0))
		return 0;
	return -1;
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
				LOG("RECV HS PKT: 0x%08x %05d\n", ep->remote_addr, ntohs(ep->remote_port));

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
		size_t ip_packet_size;
		char * ip_packet;
		if(map->protocol == IPPROTO_UDP)
			ip_packet = build_udpip_packet(buf->base, nread, &ip_packet_size, saddr, daddr, sport, dport);
        else if(map->protocol == IPPROTO_TCP)
			ip_packet = build_tcpip_packet(buf->base, nread, &ip_packet_size, saddr, daddr, sport, dport);

		struct sockaddr_in daddr_in;
		bzero(&daddr_in, sizeof(daddr_in));
		daddr_in.sin_family = AF_INET;
		daddr_in.sin_addr.s_addr = daddr;

		LOG("RAW SOCK SED: F[0x%08x %05d] T[0x%08x %05d]\n", saddr, ntohs(sport), daddr, ntohs(dport));
		if (sendto(raw_sock, ip_packet, ip_packet_size, 0, (struct sockaddr *) &daddr_in, (socklen_t) sizeof(daddr_in)) < 0)
			ERROR("raw socket sendto()\n");

		free(ip_packet);

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
	size_t ip4h_size = ip4h->ihl * 4;
	Socket *socket = (Socket *) (pkg_data + ip4h_size);

	//save IP & port
	ClientAddr peer_addr;
	peer_addr.ipaddr_local = ip4h->saddr;
	peer_addr.port_local = socket->port.s;
	peer_addr.ipaddr_remote = ip4h->daddr;
	peer_addr.port_remote = socket->port.d;

	//udp or tcp
	u_char *payload;
	size_t payload_size;
	if(ip4h->protocol == IPPROTO_UDP)
	{
		payload = ((u_char*) socket) + sizeof(struct udphdr);
		payload_size = pkg_data_len - sizeof(struct udphdr) - ip4h_size;
	}
	else if (ip4h->protocol == IPPROTO_TCP)
	{
		//*4 = SequenceNumber(4), *16 = Checksum(2) + UrgentPointer(2)
		memcpy(((u_char*) socket) + 16, ((u_char*) socket) + 4, 4);
		//8 = src(2) + dst(2) + Checksum(2) + UrgentPointer(2)
		payload = ((u_char*) socket) + 8;
		payload_size = pkg_data_len - ip4h_size - 8;
	}
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);


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
		map->protocol = ip4h->protocol;

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
			if(sizeof(EstablishPacket)+payload_size > UDPROXY_FO_MAX)
			{
				// create non-fastopen Handshake packet
				buf = uv_buf_init(malloc(sizeof(EstablishPacket)), sizeof(EstablishPacket));
				ep = (EstablishPacket*) buf.base;

				if(map->waiting_handshake_data.len > 0)
					free(map->waiting_handshake_data.base);
				map->waiting_handshake_data.len = payload_size;
				map->waiting_handshake_data.base = malloc(payload_size);
				// copy non-fastopen data packet to waiting send field
				memcpy(map->waiting_handshake_data.base, payload, payload_size);
			}
			// fastopen
			else
			{
				buf = uv_buf_init(malloc(sizeof(EstablishPacket)+payload_size), sizeof(EstablishPacket)+payload_size);
				ep = (EstablishPacket*) buf.base;
				memcpy(ep->data, payload, payload_size);
			}

			ep->magic_number = UDPROXY_MN;
			ep->remote_addr = ip4h->daddr;
			ep->remote_port = socket->port.d;
			ep->protocol = ip4h->protocol;

			// DNAT match search
			if(client_dnatmap_head)
			{
				struct sockaddr_in naddr;
				naddr.sin_addr.s_addr = ip4h->daddr;
				naddr.sin_port = socket->port.d;
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
			buf = uv_buf_init(malloc(payload_size), payload_size);
			memcpy(buf.base, payload, payload_size);
		}
	}
	else
	{
		buf = uv_buf_init(malloc(payload_size), payload_size);
		memcpy(buf.base, payload, payload_size);
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

int as_client(int argc, char **argv)
{
	bzero(&proxy_sockaddr, sizeof(proxy_sockaddr));
	struct sockaddr_in * proxy_sockaddr_in = (struct sockaddr_in *) &proxy_sockaddr;
	proxy_sockaddr_in->sin_family = AF_INET;

	int i = 1;
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
		{
			enable_verbose = 1;
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

					long long int pre_mask = 0xFFFFFFFF;
					dnat->mask = pre_mask << (32 - subnet_cidr);
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

	LOG("client startup\n");
	loop = uv_default_loop();
	uv_timer_init(loop, &rm_timeout_timer);
	uv_timer_start(&rm_timeout_timer, rm_timeout_client, 1000, 1000);

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

	return uv_run(loop, UV_RUN_DEFAULT);

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
