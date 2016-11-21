/*
 * server.c
 *
 *  Created on: Nov 13, 2016
 *      Author: MiniLight
 */

#include "common.h"

static uint udp_timeout_new = 30;
static uint udp_timeout_established = 180;
static uint enable_verbose = 0;
static uv_loop_t * loop = NULL;
static uv_timer_t rm_timeout_timer;

static uv_udp_t udproxy_socket;
static struct sockaddr proxy_sockaddr;

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

static ProxyPortMap * proxy_map_head = NULL;

/*
 * ==========================
 * find port map
 * ==========================
 */
static int proxy_find_by_addr(ProxyPortMap * e, const struct sockaddr * client_addr)
{
	return memcmp(&e->client_addr, client_addr, sizeof(struct sockaddr_in));
}

static int proxy_find_by_sock(ProxyPortMap * e, uv_udp_t * remote_sock)
{
	return &e->remote_sock - remote_sock;
}

static uv_buf_t copy_buffer(const uv_buf_t * buf, size_t suggested_size)
{
	uv_buf_t result;
	result.base = malloc(suggested_size);
	result.len = suggested_size;
	memcpy(result.base, buf->base, suggested_size);
	return result;
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
			ERROR("ERR: NON-HS PKT\n");
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
		LOG("NEW RECV HS PKT: 0x%08x %05d  PLD LEN:%04zu\n", ep->remote_addr, ntohs(ep->remote_port), nread);
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
				//todo TCP
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
			//todo TCP
			udproxy_udp_send(&map->remote_sock, &send_data, 1, &map->remote_addr);
		}
	}
	else
	{
		uv_buf_t send_data = copy_buffer(buf, nread);
		//todo TCP
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

int as_server(int argc, char **argv)
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
	}

	LOG("server startup\n");
	loop = uv_default_loop();
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

	return uv_run(loop, UV_RUN_DEFAULT);
}
