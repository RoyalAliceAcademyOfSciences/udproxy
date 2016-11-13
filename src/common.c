/*
 * common.c
 *
 *  Created on: Nov 13, 2016
 *      Author: MiniLight
 */

#include "common.h"

void print_help()
{
	printf("Usage:\n"
			"udproxy --port|-p [--verbose|-v] [--clientmode|-c --address|-a] [--queue num|-q]\n");
}

void alloc_buffer(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
	buf->base = malloc(size);
	buf->len = size;
}

void udproxy_on_send(uv_udp_send_t* req, int status)
{
//	if (enable_verbose && status)
//	{
//		ERROR("on_send() error!\n");
//	}

	//free() memory ponits after send
	int i;
	for (i = 0; i < req->nbufs; i++)
		free(((char**)req->data)[i]);
	free(req->data);

	free(req);
}

int udproxy_udp_send(uv_udp_t* handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr* addr)
{
	uv_udp_send_t* req = malloc(sizeof(uv_udp_send_t));

	//tell on_send(), which memory points need to free()
	req->data = malloc(sizeof(char*) * nbufs);
	int i;
	for(i=0;i<nbufs;i++)
		((char**)req->data)[i] = bufs[i].base;

	return uv_udp_send(req, handle, bufs, nbufs, addr, udproxy_on_send);
}


