/*
 * common.h
 *
 *  Created on: Nov 13, 2016
 *      Author: MiniLight
 */

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <uv.h>
#include "utlist.h"

#ifdef DEBUG
#define LOG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define LOG(x, ...) if (enable_verbose) { printf(x, ##__VA_ARGS__); }
#endif
#define ERROR(x, ...) fprintf(stderr, x, ##__VA_ARGS__)

// magic number
#define UDPROXY_MN		htonl(0x20160603)

typedef struct establishPacket
{
	uint magic_number;
	uint remote_addr;
	u_int16_t remote_port;
	u_char protocol;
	u_char data[];
} EstablishPacket;

void print_help();
void alloc_buffer(uv_handle_t* handle, size_t size, uv_buf_t* buf);
void udproxy_on_send(uv_udp_send_t* req, int status);
int udproxy_udp_send(uv_udp_t* handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr* addr);

#endif /* SRC_COMMON_H_ */
