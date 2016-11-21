/*
 * netpacketkits.h
 *
 *  Created on: Nov 15, 2016
 *      Author: MiniLight
 */

#ifndef SRC_NETPACKETKITS_H_
#define SRC_NETPACKETKITS_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

//Prepare for different architectures checksum
extern int enable_addzero;

typedef union sockhdr {
	struct {
		ushort s;
		ushort d;
	} port;
	struct udphdr udp;
	struct tcphdr tcp;
	char data[0];
} Socket;

char * build_udpip_packet(char* data, size_t d_size, size_t * result_size, uint saddr, uint daddr, u_int16_t sport, u_int16_t dport);
char * build_tcpip_packet(char* data, size_t d_size, size_t * result_size, uint saddr, uint daddr, u_int16_t sport, u_int16_t dport);

#endif /* SRC_NETPACKETKITS_H_ */
