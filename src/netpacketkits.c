/*
 * netpacketkits.c
 *
 *  Created on: Nov 15, 2016
 *      Author: MiniLight
 */

#include "netpacketkits.h"
#include "common.h"

int enable_addzero = 0;
/*
 * char* data		in	payload data
 * size_t d_size	in	payload data size
 * size_t * result_size	out	udp packet with ip header size
 * uint saddr		in	udp packet saddr
 * uint daddr		in	udp packet daddr
 * u_int16_t sport	in	udp packet sport
 * u_int16_t dport	in	udp packet dport
 *
 * char * return	out	udp packet with ip header
 */
char * build_udpip_packet(char* data, size_t d_size, size_t * result_size, uint saddr, uint daddr, u_int16_t sport, u_int16_t dport)
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

/*
 * char* data		in	payload data
 * size_t d_size	in	payload data size
 * size_t * result_size	out	tcp packet with ip header size
 * uint saddr		in	tcp packet saddr
 * uint daddr		in	tcp packet daddr
 * u_int16_t sport	in	tcp packet sport
 * u_int16_t dport	in	tcp packet dport
 *
 * char * return	out	tcp packet with ip header
 */
char * build_tcpip_packet(char* data, size_t d_size, size_t * result_size, uint saddr, uint daddr, u_int16_t sport, u_int16_t dport)
{
	struct pseudo_tcphdr {
		u_int32_t source;
		u_int32_t dest;
		u_int8_t zero;//always zero
		u_int8_t protocol;// = 6;//for tcp
		u_int16_t tcp_length;
	};

	//8 = src(2) + dst(2) + Checksum(2) + UrgentPointer(2)
	*result_size = d_size + sizeof(struct iphdr) + 8;

	//set all header pointer
	char * result = malloc(*result_size);
	struct iphdr *ip4h = (struct iphdr *) result;
	struct tcphdr *tcph = (struct tcphdr *) (((char*) ip4h) + sizeof(struct iphdr));
	struct pseudo_tcphdr *ptcph = (struct pseudo_tcphdr *) (((char*) tcph) - sizeof(struct pseudo_tcphdr));

	//copy data
	//reserved 8 bytes for src(2)/dst(2)/seq(4)
	memcpy(((char*)tcph)+8, data, d_size);
	//*4 = SequenceNumber(4), *16 = Checksum(2) + UrgentPointer(2)
	memcpy(((u_char*) tcph) + 4, ((u_char*) tcph) + 16, 4);
	bzero(((u_char*) tcph) + 16, 4);

	//set tcp header
	tcph->dest = dport;
	tcph->source = sport;

	//set tcp pseudo header
	ptcph->dest = daddr;
	ptcph->source = saddr;
	ptcph->zero = 0;
	ptcph->protocol = IPPROTO_TCP;    //IPPROTO_RAW;    /* protocol at L4 */
	ptcph->tcp_length = d_size + 8;

	//checksum
	tcph->check = 0;
	u_int16_t *addr = (u_int16_t *) ptcph;
	int len = sizeof(struct pseudo_tcphdr) + ntohs(ptcph->tcp_length);
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
	tcph->check = ~sum;

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


