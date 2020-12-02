#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"

#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#pragma pack(push, 1)
struct ethhdr
{
	uint8_t dst_host[6];
	uint8_t src_host[6];
	uint16_t type;
};

struct iphdr
{
	uint8_t info;
	uint8_t tos;
	uint16_t len;
	uint16_t frag_id;
	uint16_t frag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
};

struct tcphdr
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t len;
	uint8_t flag;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_pointer;
};

struct eth_ip_tcp_hdr
{
	struct ethhdr eth_;
	struct iphdr ip_;
	struct tcphdr tcp_;
};

struct eth_ip_tcp_hdr_data
{
	struct ethhdr eth_;
	struct iphdr ip_;
	struct tcphdr tcp_;
	char data[10];
};
#pragma pack(pop)
uint16_t getchecksum(u_char *, int);
uint16_t gettcpsum(struct eth_ip_tcp_hdr *);
uint16_t gettcpsum_data(struct eth_ip_tcp_hdr_data *);
void forward_sendpkt(pcap_t *, Mac, struct eth_ip_tcp_hdr *);
void backward_sendpkt(pcap_t *, Mac, struct eth_ip_tcp_hdr *);
int pattern_find(uint8_t *, int);
void tcp_block(pcap_t *, char *);
char pattern[100];
void usage()
{
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}
int GetInterfaceMacAddress(char *ifname, char *MAC_Address)
{
	uint8_t *mac = (uint8_t *)malloc(sizeof(uint8_t) * 30);
	struct ifreq ifr;
	int sockfd, ret;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("Fail to get interface MAC address - socket() failed\n");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (ret < 0)
	{
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed \n");
		close(sockfd);
		return -1;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	close(sockfd);
	sprintf(MAC_Address, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	free(mac);
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		usage();
		return -1;
	}
	char *dev = argv[1];
	memcpy(pattern, argv[2], strlen(argv[2]));
	printf("block pattern : %s\n", pattern);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char *my_mac_addr = (char *)malloc(sizeof(uint8_t) * 20);
	GetInterfaceMacAddress(argv[1], my_mac_addr);

	tcp_block(handle, my_mac_addr);
}

void tcp_block(pcap_t *handle, char *mac_addr)
{
	while (1)
	{
		struct pcap_pkthdr *header;
		uint8_t *rcv_packet;

		int res = pcap_next_ex(handle, &header, (const u_char **)&rcv_packet);
		if (res == 0)
			continue;
		if (res == -1 || res == -2)
		{
			fprintf(stderr, "pcap_next_ex return error! %d(%s).\n", res, pcap_geterr(handle));
			break;
		}
		struct eth_ip_tcp_hdr *packet = (struct eth_ip_tcp_hdr *)rcv_packet;
		if (ntohs(packet->eth_.type) != 0x0800 || packet->ip_.protocol != 6)
			continue; //check ipv4 & tcp
		int ippkt_len = ntohs(packet->ip_.len);
		int iphdr_len = ((packet->ip_.info) & 0x0F) * 4;
		int tcphdr_len = (((packet->tcp_.len) & 0xF0) >> 4) * 4;
		int pkt_datalen = ippkt_len - sizeof(struct iphdr) - sizeof(struct tcphdr);
		uint8_t *pkt_data = rcv_packet + sizeof(struct eth_ip_tcp_hdr); // TCP data in received pkt.
		if (!pattern_find(pkt_data, pkt_datalen))
		{
			continue;
		}
		printf("I got~\n");
		forward_sendpkt(handle, Mac(mac_addr), packet);
		backward_sendpkt(handle, Mac(mac_addr), packet);
	}
}

void forward_sendpkt(pcap_t *handle, Mac mac_addr, struct eth_ip_tcp_hdr *packet)
{
	int datalen = ntohs(packet->ip_.len) - sizeof(struct iphdr) - sizeof(struct tcphdr);

	eth_ip_tcp_hdr *sendpkt = (eth_ip_tcp_hdr *)calloc(0, sizeof(struct eth_ip_tcp_hdr));

	memcpy(sendpkt, packet, sizeof(struct ethhdr));

	memcpy(&(sendpkt->eth_.src_host), mac_addr, sizeof(Mac));
	memcpy(&(sendpkt->ip_), &(packet->ip_), sizeof(struct iphdr));
	sendpkt->ip_.len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	sendpkt->ip_.checksum = 0;
	sendpkt->ip_.checksum = getchecksum(((u_char *)&(sendpkt->ip_)), sizeof(struct iphdr));
	//sendpkt->ip_.checksum = packet->ip_.checksum;
	sendpkt->tcp_.src_port = packet->tcp_.src_port;
	sendpkt->tcp_.dst_port = packet->tcp_.dst_port;
	sendpkt->tcp_.seq = htonl(ntohl(packet->tcp_.seq) + datalen);
	sendpkt->tcp_.ack = packet->tcp_.ack;
	sendpkt->tcp_.len = packet->tcp_.len;
	sendpkt->tcp_.flag = 0x04; //  rst
	sendpkt->tcp_.window_size = packet->tcp_.window_size;

	sendpkt->tcp_.checksum = 0;
	sendpkt->tcp_.checksum = gettcpsum(sendpkt);
	int res = pcap_sendpacket(handle, (u_char *)sendpkt, sizeof(struct eth_ip_tcp_hdr));
	if (res != 0)
		printf("ERROR!! failed send forward packet");
	else
	{
		printf("success!! send forward packet!\n");
	}
}

void backward_sendpkt(pcap_t *handle, Mac mac_addr, struct eth_ip_tcp_hdr *packet)
{
	int datalen = ntohs(packet->ip_.len) - sizeof(struct iphdr) - sizeof(struct tcphdr);

	eth_ip_tcp_hdr_data *sendpkt = (eth_ip_tcp_hdr_data *)calloc(0, sizeof(struct eth_ip_tcp_hdr_data));

	memcpy(sendpkt, packet, sizeof(struct ethhdr));

	memcpy(sendpkt->eth_.src_host, mac_addr, 6);
	memcpy(sendpkt->eth_.dst_host, packet->eth_.src_host, 6);

	sendpkt->ip_.info = packet->ip_.info;
	sendpkt->ip_.len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 10);
	sendpkt->ip_.ttl = 128;
	sendpkt->ip_.protocol = packet->ip_.protocol;
	sendpkt->ip_.src_ip = packet->ip_.dst_ip;
	sendpkt->ip_.dst_ip = packet->ip_.src_ip;

	sendpkt->ip_.checksum = 0;
	sendpkt->ip_.checksum = getchecksum(((u_char *)&(sendpkt->ip_)), sizeof(struct iphdr));

	sendpkt->tcp_.src_port = packet->tcp_.dst_port;
	sendpkt->tcp_.dst_port = packet->tcp_.src_port;
	sendpkt->tcp_.seq = packet->tcp_.ack;
	sendpkt->tcp_.ack = htonl(ntohl(packet->tcp_.seq) + datalen);
	sendpkt->tcp_.len = packet->tcp_.len;
	sendpkt->tcp_.flag = 0x11;
	sendpkt->tcp_.checksum = 0;
	sendpkt->tcp_.window_size = packet->tcp_.window_size;

	memcpy(sendpkt->data, "blocked!!!", 10);
	sendpkt->tcp_.checksum = gettcpsum_data(sendpkt);
	int res = pcap_sendpacket(handle, (u_char *)sendpkt, sizeof(struct eth_ip_tcp_hdr_data));
	if (res != 0)
		printf("ERROR!! failed send backward pakcet");
	else
	{
		printf("success!! send backward packet!\n");
	}
}

uint16_t getchecksum(u_char *data, int len)
{
	int tmp = 0;
	for (int i = 0; i < len; i += 2)
	{
		tmp += ntohs(*(uint16_t *)(data + i));
	}
	uint16_t res = tmp & 0xFFFF;
	res += (tmp >> 16);
	return htons(~res);
}
uint16_t gettcpsum(struct eth_ip_tcp_hdr *packet)
{

	int dataLen = 12 + sizeof(struct tcphdr);

	u_char *data = (u_char *)malloc(dataLen);
	memset(data, 0, dataLen);
	memcpy(data, ((u_char *)&(packet->ip_.src_ip)), 8);
	*((u_int8_t *)(data + 9)) = 6; // IPPROTO_TCP
	*((u_int16_t *)(data + 10)) = htons(dataLen - 12);
	memcpy(data + 12, (u_char *)(&(packet->tcp_)), sizeof(struct tcphdr));

	u_int16_t sum = getchecksum(data, dataLen);

	free(data);
	return sum;
}
uint16_t gettcpsum_data(struct eth_ip_tcp_hdr_data *packet)
{
	int dataLen = 12 + sizeof(struct tcphdr) + 10;

	u_char *data = (u_char *)malloc(dataLen);
	memset(data, 0, dataLen);
	memcpy(data, ((u_char *)&(packet->ip_.src_ip)), 8);
	*((u_int8_t *)(data + 9)) = 6; // IPPROTO_TCP
	*((u_int16_t *)(data + 10)) = htons(dataLen - 12);

	memcpy(data + 12, (u_char *)(&(packet->tcp_)), sizeof(struct tcphdr));
	memcpy(data + 12 + sizeof(struct tcphdr), (u_char *)packet->data, 10);

	u_int16_t sum = getchecksum(data, dataLen);
	free(data);
	return sum;
}
int pattern_find(uint8_t *data, int size)
{
	if (size < strlen(pattern))
		return 0;
	for (int i = 0; i < size - strlen(pattern); i++)
	{
		if (!memcmp(data + i, "Host: ", 6))
		{
			if (!memcmp(data + i, pattern, strlen(pattern)))
			{

				return 1;
			}

			else
			{
				return 0;
			}
		}
	}
	return 0;
}