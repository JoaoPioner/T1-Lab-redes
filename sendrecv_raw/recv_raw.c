#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"

#define PROTO_heartbit	0xFD
#define PROTO_UDP	17
#define DST_PORT	8000

char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0xaa, 0x00, 0x01};
char src_mac[6] =	{0x00, 0x00, 0x00, 0xaa, 0x00, 0x00};

int control(int argc, char *argv[])
{
	struct ifreq ifopts;
	char ifName[IFNAMSIZ];
	int sockfd, numbytes;
	char *p;
	
	uint8_t raw_buffer[ETH_LEN];
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* End of configuration. Now we can receive data using raw sockets. */

	while (1){
		numbytes = recvfrom(sockfd, raw_buffer, ETH_LEN, 0, NULL, NULL);
		if (raw->ethernet.eth_type == ntohs(ETH_P_IP)){
			if (raw->ip.proto == PROTO_LABREDES){
				if(HEART_BEAT || START) {
					
				}


				p = (char *)&raw->udp + ntohs(raw->udp.udp_len);
				*p = '\0';
				printf("src port: %d dst port: %d size: %d msg: %s", 
				ntohs(raw->udp.src_port), ntohs(raw->udp.dst_port),
				ntohs(raw->udp.udp_len), (char *)&raw->udp + sizeof(struct udp_hdr_s)
				); 
			}
			continue;
		}
				
		// printf("got a packet, %d bytes\n", numbytes);
	}

	return 0;
}

int list_table() {
	for(int i = 0; i< total_dispositivos; i++) {
		print("Dispositivo: ...");

	}
}

int send_talk(int id, char *msg) {
	struct dispositivo device = table_device[id];
	device.mac
	device.id
	device.hostname

	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes, size = 100;
	
	uint8_t raw_buffer[ETH_LEN];
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* End of configuration. Now we can send data using raw sockets. */


	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */

	/* fill the Ethernet frame header */
	memcpy(raw->ethernet.dst_addr, bcast_mac, 6);
	memcpy(raw->ethernet.src_addr, src_mac, 6);
	raw->ethernet.eth_type = htons(ETH_P_IP);

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */
	raw->ip.ver = 0x45;
	raw->ip.tos = 0x00;
	raw->ip.len = htons(size + sizeof(struct ip_hdr_s));
	raw->ip.id = htons(0x00);
	raw->ip.off = htons(0x00);
	raw->ip.ttl = 50;
	raw->ip.proto = 0xFD;
	raw->ip.sum = htons(0x0000);
	uint8_t destination[4] =  {10,32,143,255};
	memcpy(raw->ip.dst, destination,4);
	//raw->ethernet.eth_type = 25;

	/* fill source and destination addresses */

	/* calculate the IP checksum */
	/* raw->ip.sum = htons((~ipchksum((uint8_t *)&raw->ip) & 0xffff)); */

	/* fill payload data */


	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct ip_hdr_s) + size, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");

}

int main(int argc, char *argv[])
{

	pthread_create(control, NULL, NULL, NULL);

	while(true) {
		printf("Infome uma opcao")
		scanf("%s");

		// list_table()
		// send_talk();
	}
}