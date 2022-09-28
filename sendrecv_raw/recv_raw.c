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
#include <stdint.h> // lib to int with sizes (uint8_t)
#include <pthread.h> // lib for threads
#include <unistd.h> // lib for sleep
#include "raw.h"
 
#define PROTO_LABREDES  0xFD
#define PROTO_UDP   17
#define DST_PORT    8000
 
typedef struct{
   char *name;
   uint8_t ip_address[4];
}tableItem;
 
enum packeges = {STAR=0, HEART=1, TALK=2};
 
char bcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =   {0x00, 0x00, 0x00, 0xaa, 0x00, 0x01};
char src_mac[6] =   {0x00, 0x00, 0x00, 0xaa, 0x00, 0x00};
 
tableItem table[100];
int size;
 
/*
* TABLE OPERATIONS
*/
void show_table(tableItem t[100], int size){
   printf("ID\t|HOSTNAME\t|ADDRESS\n");
   printf("-------------------------------------------\n");
   for(int i = 0; i < size; i++){
       printf("%d\t|", i);
       printf("%s\t\t|", t[i].name);
       printf("%d.%d.%d.%d\n", t[i].ip_address[0], t[i].ip_address[1], t[i].ip_address[2], t[i].ip_address[3]);  
       printf("--------------------------------------------\n");
   }
}
 
void add_in_table(tableItem table[100], int *size, char *name, uint8_t ip_address[4]){
   if(*size >= 100) return;
  
   table[*size].name = name;
   // printf("->size: %d\n", *size);
   memcpy(table[*size].ip_address, ip_address, sizeof(ip_address));
   *size += 1;
}
 
/*
* shift values back to "reduce" queue size
* *size = &int
*/
void remove_of_table_by_pos(tableItem table[100], int *size, int pos){
   if(pos > *size) return;
  
   if(pos < 99){
       for(int i = pos; i < *size; i++){
           table[i] = table[i+1];
       }
   }
  
   *size -= 1;
}
//------------------------------------------------------------------------
 
// var for readPackets
struct ifreq ifopts;
char ifName[IFNAMSIZ];
int sockfd, numbytes;
char *p;
 
uint8_t raw_buffer[ETH_LEN];
struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;
 
int readPackets()
{
 
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
               // if(HEART_BEAT || START) {
                  
               // }
 
 
               p = (char *)&raw->udp + ntohs(raw->udp.udp_len);
               *p = '\0';
               printf("src port: %d dst port: %d size: %d msg: %s\n",
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
 
int main(int argc, char *argv[]){
 
   // set interface name before thread initialization
   /* Get interface name */
   if (argc > 1)//(argc > 1)
       strcpy(ifName, argv[1]);//argv[1]);
   else
       strcpy(ifName, DEFAULT_IF);
 
   pthread_t tid;
 
   pthread_create(&tid, NULL, readPackets, (void *)&tid);
 
   int input;
 
   while(1){
       printf("1. List connection table\n");
       printf("2. Send Talk\n");
       printf("Number: ");
       scanf("%d", &input);

       switch(input) {
        case 1:
            show_table(table, &size);
        break;
        case 2:
            int dest_id;
            printf("Destination id: ");
            scanf("%d", &dest_id);
           char *msg;
            printf("Message: ");
            gets(msg);
            send_package(2,*msg);
        break;
       }
       //HEARTBEAT
       send_package(1,"");
   }
   return 0;
}
 
int send_package(int packege_type, char *msg)
{
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
   uint8_t destination[4] =  {172,20,255,255};//{10,130,255,255};
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
 
 
   return 0;
}
 
// int main(int argc, char *argv[])
// {
 
//  pthread_create(control, NULL, NULL, NULL);
 
//  while(true) {
//      printf("Infome uma opcao");
//      scanf("%s");
 
//      // list_table()
//      // send_talk();
//  }
// }
