#define ETH_LEN	1518
#define ETHER_TYPE	0x0800
#define DEFAULT_IF	"eth0"

struct eth_hdr_s {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct ip_hdr_s {
	uint8_t ver;			/* version, header length */
	uint8_t tos;			/* type of service */
	int16_t len;			/* total length */
	uint16_t id;			/* identification */
	int16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

struct udp_hdr_s {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t udp_len;
	uint16_t udp_chksum;
};

struct heart_hdr{
	char name[20]; // hostname of sender
	uint8_t func_id; // 0 = START; 1 = HEARTBEAT; 2 = TALK
	uint8_t ip_address[4];
	char msg[100];
};

struct eth_frame_s {
	struct eth_hdr_s ethernet;
	struct ip_hdr_s ip;
	struct udp_hdr_s udp;
	struct heart_hdr heartbeat;
};
