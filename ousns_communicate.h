#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <memory.h>
#include <queue>
#include <list>
#include <bitset>

#define HASHSIZE 10003
#define MINSIZE 20
#define PACKETSIZE 500
#define MSG_TIMELIMIT 8
#define PACKET_TIMELIMIT 2
#define MAXWORKER 10

// Part 1: Packet Data Structures

typedef struct {
	struct sockaddr_in client;
	uint32_t ouid, messageid, ip, length;
	uint16_t id, total, port, times;
	unsigned char type, nat;
	char content[PACKETSIZE+1];
} oupacket;

typedef std::pair<oupacket, uint32_t> packet_queue_entry;

class packet_comparison {
public:
	bool operator() (const packet_queue_entry& lhs, const packet_queue_entry& rhs) const {
		return (lhs.second > rhs.second);
	}
};

typedef struct {
	time_t time;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} sleep_timer;

typedef struct {
	std::priority_queue<packet_queue_entry, std::vector<packet_queue_entry>, packet_comparison> packets;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} send_queue;

typedef struct {
	std::queue<oupacket> packets;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} receive_queue;

// Part 2: Message Data Structures

typedef struct {
	std::bitset<256> flags;
	uint32_t ouid, messageid, ip;
	uint16_t status, count, total, port;
	std::vector<oupacket> oupackets;
} oumessage;


typedef std::pair<oumessage, uint32_t> message_list_entry;

class oumessage_table {
	std::vector<std::list<message_list_entry> > table;
	std::vector<pthread_mutex_t> mutexs;
	void *(*new_message)(struct sockaddr_in*, char*, int);
	uint32_t hashfn(uint32_t ip, uint16_t port, uint32_t messageid);
	std::list<message_list_entry>::iterator find_message(uint32_t index, uint32_t ip, uint16_t port, uint32_t messageid);
public:
	oumessage_table();
	~oumessage_table();
	void set_handler_function(void *(*new_message)(struct sockaddr_in*, char*, int));
	void message_to_content(oumessage& message, char** content, int* length);
	// sending messages;
	oumessage content_to_message(struct sockaddr_in* client, uint32_t ouid, uint32_t messageid, char* content, int length);
	bool add_message(oumessage& message);
	oumessage* get_message(uint32_t messageid);
	bool remove_message(uint32_t messageid);
	bool set_packet_flag(uint32_t messageid, uint16_t id);
	bool check_packet_flag(uint32_t messageid, uint16_t id);
	// received messages
	bool packet_arrived(uint32_t ip, uint16_t port, uint32_t messageid, oupacket& packet);
};

// Part 3: Communicate Class


class oucommunicate {
	pthread_t listener;
	pthread_t processor[MAXWORKER];
	pthread_t sender;
	pthread_t timer;

	oumessage_table messages;
	send_queue send_packets;
	receive_queue receive_packets;
	sleep_timer send_timer;
	
	void *(*failure_routine)(char*, int);
	void *(*new_message)(struct sockaddr_in*, char*, int);

	int sock;
public:
	oucommunicate();
	~oucommunicate();

	void doListen();
	void doProcess();
	void doSend();
	void doSleep();

	bool start(int sock, void *(*failure_routine)(char*, int), void *(*new_message)(struct sockaddr_in*, char*, int), int workers);
	bool send_message(struct sockaddr_in* client, uint32_t ouid, uint32_t messageid, char* content, int length);
};
