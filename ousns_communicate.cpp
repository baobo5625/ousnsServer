#include <errno.h>
#include <time.h>
#include <iostream>
#include <algorithm>
#include "ousns_communicate.h"
using namespace std;

oumessage_table::oumessage_table() {
	table.resize(HASHSIZE);
	for (int i = 0; i < HASHSIZE; i++)
		table[i] = list<message_list_entry>(); 
	mutexs.resize(HASHSIZE);
	for (int i = 0; i < HASHSIZE; i++)
		pthread_mutex_init(&mutexs[i], NULL);
}

oumessage_table::~oumessage_table() {
}

void oumessage_table::set_handler_function(void *(*new_message)(struct sockaddr_in*, char*, int)) {
	this->new_message = new_message;
}

void oumessage_table::message_to_content(oumessage& message, char** content, int* length) {
	int len = 0;
	for (int i = 0; i < message.total; i++)
		len += message.oupackets[i].length;
	*content = (char*)malloc(len + 1);
	len = 0;
	for (int i = 0; i < message.total; i++) {
		memcpy((*content) + len, message.oupackets[i].content, message.oupackets[i].length);
		len += message.oupackets[i].length;
	}
	(*content)[len] = 0;
	*length = len;
	printf("[COMM]message content: {%s}\n", *content);	
}

oumessage oumessage_table::content_to_message(struct sockaddr_in* client, uint32_t ouid, uint32_t messageid, char* content, int length) {
	oumessage message;
	message.ip = 0;
	message.port = 0;
	message.ouid = ouid;
	message.messageid = messageid;
	message.status = 0;
	message.count = 0;
	message.total = (length-1) / PACKETSIZE + 1;
	message.oupackets.resize(message.total);
	for (int i = 0; i < message.total; i++) {
		oupacket packet;
		packet.client = *client;
		packet.ouid = ouid;
		packet.messageid = messageid;
		packet.length = min(PACKETSIZE, length - i * PACKETSIZE);
		memcpy(packet.content, content + i * PACKETSIZE, packet.length);
		packet.content[packet.length] = 0;
		packet.id = i;
		packet.total = message.total;
		packet.times = 0;
		message.oupackets[i] = packet;
	}
	return message;
}

uint32_t oumessage_table::hashfn(uint32_t ip, uint16_t port, uint32_t messageid) {
	return (((port << 16) | (ip & 0xFFFF)) ^ messageid) % HASHSIZE;
}

list<message_list_entry>::iterator oumessage_table::find_message(uint32_t index, uint32_t ip, uint16_t port, uint32_t messageid) {
	time_t cur_time = time(NULL);
	for (list<message_list_entry>::iterator it = table[index].begin(); it != table[index].end(); ++it) {
		if (it->first.ip == ip && it->first.port == port && it->first.messageid == messageid) {
			return it;
		}
		if (cur_time - it->second > MSG_TIMELIMIT) {
			it = table[index].erase(it);
		}
	}
	return table[index].end();
}

bool oumessage_table::add_message(oumessage& message) {
	uint32_t index = hashfn(message.ip, message.port, message.messageid);
	pthread_mutex_lock(&(mutexs[index]));
	list<message_list_entry>::iterator it = find_message(index, message.ip, message.port, message.messageid);
	if (it != table[index].end()) {
		pthread_mutex_unlock(&(mutexs[index]));
		return false;
	} else {
		table[index].push_back(make_pair(message, 0));
		pthread_mutex_unlock(&(mutexs[index]));
		return true;
	}
}

oumessage* oumessage_table::get_message(uint32_t messageid) {
	uint32_t index = hashfn(0, 0, messageid);
	pthread_mutex_lock(&(mutexs[index]));
	list<message_list_entry>::iterator it = find_message(index, 0, 0, messageid);
	if (it != table[index].end()) {
		pthread_mutex_unlock(&(mutexs[index]));
		return &(it->first);
	} else {
		pthread_mutex_unlock(&(mutexs[index]));
		return NULL;
	}
}

bool oumessage_table::remove_message(uint32_t messageid) {
	uint32_t index = hashfn(0, 0, messageid);
	pthread_mutex_lock(&(mutexs[index]));
	list<message_list_entry>::iterator it = find_message(index, 0, 0, messageid);
	if (it != table[index].end()) {
		table[index].erase(it);
		pthread_mutex_unlock(&(mutexs[index]));
		return true;
	} else {
		pthread_mutex_unlock(&(mutexs[index]));
		return false;
	}
}

bool oumessage_table::packet_arrived(uint32_t ip, uint16_t port, uint32_t messageid, oupacket& packet) {
	if (packet.total == 1) {
		if (new_message != NULL) {
			(*new_message)(&packet.client, packet.content, packet.length);
		}
		return true;
	}
	uint32_t index = hashfn(ip, port, messageid);
	pthread_mutex_lock(&(mutexs[index]));
	list<message_list_entry>::iterator it = find_message(index, ip, port, messageid);
	if (it != table[index].end()) {
		if (!it->first.flags[packet.id]) {
			it->first.oupackets[packet.id] = packet;
			it->first.flags[packet.id] = 1;
			it->first.count++;
			it->second = time(NULL);
			if (it->first.count == it->first.total) {
				if (new_message != NULL) {
					char* content;
					int length;
					message_to_content(it->first, &content, &length);
					printf("[TEST]%d:%s\n", length, content);
					(*new_message)(&packet.client, content, length);
//					free(content);
				}
				table[index].erase(it);
			}
		}
		pthread_mutex_unlock(&(mutexs[index]));
		return true;
	} else {
		oumessage message;
		message.ip = ip;
		message.port = port;
		message.ouid = packet.ouid;
		message.messageid = packet.messageid;
		message.status = 1;
		message.count = 1;
		message.total = packet.total;
		message.oupackets.resize(packet.total);
		message.oupackets[packet.id] = packet;
		message.flags[packet.id] = 1;
		table[index].push_back(make_pair(message, time(NULL)));
		pthread_mutex_unlock(&(mutexs[index]));
		return true;
	}
}

bool oumessage_table::set_packet_flag(uint32_t messageid, uint16_t id) {
	uint32_t index = hashfn(0, 0, messageid);
	pthread_mutex_lock(&(mutexs[index]));
	list<message_list_entry>::iterator it = find_message(index, 0, 0, messageid);
	if (it != table[index].end() && (!it->first.flags[id])) {
		it->first.flags[id] = 1;
		it->first.count++;
		if (it->first.count == it->first.total)
			table[index].erase(it);
		pthread_mutex_unlock(&(mutexs[index]));
		return true;
	} else {
		pthread_mutex_unlock(&(mutexs[index]));
		return false;
	}
}

bool oumessage_table::check_packet_flag(uint32_t messageid, uint16_t id) {
	uint32_t index = hashfn(0, 0, messageid);
	pthread_mutex_lock(&(mutexs[index]));
	list<message_list_entry>::iterator it = find_message(index, 0, 0, messageid);
	if (it != table[index].end() && (!it->first.flags[id])) {
		pthread_mutex_unlock(&(mutexs[index]));
		return true;
	} else {
		pthread_mutex_unlock(&(mutexs[index]));
		return false;
	}
}

oucommunicate::oucommunicate() {
}

oucommunicate::~oucommunicate() {

}

// thread handlers
void* listen_handler(void *arg) {
	((oucommunicate*)arg)->doListen();
}

void* process_handler(void *arg) {
	((oucommunicate*)arg)->doProcess();
}

void* send_handler(void *arg) {
	((oucommunicate*)arg)->doSend();
}

void* sleep_handler(void *arg) {
	((oucommunicate*)arg)->doSleep();
}

bool oucommunicate::start(int sock, void *(*failure_routine)(char*, int), void *(*new_message)(struct sockaddr_in*, char*, int), int workers) {
	this->sock = sock;
	this->failure_routine = failure_routine;
	this->new_message = new_message;
	messages.set_handler_function(new_message);
	pthread_mutex_init(&send_packets.mutex, NULL);
	pthread_cond_init(&send_packets.cond, NULL);
	pthread_mutex_init(&receive_packets.mutex, NULL);
	pthread_cond_init(&receive_packets.cond, NULL);
	send_timer.time = 0;
	pthread_mutex_init(&send_timer.mutex, NULL);
	pthread_cond_init(&send_timer.cond, NULL);
	if (pthread_create(&listener, NULL, listen_handler, (void*)this))
		return false;
	for (int i = 0; i < workers; i++)
		if (pthread_create(&processor[i], NULL, process_handler, (void*)this))
			return false;
	if (pthread_create(&sender, NULL, send_handler, (void*)this))
		return false;
	if (pthread_create(&timer, NULL, sleep_handler, (void*)this))
		return false;
	return true;
}

void oucommunicate::doListen() {
	struct sockaddr_in client;
	socklen_t structlength = sizeof(client);
	char recvbuf[PACKETSIZE+2];
	uint32_t *ouid, *messageid, *ip;
	uint16_t *id, *total, *port;
	unsigned char *type, *nat;
	while (1) {
		int recvd = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&client, &structlength);
		if (recvd < MINSIZE || recvd > PACKETSIZE) continue;
		oupacket packet;
		type = (unsigned char*)recvbuf;
		nat = (unsigned char*)(recvbuf + 1);
		ouid = (uint32_t*)(recvbuf + 2);
		messageid = (uint32_t*)(recvbuf + 6);
		id = (uint16_t*)(recvbuf + 10);
		total = (uint16_t*)(recvbuf + 12);
		ip = (uint32_t*)(recvbuf + 14);
		port = (uint16_t*)(recvbuf + 18);
		packet.type = *type;
		packet.nat = *nat;
		packet.ouid = *ouid;
		packet.messageid = *messageid;
		packet.id = *id;
		packet.total = *total;
		packet.ip = *ip;
		packet.port = *port;
		packet.length = recvd - MINSIZE;
		memcpy(packet.content, recvbuf + MINSIZE, packet.length);
		packet.content[packet.length] = 0;
		packet.client = client;
		printf("[COMM]raw packet from [client_ip:%s,client_port:%u,length:%u], type:%u,nat:%u,ouid:%u,messageid:%u,id:%u,total:%u,ip:%u,port:%u\n", inet_ntoa(packet.client.sin_addr), ntohs(packet.client.sin_port), packet.length, *type, *nat, *ouid, *messageid, *id, *total, *ip, *port);
		pthread_mutex_lock(&receive_packets.mutex);
		receive_packets.packets.push(packet);
		pthread_mutex_unlock(&receive_packets.mutex);
		pthread_cond_signal(&receive_packets.cond);
	}
}

void oucommunicate::doProcess() {
	char sendbuf[PACKETSIZE+1];
	uint32_t *ouid, *messageid, *ip;
	uint16_t *id, *total, *port;
	unsigned char *type, *nat;
	while (1) {
		pthread_mutex_lock(&receive_packets.mutex);
		while (receive_packets.packets.empty())
			pthread_cond_wait(&receive_packets.cond, &receive_packets.mutex);
		oupacket packet = receive_packets.packets.front();
		receive_packets.packets.pop();
		pthread_mutex_unlock(&receive_packets.mutex);
	
		if (packet.type == 0 && packet.length == 0) {
			// ack packet
			printf("[COMM]received an ack packet from [client_ip:%s,client_port:%u] messageid:%u,id:%u,total:%u\n", inet_ntoa(packet.client.sin_addr), ntohs(packet.client.sin_port), packet.messageid, packet.id, packet.total);
			messages.set_packet_flag(packet.messageid, packet.id);
		} else {
			int len = 0;
			if (packet.type > 0) {
				// forward packet
				struct in_addr fromIP, toIP;
				uint16_t fromPort, toPort;
				fromIP = packet.client.sin_addr;
				fromPort = packet.client.sin_port;
				toIP.s_addr = packet.ip;
				toPort = packet.port;
				printf("[COMM]a packet from [ip:%s,port:%u] to [ip:%s,port:%u]\n", inet_ntoa(fromIP), ntohs(fromPort), inet_ntoa(toIP), ntohs(toPort), packet.messageid, packet.id, packet.total);
				packet.client.sin_addr = toIP;
				packet.client.sin_port = toPort;
				packet.ip = fromIP.s_addr;
				packet.port = fromPort;
				len = packet.length;
				printf("[COMM]forward a packet from [ip:%s,port:%u] to [ip:%s,port:%u], messageid:%u,id:%u,total:%u\n", inet_ntoa(fromIP), ntohs(fromPort), inet_ntoa(toIP), ntohs(toPort), packet.messageid, packet.id, packet.total);
			} else 	{
				// data packet
				printf("[COMM]received a data packet, length:%d: {%s}\n", packet.length, packet.content);
				messages.packet_arrived(packet.client.sin_addr.s_addr, packet.client.sin_port, packet.messageid, packet);
			}
			// forward or acknowledge
			type = (unsigned char*)sendbuf;
			nat = (unsigned char*)(sendbuf + 1);
			ouid = (uint32_t*)(sendbuf + 2);
			messageid = (uint32_t*)(sendbuf + 6);
			id = (uint16_t*)(sendbuf + 10);
			total = (uint16_t*)(sendbuf + 12);
			ip = (uint32_t*)(sendbuf + 14);
			port = (uint16_t*)(sendbuf + 18);
			*type = packet.type;
			*nat = packet.nat;
			*ouid = packet.ouid;
			*messageid = packet.messageid;
			*id = packet.id;
			*total = packet.total;
			*ip = packet.ip;
			*port = packet.port;
			memcpy(sendbuf + MINSIZE, packet.content, len);
			sendbuf[len + MINSIZE] = 0;
			socklen_t structlength = sizeof(packet.client);
			sendto(sock, sendbuf, len + MINSIZE, 0, (struct sockaddr*)&packet.client, structlength);
			printf("[COMM]send packet length: %u\n", len);
		}
	}
}

void oucommunicate::doSleep() {
	while (1) {
		pthread_mutex_lock(&send_timer.mutex);
		int sleeptime;
		if ((sleeptime = send_timer.time - time(NULL)) < 0)
			pthread_cond_wait(&send_timer.cond, &send_timer.mutex);
		sleeptime = send_timer.time - time(NULL);
		if (sleeptime < 0) sleeptime = 0;
		send_timer.time = 0;
		pthread_mutex_unlock(&send_timer.mutex);
		printf("[COMM]go sleep for a while: %d\n", sleeptime);
		sleep(sleeptime);
		pthread_mutex_lock(&send_packets.mutex);
		pthread_mutex_unlock(&send_packets.mutex);
		pthread_cond_signal(&send_packets.cond);
	}
}

void oucommunicate::doSend() {
	char sendbuf[PACKETSIZE+1];
	uint32_t *ouid, *messageid, *ip;
	uint16_t *id, *total, *port;
	unsigned char *type, *nat;
	while (1) {
		printf("[COMM]checking sending queue\n");
		pthread_mutex_lock(&send_packets.mutex);
		while (send_packets.packets.empty() || send_packets.packets.top().second > time(NULL)) {
			if (!send_packets.packets.empty()) {
				pthread_mutex_lock(&send_timer.mutex);
				send_timer.time = send_packets.packets.top().second;
				pthread_mutex_unlock(&send_timer.mutex);
				pthread_cond_signal(&send_timer.cond);
			}
			pthread_cond_wait(&send_packets.cond, &send_packets.mutex);
		}
		printf("[COMM]ready for sending\n");
		oupacket packet = (send_packets.packets.top()).first;
		send_packets.packets.pop();
		pthread_mutex_unlock(&send_packets.mutex);
		// check acknowledge flag
		if (messages.check_packet_flag(packet.messageid, packet.id)) {
			// check timeout times
			if (packet.times >= 3) {
				printf("[COMM]message sending failed due to packet timeout\n");
				printf("[COMM]remove message [client_ip:%s,client_port:%u] ouid:%u,messageid:%u,id:%u,total:%u\n", inet_ntoa(packet.client.sin_addr), ntohs(packet.client.sin_port), packet.ouid, packet.messageid, packet.id, packet.total);
				// failure
				if (failure_routine != NULL) {
					char* content;
					int length;
					messages.message_to_content(*messages.get_message(packet.messageid), &content, &length);
					(*failure_routine)(content, length);
//					free(content);
				}
				messages.remove_message(packet.messageid);
			} else {
				printf("[COMM]sending start\n");
				// send packet
				type = (unsigned char*)sendbuf;
				nat = (unsigned char*)(sendbuf + 1);
				ouid = (uint32_t*)(sendbuf + 2);
				messageid = (uint32_t*)(sendbuf + 6);
				id = (uint16_t*)(sendbuf + 10);
				total = (uint16_t*)(sendbuf + 12);
				ip = (uint32_t*)(sendbuf + 14);
				port = (uint16_t*)(sendbuf + 18);
				*type = 0;
				*nat = 1;
				*ouid = packet.ouid;
				*messageid = packet.messageid;
				*id = packet.id;
				*total = packet.total;
				*ip = 0;
				*port = 0;
				memcpy(sendbuf + MINSIZE, packet.content, packet.length);
				sendbuf[packet.length + MINSIZE] = 0;
				socklen_t structlength = sizeof(packet.client);
				sendto(sock, sendbuf, packet.length + MINSIZE, 0, (struct sockaddr*)&packet.client, structlength);
				printf("[COMM]ouid:%u,messageid:%u,id:%u,total:%u,content:%s\n", *ouid, *messageid, *id, *total, sendbuf + MINSIZE);
				printf("[COMM]sending finish\n");
				// push back for at most 3 times
				packet.times++;
				pthread_mutex_lock(&send_packets.mutex);
				send_packets.packets.push(make_pair(packet, time(NULL) + PACKET_TIMELIMIT));
				pthread_mutex_unlock(&send_packets.mutex);
			}
		}
	}
}

bool oucommunicate::send_message(struct sockaddr_in* client, uint32_t ouid, uint32_t messageid, char* content, int len) {
	oumessage message = messages.content_to_message(client, ouid, messageid, content, len);
	if (messages.add_message(message)) {
		printf("[COMM]add message: %s\n", content);
		for (int i = 0; i < message.total; i++)	{
			printf("[COMM]add packet %d\n", i);
			pthread_mutex_lock(&send_packets.mutex);
			send_packets.packets.push(make_pair(message.oupackets[i], time(NULL)));
			pthread_mutex_unlock(&send_packets.mutex);
			pthread_cond_signal(&send_packets.cond);
		}
		return true;
	} else
		return false;
}
