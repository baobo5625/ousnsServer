#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <errno.h>

int main(int argc, char *argv[]) {
	int sock;
	struct sockaddr_in server, client;
	int snd, sendlen;
	socklen_t structlength;
	int port = 50000;
	char sendbuf[2000];    

	memset((char *)&server,0,sizeof(server));
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = htonl(INADDR_ANY);
	client.sin_port = htons(49999);
	
	memset((char *)&server,0,sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(port);

	if ((sock = socket(AF_INET,SOCK_DGRAM,0)) < 0) {
		printf("socket create error!\n");
		return 1;
	}
	
	structlength = sizeof(server);
	if (bind(sock, (struct sockaddr *)&client, structlength) < 0) {
		printf("socket bind error!\n");
		return 1;
	}

	uint32_t *ouid, *messageid, *ci;
	uint16_t *id, *total, *cp;
	unsigned char *type, *nat;
	type = (unsigned char*)sendbuf;
	nat = (unsigned char*)(sendbuf + 1);
	ouid = (uint32_t*)(sendbuf + 2);
	messageid = (uint32_t*)(sendbuf + 6);
	id = (uint16_t*)(sendbuf + 10);
	total = (uint16_t*)(sendbuf + 12);
	ci = (uint32_t*)(sendbuf + 14);
	cp = (uint16_t*)(sendbuf + 18);
	*type = 0;
	*nat = 0;
	*ouid = 100000;
	*messageid = 321;
	*id = 0;
	*total = 3;
	*ci = 0;
	*cp = 0;
	sprintf(sendbuf + 20, "<REQUEST actionType=\"LOGIN\" messageID=\"321\" communicationVersion=\"61\"><userID userIDType=\"OuID\">100000</userID>");
	sendlen = strlen(sendbuf + 20) + 20;
	snd = sendto(sock, sendbuf, sendlen, 0, (struct sockaddr *) &server, structlength);
	puts(sendbuf + 20);
	*id = 1;
	sprintf(sendbuf + 20, "<password>baobo</password><userStatus>0</userStatus><natType>0</natType><macAddressList></macAddressList>");
	sendlen = strlen(sendbuf + 20) + 20;
	snd = sendto(sock, sendbuf, sendlen, 0, (struct sockaddr *) &server, structlength);
	puts(sendbuf + 20);
	*id = 2;
	sprintf(sendbuf + 20, "</REQUEST>");
	sendlen = strlen(sendbuf + 20) + 20;
	snd = sendto(sock, sendbuf, sendlen, 0, (struct sockaddr *) &server, structlength);
	puts(sendbuf + 20);

	sleep(1);
	*type = 0;
	*nat = 0;
	*ouid = 10000;
	*messageid = 0;
	*id = 0;
	*total = 2;
	*ci = 0;
	*cp = 0;
	snd = sendto(sock, sendbuf, 20, 0, (struct sockaddr *) &server, structlength);
	*id = 1;
	snd = sendto(sock, sendbuf, 20, 0, (struct sockaddr *) &server, structlength);

	close(sock);
	return 0;
}
