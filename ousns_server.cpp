#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <mysql.h>
#include <string.h>
#include <stack>
#include <vector>
#include <list>
#include "ousns_communicate.h"
#include "md5.h"
using namespace std;

#define TABLESIZE 1000003
#define ACTIVE_TIMELIMIT 100000
#define SERVERID 10000

typedef struct {
	uint32_t ouid;
	int status;
	struct sockaddr_in client;
	char sessionID[33];
} online_user;

typedef pair<online_user, uint32_t> user_list_entry;

vector<list<user_list_entry> > usertable;
vector<pthread_mutex_t> mutexs;

MYSQL mysqls[MAXWORKER];
stack<MYSQL*> connections;
pthread_mutex_t mutex; 
oucommunicate oucomm;
uint32_t messageid = 0;

bool connectdb(MYSQL* mysql) {
	if (mysql_init(mysql) != NULL) {
		if (mysql_real_connect(mysql, "10.54.118.99", "ousns", "ousns", "ousns", 0, NULL, 0) != NULL)
			return true;
		else
			return false;
	}
	return false;
}

uint32_t hashfn(uint32_t ouid) {
	return ouid%TABLESIZE;
}

list<user_list_entry>::iterator find_user(MYSQL* mysql, uint32_t index, uint32_t ouid) {
	time_t cur_time = time(NULL);
	for (list<user_list_entry>::iterator it = usertable[index].begin(); it != usertable[index].end(); ++it) {
		if (it->first.ouid == ouid)
			return it;
		if (cur_time - it->second > ACTIVE_TIMELIMIT) {
			// set offline
			char stmt[500];
			sprintf(stmt, "update tblusers set status = 0 where ouid = %u", ouid);
			mysql_query(mysql, stmt);
			it = usertable[index].erase(it);
		}
	}
	return usertable[index].end();
}

online_user get_user(uint32_t ouid) {
	uint32_t index = hashfn(ouid);
	pthread_mutex_lock(&(mutexs[index]));
	list<user_list_entry>::iterator it = find_user(mysql, index, ouid);
	online_user user;
	user.status = 0;
	if (it != usertable[index].end()) {
		user = it->first;
	}
	pthread_mutex_unlock(&(mutexs[index]));
	return user;
}

xmlDocPtr newDoc(char* category, char* actionType) {
	xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
	xmlNodePtr root = xmlNewNode(NULL, (const xmlChar*)category);
	xmlSetProp(root, BAD_CAST "actionType", (const xmlChar*)actionType);
	xmlDocSetRootElement(doc, root);
	return doc;
}

const char* generateSessionID(char* userID, char* ip) {
	string ret;
	ret.append(userID);
	ret.append("|");
	ret.append(ip);
	ret.append("|");
	time_t rawtime;
	time(&rawtime);
	ret.append(ctime(&rawtime));
	return md5(ret).c_str();
}

bool checkSessionID(MYSQL* mysql, uint32_t ouid, char* sessionID) {
	uint32_t index = hashfn(ouid);
	pthread_mutex_lock(&(mutexs[index]));
	list<user_list_entry>::iterator it = find_user(mysql, index, ouid);
	if (it != usertable[index].end() && strcmp(it->first.sessionID, sessionID) == 0) {
		pthread_mutex_unlock(&(mutexs[index]));
		return true;
	} else {
		pthread_mutex_unlock(&(mutexs[index]));
		return false;
	}
}

void setUser(MYSQL* mysql, struct sockaddr_in* client, uint32_t ouid, int status, char* sessionID) {
	uint32_t index = hashfn(ouid);
	pthread_mutex_lock(&(mutexs[index]));
	list<user_list_entry>::iterator it = find_user(mysql, index, ouid);
	if (it != usertable[index].end()) {
		if (client != NULL)
			it->first.client = *client;
		it->first.status = status;
		strcpy(it->first.sessionID, sessionID);
		pthread_mutex_unlock(&(mutexs[index]));
	} else {
		online_user user;
		if (client != NULL)
			user.client = *client;
		user.ouid = ouid;
		user.status = status;
		strcpy(user.sessionID, sessionID);
		usertable[index].push_back(make_pair(user, time(NULL)));
		pthread_mutex_unlock(&(mutexs[index]));
	}
}

void removeUser(MYSQL* mysql, uint32_t ouid, char* sessionID) {
	uint32_t index = hashfn(ouid);
	pthread_mutex_lock(&(mutexs[index]));
	list<user_list_entry>::iterator it = find_user(mysql, index, ouid);
	if (it != usertable[index].end()) {
		usertable[index].erase(it);
	}
	pthread_mutex_unlock(&(mutexs[index]));
}

void activeUser(MYSQL* mysql, uint32_t ouid, char* sessionID) {
	uint32_t index = hashfn(ouid);
	pthread_mutex_lock(&(mutexs[index]));
	list<user_list_entry>::iterator it = find_user(mysql, index, ouid);
	if (it != usertable[index].end()) {
		it->second = time(NULL);
	}
	pthread_mutex_unlock(&(mutexs[index]));
}

xmlDocPtr verifyLogin(MYSQL* mysql, struct sockaddr_in* client, char* messageID, char* userID, char* password, char* status, char* natType, int flag) {
	xmlDocPtr ret = newDoc("RESPONSE", "LOGIN");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MYSQL_FIELD *mysql_fields;
	unsigned int num_fields;
	char stmt[500];
	if (flag == 0)
		sprintf(stmt, "select OuID, emailID, email, nickname, signature, profile, focusCounter, birthYear, birthMonth, birthDay, sex, zodiac, displayPictureFilename, experience, personalStatement, city, province, country from tblusers where OuID = %s and password = '%s'", userID, password);
	else
		sprintf(stmt, "select OuID, emailID, email, nickname, signature, profile, focusCounter, birthYear, birthMonth, birthDay, sex, zodiac, displayPictureFilename, experience, personalStatement, city, province, country from tblusers where emailID = '%s' and password = '%s'", userID, password);
	printf("[DEBUG]mysql query: %s\n", stmt);
	mysql_query(mysql, stmt);
	mysql_result = mysql_store_result(mysql);
	if (mysql_result) {
		mysql_row = mysql_fetch_row(mysql_result);
		num_fields = mysql_num_fields(mysql_result);
		mysql_fields = mysql_fetch_fields(mysql_result);
		if (mysql_row) {
			printf("[DEBUG]login successful\n");
			// response
			xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "0");
			xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
			mysql_free_result(mysql_result);
			for (int i = 0; i < num_fields; i++) {
				xmlNewChild(root, NULL, (const xmlChar*)mysql_fields[i].name, (const xmlChar*)mysql_row[i]);
			}
			char ip[50], port[50], sessionID[50], loginTimeStamp[50];
			uint32_t ouid = strtoul((char*)mysql_row[0], NULL, 0);
			strcpy(ip, inet_ntoa(client->sin_addr));
			xmlNewChild(root, NULL, BAD_CAST "ip", (const xmlChar*)ip);
			sprintf(port, "%u", ntohs(client->sin_port));
			xmlNewChild(root, NULL, BAD_CAST "port", (const xmlChar*)port);
			strcpy(sessionID, generateSessionID(userID, ip));
			xmlSetProp(root, BAD_CAST "sessionID", (const xmlChar*)sessionID);
			sprintf(loginTimeStamp, "%d", time(NULL));
			xmlNewChild(root, NULL, BAD_CAST "loginTimeStamp", (const xmlChar*)loginTimeStamp);
			mysql_free_result(mysql_result);

			// update status
			sprintf(stmt, "update tblusers set ip = '%s', port = %s, natType = %s, status = %s, loginTimeStamp = %s where ouid = %u", ip, port, natType, status, loginTimeStamp, ouid);
			printf("%s\n", stmt);
			mysql_query(mysql, stmt);
			setUser(mysql, client, ouid, atoi(status), sessionID);
			return ret;
		}
		mysql_free_result(mysql_result);
	}
	
	// login failed
	printf("[DEBUG]login failed\n");
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	return ret;
}

xmlDocPtr doLogin(MYSQL* mysql, struct sockaddr_in* client, char* messageID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr password;
	xmlNodePtr userStatus;
	xmlNodePtr natType;
	xmlNodePtr communicationVersion;
	xmlNodePtr macAddressList;
	xmlDocPtr ret = NULL;

	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	password  = userID->next;
	if (password->next == NULL) return NULL;
	userStatus = password->next;
	if (userStatus->next == NULL) return NULL;
	natType = userStatus->next;
	if (natType->next == NULL) return NULL;
	macAddressList = natType->next;
	char* userIDType = (char*)xmlGetProp(userID, BAD_CAST "userIDType");
	if (userIDType == NULL) return NULL;
	if (userID->children == NULL || password->children == NULL || userStatus->children == NULL || natType->children == NULL) return NULL;
	
	if (strcmp(userIDType, "OuID") == 0) {
		printf("[DEBUG]login with OuID\n");
		ret = verifyLogin(mysql, client, messageID, (char*)userID->children->content, (char*)password->children->content, (char*)userStatus->children->content, (char*)natType->children->content, 0);
	} else if (strcmp(userIDType, "Email") == 0) {
		printf("[DEBUG]login with Email\n");
		ret = verifyLogin(mysql, client, messageID, (char*)userID->children->content, (char*)password->children->content, (char*)userStatus->children->content, (char*)natType->children->content, 1);
	} else {
		printf("[DEBUG]unknown userIDType\n");
	}
	return ret;
}

xmlDocPtr doLogoff(MYSQL* mysql, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;	
	xmlDocPtr ret = NULL;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		printf("[DEBUG]logoff successful\n");
		char stmt[500];
		sprintf(stmt, "update tblusers set status = 0 where ouid = %u", ouid);
		mysql_query(mysql, stmt);
		removeUser(mysql, ouid, sessionID);
	} else {
		printf("[DEBUG]logoff failed\n");
	}

	return ret;
}

xmlDocPtr doHeartBeat(MYSQL* mysql, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;	
	xmlDocPtr ret = NULL;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		printf("[DEBUG]heartbeat successful\n");
		activeUser(mysql, ouid, sessionID);
	} else {
		printf("[DEBUG]heartbeat failed\n");
	}

	return ret;
}

xmlDocPtr doChangeStatus(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;	
	xmlNodePtr userStatus;	
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	userStatus = userID->next;
	if (userID->children == NULL || userStatus->children == NULL) return NULL;

	xmlDocPtr ret = NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);
	int status = atoi((char*)(userStatus->children->content));

	if (checkSessionID(mysql, ouid, sessionID)) {
		printf("[DEBUG]change status successful\n");
		char stmt[500];
		sprintf(stmt, "update tblusers set status = %d where ouid = %u", status, ouid);
		mysql_query(mysql, stmt);
		setUser(mysql, NULL, ouid, status, sessionID);
	} else {
		printf("[DEBUG]change status failed\n");
	}

	return ret;
}

xmlDocPtr doUpdatePersonalInfo(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr changeList;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	changeList = userID->next;
	if (userID->children == NULL || changeList->children == NULL) return NULL;

	xmlDocPtr ret = newDoc("RESPONSE", "UPDATEPERSONALINFO");
	xmlNodePtr root = xmlDocGetRootElement(ret);

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		printf("[DEBUG]update personal info successful\n");
		char stmt[500];
		sprintf(stmt, "update tblusers set ");
		xmlNodePtr curnode = changeList->children;
		while (curnode != NULL) {
			if (strcmp((char*)curnode->name, "birthYear") == 0 ||
				strcmp((char*)curnode->name, "birthMonth") == 0 || 
				strcmp((char*)curnode->name, "birthDay") == 0 ||
				strcmp((char*)curnode->name, "experience") == 0)
				sprintf(stmt+strlen(stmt), "%s = %s, ", curnode->name, curnode->children->content);
			else
				sprintf(stmt+strlen(stmt), "%s = '%s', ", curnode->name, curnode->children->content);
			curnode = curnode->next;
		}
		sprintf(stmt+strlen(stmt)-1, " where ouid = %u", ouid);
		mysql_query(mysql, stmt);
		xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "0");
		xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	} else {
		printf("[DEBUG]update personal info failed\n");
		xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
		xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	}

	return ret;
}

uint32_t generateFAFR(MYSQL* mysql, uint32_t ouid, uint32_t ouid2) {
	char stmt[500];
	sprintf(stmt, "insert into tbladdfriend(OuID1, OuID2, time) VALUES(%u, %u, now())", ouid, ouid2);
	mysql_query(mysql, stmt);
	return mysql_insert_id(mysql);
}

uint32_t generateOfflineMsg(MYSQL* mysql, uint32_t to, uint32_t from, int type, char* message) {
	char stmt[2000], msg[2000];
	mysql_real_escape_string(mysql, msg, message, strlen(message)); 
	sprintf(stmt, "insert into tblmessages(to_id, from_id, type, message, time, status) VALUES(%u, %u, %d, '%s', now(), 0)", to, from, type, msg);
	mysql_query(mysql, stmt);
	return mysql_insert_id(mysql);
}

uint32_t generateGroupMsg(MYSQL* mysql, uint32_t groupid, int type, char* message) {
	char stmt[2000], msg[2000];
	mysql_real_escape_string(mysql, msg, message, strlen(message)); 
	sprintf(stmt, "insert into tblgroupmessages(groupid, type, message, time, status) VALUES(%u, %d, '%s', now(), 0)", groupid, type, msg);
	mysql_query(mysql, stmt);
	return mysql_insert_id(mysql);
}

void addFriendRequest(MYSQL* mysql, char* messageID, uint32_t ouid, uint32_t ouid2, char* reason) {
	xmlNodePtr node;
	xmlDocPtr msg = newDoc("SYSMSG", "SYSADDFRIEND");
	xmlNodePtr msgroot = xmlDocGetRootElement(msg);

	online_user user = get_user(ouid2);
	uint32_t sysMsgID = generateFAFR(mysql, ouid, ouid2);

	char buff[1000];			
	sprintf(buff, "%u", sysMsgID);
	xmlSetProp(msgroot, BAD_CAST "messageID", (const xmlChar*)buff);
	sprintf(buff, "%u", ouid);
	xmlNewChild(msgroot, NULL, BAD_CAST "OuID", (const xmlChar*)buff);
	xmlNewChild(msgroot, NULL, BAD_CAST "addFriendReason", (const xmlChar*)reason);

	xmlChar* xmlbuff;
	int bufsize;
	xmlDocDumpMemory(msg, &xmlbuff, &bufsize);
	sprintf(buff, "%s", (char*)xmlbuff);
	xmlFree(xmlbuff);
	xmlFreeDoc(msg);

	if (user.status > 0) {
		// online user
		printf("[DEBUG]forward add friend request to an online user\n");
		pthread_mutex_lock(&mutex);
		uint32_t curid = messageid++;
		pthread_mutex_unlock(&mutex);
		oucomm.send_message(&user.client, SERVERID, curid, buff, strlen(buff));
	} else {
		// offline user
		printf("[DEBUG]forward add friend request to an offline user\n");
		generateOfflineMsg(mysql, ouid2, SERVERID, 0, buff);
	}
}

xmlDocPtr doAddFriend(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr friendUserID;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	friendUserID = userID->next;
	if (friendUserID->next == NULL) return NULL;
	addFriendReason = friendUserID->next;
	if (userID->children == NULL || friendUserID->children == NULL || addFriendReason->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);
	uint32_t ouid2 = strtoul((char*)(friendUserID->children->content), NULL, 0);
	char* reason = (char*)(addFriendReason->children->content);

	xmlDocPtr ret = NULL;

	if (checkSessionID(mysql, ouid, sessionID)) {
		printf("[DEBUG]addfriend request successful\n");
		addFriendRequest(mysql, messageID, ouid, ouid2, reason);
		return ret;
	}
	printf("[DEBUG]addfriend request failed\n");
	return ret;
}

xmlDocPtr replyAddFriendRequest(MYSQL* mysql, char* messageID, uint32_t ouid, uint32_t ouid2, uint32_t result, uint32_t msgid) {
	xmlNodePtr node;
	xmlDocPtr ret = newDoc("RESPONSE", "REPLYADDFRIEND");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	xmlDocPtr msg = newDoc("SYSMSG", "SYSREPLYADDFRIEND");
	xmlNodePtr msgroot = xmlDocGetRootElement(msg);

	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MYSQL_FIELD *mysql_fields;
	unsigned int num_fields;
	char stmt[500];
	bool error = false;

	sprintf(stmt, "select OuID, nickname, signature, ip as friendIP, port as friendPort, status as friendStatus, profile as friendProfile, displayPictureFilename as friendDPFileName, natType as friendNatType from tblusers where OuID = %u", ouid);
	printf("[DEBUG]%s\n", stmt);

	mysql_query(mysql, stmt);
	mysql_result = mysql_store_result(mysql);

	if (mysql_result) {
		if (mysql_num_rows(mysql_result) == 1) {
			num_fields = mysql_num_fields(mysql_result);
			mysql_fields = mysql_fetch_fields(mysql_result);
			mysql_row = mysql_fetch_row(mysql_result);
			for (int i = 0; i < num_fields; i++) {
				xmlNewChild(msgroot, NULL, (const xmlChar*)mysql_fields[i].name, (const xmlChar*)mysql_row[i]);
			}
		} else
			error = true;
		mysql_free_result(mysql_result);
	} else
		error = true;
	
	sprintf(stmt, "select OuID, nickname, signature, ip as friendIP, port as friendPort, status as friendStatus, profile as friendProfile, displayPictureFilename as friendDPFileName, natType as friendNatType from tblusers where OuID = %u", ouid2);
	printf("[DEBUG]%s\n", stmt);

	mysql_query(mysql, stmt);
	mysql_result = mysql_store_result(mysql);

	if (mysql_result) {
		if (mysql_num_rows(mysql_result) == 1) {
			num_fields = mysql_num_fields(mysql_result);
			mysql_fields = mysql_fetch_fields(mysql_result);
			mysql_row = mysql_fetch_row(mysql_result);
			for (int i = 0; i < num_fields; i++) {
				xmlNewChild(root, NULL, (const xmlChar*)mysql_fields[i].name, (const xmlChar*)mysql_row[i]);
			}
		} else
			error = true;
		mysql_free_result(mysql_result);
	} else
		error = true;

	if (error) {
		xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
		xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
		xmlFreeDoc(msg);
		return ret;
	}

	online_user user = get_user(ouid2);

	char buff[1000];			
	sprintf(buff, "%u", msgid);
	xmlSetProp(msgroot, BAD_CAST "messageID", (const xmlChar*)buff);
	sprintf(buff, "%u", result);
	node = xmlNewChild(msgroot, NULL, BAD_CAST "replyResult", (const xmlChar*)buff);
	
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "0");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	
	xmlChar* xmlbuff;
	int bufsize;
	xmlDocDumpMemory(msg, &xmlbuff, &bufsize);
	sprintf(buff, "%s", (char*)xmlbuff);
	xmlFree(xmlbuff);
	xmlFreeDoc(msg);

	// add friend if accept
	if (result == 0) {
		char stmt[500];
		sprintf(stmt, "insert into tblfriends(OuID1, OuID2) VALUES(%u, %u)", ouid, ouid2);
		mysql_query(mysql, stmt);
		sprintf(stmt, "insert into tblfriends(OuID1, OuID2) VALUES(%u, %u)", ouid2, ouid);
		mysql_query(mysql, stmt);
	}

	if (user.status > 0) {
		// online user
		printf("[DEBUG]forward reply add friend to an online user\n");
		pthread_mutex_lock(&mutex);
		uint32_t curid = messageid++;
		pthread_mutex_unlock(&mutex);
		oucomm.send_message(&user.client, SERVERID, curid, buff, strlen(buff));
	} else {
		// offline user
		printf("[DEBUG]forward reply friend request to an offline user\n");
		generateOfflineMsg(mysql, ouid2, SERVERID, 0, buff);
	}
	return ret;
}

xmlDocPtr doReplyAddFriend(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr friendUserID;
	xmlNodePtr replyResult;
	xmlNodePtr sysMsgID;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	friendUserID = userID->next;
	if (friendUserID->next == NULL) return NULL;
	replyResult = friendUserID->next;
	if (replyResult->next == NULL) return NULL;
	sysMsgID = replyResult->next;
	if (userID->children == NULL || friendUserID->children == NULL || replyResult->children == NULL || sysMsgID->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);
	uint32_t ouid2 = strtoul((char*)(friendUserID->children->content), NULL, 0);
	uint32_t result = strtoul((char*)(replyResult->children->content), NULL, 0);
	uint32_t msgid = strtoul((char*)(sysMsgID->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		char stmt[500];
		sprintf(stmt, "delete from tbladdfriend where id = %u and ouid1 = %u and ouid2 = %u", msgid, ouid2, ouid);
		mysql_query(mysql, stmt);
		if (mysql_affected_rows(mysql) == 1) {
			printf("[DEBUG]replyaddfriend request successful\n");
			return replyAddFriendRequest(mysql, messageID, ouid, ouid2, result, msgid);
		}
	}
	
	printf("[DEBUG]replyaddfriend request failed\n");
	xmlDocPtr ret = newDoc("RESPONSE", "REPLYADDFRIEND");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	return ret;
}

xmlDocPtr removeFriend(MYSQL* mysql,  uint32_t ouid, uint32_t ouid2) {
	xmlNodePtr node;
	xmlDocPtr msg1 = newDoc("SYSMSG", "SYSREMOVEFRIEND");
	xmlNodePtr root1 = xmlDocGetRootElement(msg1);
	xmlDocPtr msg2 = newDoc("SYSMSG", "SYSREMOVEFRIEND");
	xmlNodePtr root2 = xmlDocGetRootElement(msg2);

	char buff[1000];			
	sprintf(buff, "%u", ouid);
	xmlNewChild(root1, NULL, BAD_CAST "OuID", (const xmlChar*)buff);
	sprintf(buff, "%u", ouid2);
	xmlNewChild(root2, NULL, BAD_CAST "OuID", (const xmlChar*)buff);
	
	xmlSetProp(root1, BAD_CAST "returnCode", BAD_CAST "0");
	xmlSetProp(root1, BAD_CAST "messageID", BAD_CAST "0");
	xmlSetProp(root2, BAD_CAST "returnCode", BAD_CAST "0");
	xmlSetProp(root2, BAD_CAST "messageID", BAD_CAST "0");
	

	online_user user = get_user(ouid2);

	xmlChar* xmlbuff;
	int bufsize;
	xmlDocDumpMemory(msg1, &xmlbuff, &bufsize);
	sprintf(buff, "%s", (char*)xmlbuff);
	xmlFree(xmlbuff);
	xmlFreeDoc(msg1);

	if (user.status > 0) {
		// online user
		printf("[DEBUG]forward remove friend to an online user\n");
		pthread_mutex_lock(&mutex);
		uint32_t curid = messageid++;
		pthread_mutex_unlock(&mutex);
		oucomm.send_message(&user.client, SERVERID, curid, buff, strlen(buff));
	} else {
		// offline user
		printf("[DEBUG]forward remove friend to an offline user\n");
		generateOfflineMsg(mysql, ouid2, SERVERID, 0, buff);
	}
	return msg2;
}

xmlDocPtr doRemoveFriend(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr friendUserID;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	friendUserID = userID->next;
	if (userID->children == NULL || friendUserID->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);
	uint32_t ouid2 = strtoul((char*)(friendUserID->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		char stmt[500];
		sprintf(stmt, "delete from tblfriends where (ouid1 = %u and ouid2 = %u) or (ouid1 = %u and ouid2 = %u)", ouid2, ouid, ouid, ouid2);
		mysql_query(mysql, stmt);
		if (mysql_affected_rows(mysql) > 0) {
			printf("[DEBUG]removefriend request successful\n");
			return removeFriend(mysql, ouid, ouid2);
		}
	}
	
	printf("[DEBUG]removefriend request failed\n");
	return NULL;
}

xmlDocPtr downloadFriend(MYSQL* mysql, char* messageID, uint32_t ouid) {
	xmlDocPtr ret = newDoc("RESPONSE", "DOWNLOADFRIEND");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "0");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);

	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MYSQL_FIELD *mysql_fields;
	unsigned int num_fields;
	char stmt[500];

	sprintf(stmt, "select tblusers.OuID, tblusers.emailID, tblusers.email, tblusers.nickname, tblusers.signature, tblfriends.localGroup, tblusers.focusCounter, tblusers.ip as friendIP, tblusers.port as friendPort, tblusers.status as friendStatus, tblusers.profile as friendProfile, tblusers.displayPictureFilename as friendDPFileName, tblusers.natType as friendNatType from tblusers, tblfriends where tblfriends.OuID1 = %u and tblfriends.OuID2 = tblusers.OuID", ouid);
	mysql_query(mysql, stmt);
	mysql_result = mysql_store_result(mysql);

	if (mysql_result) {

		num_fields = mysql_num_fields(mysql_result);
		mysql_fields = mysql_fetch_fields(mysql_result);
		char name[50];
		int k = 1;
		while (mysql_row = mysql_fetch_row(mysql_result)) {
			sprintf(name, "friendInfo%d", k++);
			xmlNodePtr node = xmlNewNode(NULL, (const xmlChar*)name);
			for (int i = 0; i < num_fields; i++) {
				xmlNewChild(node, NULL, (const xmlChar*)mysql_fields[i].name, (const xmlChar*)mysql_row[i]);
			}
			xmlAddChild(root, node);
		}
		mysql_free_result(mysql_result);
	}
	
	return ret;
}

xmlDocPtr doDownloadFriend(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		printf("[DEBUG]downloadfriend request successful\n");
		return downloadFriend(mysql, messageID, ouid);
	}
	
	printf("[DEBUG]downloadfriend request failed\n");
	xmlDocPtr ret = newDoc("RESPONSE", "DOWNLOADFRIEND");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	return ret;
}

xmlDocPtr searchFriend(MYSQL* mysql, char* messageID, uint32_t ouid, int searchType, char* keyword, int offset, int limit) {
	xmlDocPtr ret = newDoc("RESPONSE", "SEARCHFRIEND");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "0");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);

	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MYSQL_FIELD *mysql_fields;
	unsigned int num_fields;
	char stmt[500];

	if (searchType == 0)
		sprintf(stmt, "select tblusers.OuID as targetUserID, tblusers.emailID as emailID, tblusers.nickname as nickname from tblusers where tblusers.OuID = %s limit %d,%d", keyword, offset, limit);
	else if (searchType == 1)
		sprintf(stmt, "select tblusers.OuID as targetUserID, tblusers.emailID as emailID, tblusers.nickname as nickname from tblusers where tblusers.emailID = '%s' limit %d,%d", keyword, offset, limit);
	else
		sprintf(stmt, "select tblusers.OuID as targetUserID, tblusers.emailID as emailID, tblusers.nickname as nickname from tblusers where tblusers.nickname = '%s' limit %d,%d", keyword, offset, limit);

	mysql_query(mysql, stmt);
	mysql_result = mysql_store_result(mysql);

	char totalResult[50], searchOffset[50];
	sprintf(totalResult, "%d", 0);
	sprintf(searchOffset, "%d", offset);

	if (mysql_result) {
		sprintf(totalResult, "%d", mysql_num_rows(mysql_result));
		sprintf(searchOffset, "%d", offset);
		xmlNewChild(root, NULL, BAD_CAST "searchTotalResult", (const xmlChar*)totalResult);
		xmlNewChild(root, NULL, BAD_CAST "searchOffset", (const xmlChar*)searchOffset);

		num_fields = mysql_num_fields(mysql_result);
		mysql_fields = mysql_fetch_fields(mysql_result);
		char name[50];
		int k = 1;
		while (mysql_row = mysql_fetch_row(mysql_result)) {
			sprintf(name, "searchResult%d", k++);
			xmlNodePtr node = xmlNewNode(NULL, (const xmlChar*)name);
			for (int i = 0; i < num_fields; i++) {
				xmlNewChild(node, NULL, (const xmlChar*)mysql_fields[i].name, (const xmlChar*)mysql_row[i]);
			}
			xmlAddChild(root, node);
		}
		mysql_free_result(mysql_result);
	} else {
		xmlNewChild(root, NULL, BAD_CAST "searchTotalResult", (const xmlChar*)totalResult);
		xmlNewChild(root, NULL, BAD_CAST "searchOffset", (const xmlChar*)searchOffset);
	}
	
	return ret;
}

xmlDocPtr doSearchFriend(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr searchUserIDType;
	xmlNodePtr searchKeyword;
	xmlNodePtr searchOffset;
	xmlNodePtr searchLimit;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	searchUserIDType = userID->next;
	if (searchUserIDType->next == NULL) return NULL;
	searchKeyword = searchUserIDType->next;
	if (searchKeyword->next == NULL) return NULL;
	searchOffset = searchKeyword->next;
	if (searchOffset->next == NULL) return NULL;
	searchLimit = searchOffset->next;
	if (userID->children == NULL || searchUserIDType->children == NULL || searchKeyword->children == NULL || searchOffset->children == NULL || searchLimit->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);
	uint32_t searchType = strtoul((char*)(searchUserIDType->children->content), NULL, 0);
	uint32_t offset = strtoul((char*)(searchOffset->children->content), NULL, 0);
	uint32_t limit = strtoul((char*)(searchLimit->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		printf("[DEBUG]searchfriend request successful\n");
		return searchFriend(mysql, messageID, ouid, searchType, (char*)(searchKeyword->children->content), offset, limit);
	}
	
	printf("[DEBUG]searchfriend request failed\n");
	xmlDocPtr ret = newDoc("RESPONSE", "SEARCHFRIEND");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	return ret;
}

xmlDocPtr queryUser(MYSQL* mysql, char* messageID, uint32_t ouid, uint32_t ouid2) {
	xmlDocPtr ret = newDoc("RESPONSE", "QUERYUSER");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MYSQL_FIELD *mysql_fields;
	unsigned int num_fields;
	char stmt[500];
	sprintf(stmt, "select OuID, emailID, email, nickname, signature, profile, focusCounter, birthYear, birthMonth, birthDay, sex, displayPictureFilename, experience, personalStatement, city, province, country from tblusers where OuID = %u", ouid2);
	mysql_query(mysql, stmt);
	mysql_result = mysql_store_result(mysql);
	if (mysql_result) {
		mysql_row = mysql_fetch_row(mysql_result);
		num_fields = mysql_num_fields(mysql_result);
		mysql_fields = mysql_fetch_fields(mysql_result);
		if (mysql_row) {
			printf("[DEBUG]queryuser successful\n");
			xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "0");
			xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
			for (int i = 0; i < num_fields; i++) {
				xmlNewChild(root, NULL, (const xmlChar*)mysql_fields[i].name, (const xmlChar*)mysql_row[i]);
			}
			mysql_free_result(mysql_result);
			return ret;
		}
		mysql_free_result(mysql_result);
	}
	printf("[DEBUG]queryuser failed\n");
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	return ret;
}


xmlDocPtr doQueryUser(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr targetUserID;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	targetUserID = userID->next;
	if (userID->children == NULL || targetUserID->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);
	uint32_t ouid2 = strtoul((char*)(targetUserID->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		return queryUser(mysql, messageID, ouid, ouid2);
	}
	
	printf("[DEBUG]queryuser request failed\n");
	xmlDocPtr ret = newDoc("RESPONSE", "QUERYUSER");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	return ret;
}

void sendMessage(MYSQL* mysql, uint32_t ouid, uint32_t ouid2, char* msg) {
	online_user user = get_user(ouid2);

	if (user.status > 0) {
		// online user
		printf("[DEBUG]forward chat message to an online user\n");
		pthread_mutex_lock(&mutex);
		uint32_t curid = messageid++;
		pthread_mutex_unlock(&mutex);
		oucomm.send_message(&user.client, SERVERID, curid, msg, strlen(msg));
	} else {
		// offline user
		printf("[DEBUG]forward chat message to an offline user\n");
		generateOfflineMsg(mysql, ouid2, ouid, 1, buff);
	}
}

void getOfflineMessage(MYSQL* mysql, uint32_t ouid) {
	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MYSQL_FIELD *mysql_fields;
	unsigned int num_fields;
	char stmt[500];
	sprintf(stmt, "select id, from_id, message from tblmessages where to_id = %u and status = 0");
	mysql_query(mysql, stmt);
	mysql_result = mysql_store_result(mysql);
	if (mysql_result) {
		maxid = 0;
		while (mysql_row = mysql_fetch_row(mysql_result)) {
			uint32_t id = strtoul((char*)mysql_row[0]);
			uint32_t ouid2 = strtoul((char*)mysql_row[1]);
			char* msg = (char*)mysql_row[2];
			if (id > maxid) maxid = id;
			sendMessage(mysql, ouid2, ouid, msg);
		}
		mysql_free_result(mysql_result);
		sprintf(stmt, "delete from tblmessages where to_id = %u and id <= %u", ouid, maxid);
		mysql_query(mysql, stmt);
	}
}

xmlDocPtr doGetOfflineMessage(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->children == NULL) return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);

	if (checkSessionID(mysql, ouid, sessionID)) {
		getOfflineMessage(mysql, ouid);
	}
}

void sendGroupMessage(MYSQL* mysql, uint32_t ouid, uint32_t groupid, char* msg) {
	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MYSQL_FIELD *mysql_fields;
	unsigned int num_fields;
	char stmt[500];

	uint32_t msgID = generateGroupMsg(mysql, groupid, 1, msg);

	sprintf(stmt, "update tblgroupmembers set lastactivedate = now() where groupid = %u and ouid = %u", groupid, ouid);
	mysql_query(mysql, stmt);

	sprintf(stmt, "select ouid from tblgroupmembers where groupid = %u", groupid);
	mysql_query(mysql, stmt);
	mysql_result = mysql_store_result(mysql);
	if (mysql_result) {
		while (mysql_row = mysql_fetch_row(mysql_result)) {
			uint32_t ouid2 = strtoul((char*)mysql_row[0]);
			if (ouid2 != ouid) {
				online_user user = get_user(ouid2);
				if (user.status > 0) {
					char stmt[500];
					sprintf(stmt, "update tblingroups set pointer = %u where ouid = %u and groupid = %u", msgID, ouid2, groupid);
					mysql_query(mysql, stmt);
				}
			}
		}
		mysql_free_result(mysql_result);
	}
}

xmlDocPtr doSendMessage(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr receiverID;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	receiverID = userID->next;
	if (receiverID->next == NULL) return NULL;
	messageBody = receiverID->next;
	if (userID->children == NULL || receiverID->children == NULL || messageBody->children == NULL) return NULL;

	char* type = (char*)xmlGetProp(receiverID, BAD_CAST "type");
	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);
	uint32_t ouid2 = strtoul((char*)(receiverID->children->content), NULL, 0);
	char* msg = (char*)(messageBody->children->content);

	if (checkSessionID(mysql, ouid, sessionID)) {
		xmlNodePtr node;
		xmlDocPtr msg = newDoc("SYSMSG", "CHAT");
		xmlNodePtr msgroot = xmlDocGetRootElement(msg);

		char buff[1000];
		xmlChar* xmlbuff;
		int bufsize;

		if (type != NULL && strcmp(type, "group") == 0) {
			// group message
			sprintf(buff, "%u", ouid2);
			node = xmlNewChild(msgroot, NULL, BAD_CAST "senderID", (const xmlChar*)buff);
			xmlSetProp(node, BAD_CAST "type", BAD_CAST "group");	
			xmlNewChild(msgroot, NULL, BAD_CAST "messageBody", (const xmlChar*)msg);
			xmlDocDumpMemory(msg, &xmlbuff, &bufsize);
			sprintf(buff, "%s", (char*)xmlbuff);
			xmlFree(xmlbuff);

			sendGroupMessage(mysql, ouid, ouid2, buff);
		} else {
			// personal message
			sprintf(buff, "%u", ouid);
			node = xmlNewChild(msgroot, NULL, BAD_CAST "senderID", (const xmlChar*)buff);
			xmlSetProp(node, BAD_CAST "type", BAD_CAST "personal");	
			xmlNewChild(msgroot, NULL, BAD_CAST "messageBody", (const xmlChar*)msg);
			xmlDocDumpMemory(msg, &xmlbuff, &bufsize);
			sprintf(buff, "%s", (char*)xmlbuff);
			xmlFree(xmlbuff);

			sendMessage(mysql, ouid, ouid2, buff);
		}

		xmlFreeDoc(msg);
	}	
	return NULL;
}

bool checkGroupCounter(MYSQL* mysql, uint32_t ouid) {
	char stmt[500];
	sprintf(stmt, "update tblusers set ownGroups = ownGroups + 1 where OuID = %u and ownGroups < groupLimits", ouid);
	mysql_query(mysql, stmt);
	if (mysql_affected_rows(mysql) == 1)
		return true;
	else
		return false;
}

void setGroupOwner() {

}

void setGroupAdmin() {

}

void addGroupMember() {

}

void removeGroupMember() {
}

void inviteMember(uint32_t ouid, uint32_t ouid2, uint32_t groupid, char* reason) {
	xmlNodePtr node;
	xmlDocPtr msg = newDoc("SYSMSG", "INVITEJOINGROUP");
	xmlNodePtr msgroot = xmlDocGetRootElement(msg);

	online_user user = get_user(ouid2);
	uint32_t sysMsgID = generateFAFR(mysql, ouid, ouid2);

	char buff[1000];			
	sprintf(buff, "%u", sysMsgID);
	xmlSetProp(msgroot, BAD_CAST "messageID", (const xmlChar*)buff);
	sprintf(buff, "%u", ouid);
	xmlNewChild(msgroot, NULL, BAD_CAST "OuID", (const xmlChar*)buff);
	xmlNewChild(msgroot, NULL, BAD_CAST "addFriendReason", (const xmlChar*)reason);

	xmlChar* xmlbuff;
	int bufsize;
	xmlDocDumpMemory(msg, &xmlbuff, &bufsize);
	sprintf(buff, "%s", (char*)xmlbuff);
	xmlFree(xmlbuff);
	xmlFreeDoc(msg);






}

void createGroup(MYSQL* mysql, char* messageID, uint32_t ouid, char* name, char* description, char* category, char* announcement, char* tag, xmlNodePtr members) {
	char stmt[500];
	char name2[50], description2[500], category2[50], announcment2[500], tag2[500];
	mysql_real_escape_string(mysql, name2, name, strlen(name));
	mysql_real_escape_string(mysql, description2, description, strlen(description));
	mysql_real_escape_string(mysql, category2, category, strlen(category));
	mysql_real_escape_string(mysql, announcement2, announcement, strlen(announcement));
	mysql_real_escape_string(mysql, tag2, tag, strlen(tag));

	sprintf(stmt, "insert into tblgroups(type, groupName, description, category, tag, announcement, owner, sincedate, createdBy, joinGroupPolicy, total, memberLimit) VALUES(0, '%s', '%s', '%s', '%s', %s', %u, now(), %u, 0, 1, 99)", name2, description2, category2, tag2, announcement2, ouid);
	mysql_query(mysql, stmt);
	uint32_t groupid = mysql_insert_id(mysql);
	sprintf(stmt, "insert into tblgroupmembers(groupid, ouid, privilege, lastactivedate) VALUES(%u, %u, 2, now())", groupid, ouid);
	mysql_query(mysql, stmt);
	sprintf(stmt, "insert into tblingroups(ouid, groupid, privilege) VALUES(%u, %u, 2)", ouid, groupid);
	mysql_query(mysql, stmt);

	xmlNodePtr mem = members->children;
	while (mem != NULL) {
		if (mem->children != NULL) {
			uint32_t ouid2 = strtoul((char*)(mem->children->content), NULL, 0);
			inviteMember(ouid, ouid2, groupid, "");
		}
		mem = mem->next;
	}
}

xmlDocPtr doCreateGroup(MYSQL* mysql, char* messageID, char* sessionID, xmlNodePtr node) {
	xmlNodePtr userID;
	xmlNodePtr groupName;
	xmlNodePtr groupDescription;
	xmlNodePtr groupCategory;
	xmlNodePtr groupAnnouncement;
	xmlNodePtr groupTag;
	xmlNodePtr groupMemberList;
	if (node->children == NULL) return NULL;
	userID = node->children;
	if (userID->next == NULL) return NULL;
	groupName = userID->next;
	if (groupName->next == NULL) return NULL;
	groupDescription = groupName->next;
	if (groupDescription->next == NULL) return NULL;
	groupCategory = groupDescription->next;
	if (groupCategory->next == NULL) return NULL;
	groupAnnouncement = groupCategory->next;
	if (groupAnnouncement->next == NULL) return NULL;
	groupTag = groupAnnouncement->next;
	if (groupTag->next == NULL) return NULL;
	groupMemberList = groupTag->next;
	if (userID->children == NULL || groupName->children == NULL || groupDescription->children == NULL || 
		groupCategory->children == NULL || groupAnnouncement->children == NULL || groupTag->children == NULL)
		return NULL;

	uint32_t ouid = strtoul((char*)(userID->children->content), NULL, 0);
	char* name = (char*)(groupName->children->content);
	char* description = (char*)(groupDescription->children->content);
	char* category = (char*)(groupCategory->children->content);
	char* announcement = (char*)(groupAnnouncement->children->content);
	char* tag = (char*)(groupTag->children->content);

	if (checkSessionID(mysql, ouid, sessionID) && increaseGroupCounter(mysql, ouid)) {
		printf("[DEBUG]searchfriend request successful\n");
		createGroup(mysql, messageID, ouid, name, category, description, groupMemberList);
		xmlDocPtr ret = newDoc("RESPONSE", "CREATEGROUP");
		xmlNodePtr root = xmlDocGetRootElement(ret);
		xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "0");
		xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
		return ret;
	}
	
	printf("[DEBUG]creategroup request failed\n");
	xmlDocPtr ret = newDoc("RESPONSE", "CREATEGROUP");
	xmlNodePtr root = xmlDocGetRootElement(ret);
	xmlSetProp(root, BAD_CAST "returnCode", BAD_CAST "1");
	xmlSetProp(root, BAD_CAST "messageID", (const xmlChar*)messageID);
	return ret;
}

xmlDocPtr doFollowUser(xmlNodePtr node) {


}

xmlDocPtr doGetFollowList(xmlNodePtr node) {


}

xmlDocPtr doAddFile(xmlNodePtr node) {

}

void process(struct sockaddr_in* client, const char* recvbuf, int recvlen, char* sendbuf, int* sendlen) {
	// new xml doc
	xmlDocPtr doc = xmlParseMemory(recvbuf, recvlen);
	xmlDocPtr ret = NULL;
	xmlNodePtr cur_node = xmlDocGetRootElement(doc);

	MYSQL* mysql;

	pthread_mutex_lock(&mutex);
	mysql = connections.top();
	connections.pop();
	pthread_mutex_unlock(&mutex);

	if (!mysql_ping(mysql)) {
		mysql_close(mysql);
		if (connectdb(mysql) == false) {
			printf("not connected!\n");
			exit(1);
		}
	}

	if (cur_node != NULL && cur_node->type == XML_ELEMENT_NODE && strcmp((char*)cur_node->name, "REQUEST") == 0) {
		printf("[DEBUG]new request\n");
		char* actionType = (char*)xmlGetProp(cur_node, BAD_CAST "actionType");
		char* messageID = (char*)xmlGetProp(cur_node, BAD_CAST "messageID");
		char* communicationVersion = (char*)xmlGetProp(cur_node, BAD_CAST "communicationVersion");
		char* sessionID = (char*)xmlGetProp(cur_node, BAD_CAST "sessionID");
		if (actionType != NULL && messageID != NULL) {
			printf("[DEBUG]actionType: %s, messageID: %s\n", actionType, messageID);
			// communication version checking
			// TODO
			if (strcmp(actionType, "LOGIN") == 0 && communicationVersion != NULL) {
				printf("[DEBUG]login process start\n");
				ret = doLogin(mysql, client, messageID, cur_node);
				printf("[DEBUG]login process finish\n");
			} else if (strcmp(actionType, "LOGOFF") == 0 && sessionID != NULL) {
				printf("[DEBUG]logoff process start\n");
				ret = doLogoff(mysql, sessionID, cur_node);
				printf("[DEBUG]logoff process finish\n");
			} else if (strcmp(actionType, "HEARTBEAT") == 0 && sessionID != NULL) {
				printf("[DEBUG]heartbeat process start\n");
				ret = doHeartBeat(mysql, sessionID, cur_node);
				printf("[DEBUG]heartbeat process finish\n");
			} else if (strcmp(actionType, "CHANGESTATUS") == 0 && sessionID != NULL) {
				printf("[DEBUG]changestatus process start\n");
				ret = doChangeStatus(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]changestatus process finish\n");
			} else if (strcmp(actionType, "UPDATEPERSONALINFO") == 0 && sessionID != NULL) {
				printf("[DEBUG]updatepersonalinfo process start\n");
				ret = doUpdatePersonalInfo(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]updatepersonalinfo process finish\n");
			} else if (strcmp(actionType, "ADDFRIEND") == 0 && sessionID != NULL) {
				printf("[DEBUG]addfriend process start\n");
				ret = doAddFriend(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]addfriend process finish\n");
			} else if (strcmp(actionType, "REPLYADDFRIEND") == 0 && sessionID != NULL) {
				printf("[DEBUG]replyaddfriend process start\n");
				ret = doReplyAddFriend(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]replyaddfriend process finish\n");
			} else if (strcmp(actionType, "REMOVEFRIEND") == 0 && sessionID != NULL) {
				printf("[DEBUG]removefriend process start\n");
				ret = doRemoveFriend(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]removefriend process finish\n");
			} else if (strcmp(actionType, "DOWNLOADFRIEND") == 0 && sessionID != NULL) {
				printf("[DEBUG]downloadfriend process start\n");
				ret = doDownloadFriend(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]downloadfriend process finish\n");
			} else if (strcmp(actionType, "SEARCHFRIEND") == 0 && sessionID != NULL) {
				printf("[DEBUG]searchfriend process start\n");
				ret = doSearchFriend(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]searchfriend process finish\n");
			} else if (strcmp(actionType, "QUERYUSER") == 0 && sessionID != NULL) {
				printf("[DEBUG]queryuser process start\n");
				ret = doQueryUser(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]queryuser process finish\n");
			} else if (strcmp(actionType, "CREATEGROUP") == 0 && sessionID != NULL) {
				printf("[DEBUG]creategroup process start\n");
				ret = doCreateGroup(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]creategroup process finish\n");
			} else if (strcmp(actionType, "GETOFFLINEMESSAGE") == 0) {
				printf("[DEBUG]getofflinemessage process start\n");
				ret = doGetOfflineMessage(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]getofflinemessage process finish\n");
			} else if (strcmp(actionType, "SENDMESSAGE") == 0) {
				printf("[DEBUG]sendmessage process start\n");
				ret = doSendMessage(mysql, messageID, sessionID, cur_node);
				printf("[DEBUG]sendmessage process finish\n");
			} else if (strcmp(actionType, "FOLLOWUSER") == 0) {
				ret = doFollowUser(cur_node);
			} else if (strcmp(actionType, "GETFOLLOWLIST") == 0) {
				ret = doGetFollowList(cur_node);
			} else if (strcmp(actionType, "ADDFILE") == 0) {
				ret = doAddFile(cur_node);
			} else {

			}
		}
		
	}

	pthread_mutex_lock(&mutex);
	connections.push(mysql);
	pthread_mutex_unlock(&mutex);

	if (ret != NULL) {
		xmlChar* buff;
		int bufsize;
		printf("[DEBUG]response start\n");
		xmlDocDumpMemory(ret, &buff, &bufsize);
		sprintf(sendbuf, "%s", (char*)buff);
		*sendlen = strlen(sendbuf);
		xmlFree(buff);
		printf("[DEBUG]response finish\n");
		xmlFreeDoc(ret);
	} else {
		printf("[DEBUG]no response\n");
		*sendlen = 0;
	}
	xmlFreeDoc(doc);
}



void* new_message(struct sockaddr_in* client, char* recvbuf, int recvlen) {
	char sendbuf[10000];
	int sendlen;

	socklen_t structlength = sizeof(*client);

	printf("[DEBUG]new request from ip:%s, port:%u\n", inet_ntoa(client->sin_addr), ntohs(client->sin_port));
	printf("[DEBUG]request content:%s\n", recvbuf);
	
	process(client, recvbuf, recvlen, sendbuf, &sendlen);
	if (sendlen > 0){
		pthread_mutex_lock(&mutex);
		uint32_t curid = messageid++;
		pthread_mutex_unlock(&mutex);
		oucomm.send_message(client, SERVERID, curid, sendbuf, sendlen);
		printf("[DEBUG]response content:%s\n", sendbuf);
	}
}

int main(int argc, char *argv[]) {
	int sock;
	struct sockaddr_in server, client;
	socklen_t structlength;
	int port = 50000;

	memset((char *)&server,0,sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port);

	if ((sock = socket(AF_INET,SOCK_DGRAM,0)) < 0) {
		printf("socket create error!\n");
		return 1;
	}
	
	structlength = sizeof(server);
	if (bind(sock, (struct sockaddr *)&server, structlength) < 0) {
		printf("socket bind error!\n");
		return 1;
	}

	for (int i = 0; i < MAXWORKER; i++) {
		if (connectdb(&mysqls[i]) == false) {
			printf("not connected!\n");
			return 1;
		}
		connections.push(&mysqls[i]);
	}

	pthread_mutex_init(&mutex, NULL);

	usertable.resize(TABLESIZE);
	for (int i = 0; i < TABLESIZE; i++)
		usertable[i] = list<user_list_entry>();
	mutexs.resize(TABLESIZE);
	for (int i = 0; i < TABLESIZE; i++)
		pthread_mutex_init(&mutexs[i], NULL);

	oucomm.start(sock, NULL, new_message, MAXWORKER);

	while (1) {
		sleep(1000);
	}

	for (int i = 0; i < MAXWORKER; i++)
		mysql_close(&mysqls[i]);
	close(sock);
	return 0;
}
