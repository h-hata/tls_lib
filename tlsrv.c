
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <linux/sockios.h>
//#include <linux/if.h>
//#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "tls.h"
extern void dump_packet(unsigned char *,int);
#define	PRIV_FILE	"cert/server.key"
#define	CERT_FILE	"cert/server.crt"
#define	PORT		4444	

struct packet_t{
	unsigned int a;
	unsigned short b;
	unsigned short c;
	char	uid[64];
	char	pass[64];
	unsigned int d;
};

	

void check_packet(void *pa)
{
	struct packet_t	*p;
	p=(struct packet_t *)pa;
	printf("a= %u (%04X)\n", ntohl(p->a),ntohl(p->a));
	printf("b= %u (%02X)\n", ntohs(p->b),ntohl(p->b));
	printf("c= %u (%02X)\n", ntohs(p->c),ntohl(p->c));
	printf("uid=%s\n",p->uid);
	printf("pas=%s\n",p->pass);
	printf("a= %u (%04X)\n", ntohl(p->d),ntohl(p->d));
}

static void tls_callback(SSL *ssl,char *ipv4,int port)
{
	char buff[64000];
	int	len;
	int	i;

#ifdef DEBUG
	printf("New Session Establieshed\n");
	printf("Peer IP=%s(%d)\n",ipv4,port);
#endif
	len=64000;
	printf("read in\n");
	len=SSL_read(ssl,buff,len);
	printf("read out len=%d\n",len);
	if(len<=0){
		//printf("Break\n");
		return;
	}
	dump_packet(buff,len);
char *RESP= "HTTP/1.1 200 OK\r\n"
"Server: Ubuntu\r\n"
"Connection: close\r\n"
"Content-Type: text/html; charset=utf-8\r\n"
"Content-Language: ja\r\n"
"Content-Length: %d\r\n\r\n"
"%s";

#define BODY "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>HTMLサンプル</title></head><body><h1>見出し１</h1><hr>本文はなにもありません</body></html>\n"

	sprintf(buff,RESP,strlen(BODY),BODY);
	len=SSL_write(ssl,buff,strlen(buff));
	printf("Sent len=%d\n",len);
	dump_packet(buff,strlen(buff));
#ifdef DEBUG
	printf("Callback functione return\n");
#endif
	return;
}


int main()
{
	int ret,i;
	STAT	stat;
	TLS_Init();
	ret=TLS_ServerSetup(
		PORT,
		CERT_FILE,
		PRIV_FILE,
		tls_callback );
	if(ret<0){
		printf("TLS_ServerSetup returned %d\n",ret);
		_exit(1);
	}
	ret=TLS_ServerStart();
	for(i=0;;i++){
		sleep(1);
		ret=TLS_Status(&stat);
		//printf("Status=%d\n",stat.active);
	}
	TLS_ServerShutdown();
	return 0;
}

