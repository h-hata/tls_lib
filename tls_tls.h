#include "tls.h"

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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <pthread.h>
#define THREAD_CC *
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(tid, entry, arg) thread_create_linux(&(tid), (entry), (arg))
#else
#include <stdio.h>
#include <windows.h>
#define	strcasecmp(x,y)	_stricmp(x,y)
#define THREAD_CC   __cdecl
#define THREAD_TYPE DWORD
#define THREAD_CREATE(tid, entry, arg) do{ _beginthread((entry),0,(arg));\
						(tid)=GetCurrentThreadId();\
					}while(0)
#endif
