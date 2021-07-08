#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#define	TLS_RECV_TIMEOUT	999
typedef void (*TLS_CALLBACK_T)(SSL *ssl,char *ipv4,int port);
typedef struct {
	int	active;
	int	shutdown;
	int	accepted;
	int	callbacked;
	int	accept_error;
	int	accept_error2;
	int	thread_error;
	int	too_many_error;
	
}STAT;
extern int TLS_Init(void);
extern int TLS_Send_Data( SSL *ssl,char *buf,int len);
extern int TLS_Recv_Data(SSL *ssl,char *buf,int len,int timeout,int *reason);
extern int TLS_Error(char *msg,int len);
/*Client APIs***********************************************/
extern int TLS_ClientSetup(char *cert_file);
extern SSL *TLS_Connect(char *host,int port,int *reason);
extern void TLS_Disconnect(SSL *ssl);
extern void TLS_ClientShutdown(void);

/*Server APIs***********************************************/
extern int TLS_ServerSetup(
		int port,
		char *server_cert,
		char *server_priv,
		TLS_CALLBACK_T tls_callback );
extern int TLS_ServerStart(void);
extern void TLS_ServerShutdown(void);
extern int TLS_Status(STAT *);


