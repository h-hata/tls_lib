/******************************************************************
 * This software has been written by Hiroaki Hata and  
 * the copyright is reserved .
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * 
 * contact email:hata@qc5.so-net.ne.jp
 * **************************************************************/
/**
  @file	tls.c
  */
#define	E_TLS	0
#include			"tls_tls.h"
#define SERVERNAME		"localhost"
#define	PORT		4430
#define	SERVER_MAX	2000
#define	CLIENT_MAX	2000
#define	STACK_SIZE	(2560*1024)
typedef enum{
	ST_INVALID,
	ST_ALIVE,
	ST_SHUTDOWN
}ST_STATUS;
typedef struct {
	ST_STATUS status;
	SSL	*ssl;
}THREAD_TABLE;
static STAT	stat;
static THREAD_TABLE	server_threads[SERVER_MAX];
static int verify_callback(int ok, X509_STORE_CTX *store);
static long post_connection_check(SSL *ssl, char *host);
static void handle_error(const char *file, int lineno, char *msg);
static int init_OpenSSL(void);
static SSL_CTX *setup_client_ctx(char *cafile);
static SSL_CTX	*setup_server_ctx(char *caertfile,char *privfile);


static TLS_CALLBACK_T	callback=NULL;
static BIO	*server_bio=NULL;
static SSL_CTX	*server_ctx=NULL;
static SSL_CTX	*client_ctx=NULL;
static pthread_mutex_t table_lock;
static pthread_mutex_t *lock_cs;
static int	shutdown_flag=0;
//static long *lock_count;

#define err_info(msg)	handle_error(__FILE__,__LINE__,msg)
#define	ERR_MSG	256
/************* MutltiThread*****************/
unsigned long pthreads_thread_id(void);
void pthreads_locking_callback(int mode, int type, const char *file, int line); 
static void thread_cleanup(void);
static int thread_setup(void);
static int thread_create_linux(pthread_t *tid, void *(*entry)(void *), void *arg);


static int err_code;
static char	err_msg[ERR_MSG];
/**
  @brief 乱数初期化
  */
static int seed_prng(void)
{
	unsigned short rand_ret;
	int i;
	srand((unsigned int)time(NULL));
	RAND_poll();
	for(i=1; i<1000; i++){
		rand_ret = rand() % 65536;
		RAND_seed(&rand_ret, sizeof(rand_ret));
		if(RAND_status()!=0) return i;
	}
	return 0;
}
/**
エラーハンドラ
*/
static void handle_error(const char *file, int lineno, char *msg)
{
	unsigned long code;
#ifdef WIN32
	sprintf_s(err_msg,ERR_MSG, "** %s:%i %s\n",file,lineno,msg);
#else
	sprintf(err_msg, "** %s:%i %s\n",file,lineno,msg);
#endif
#ifdef DEBUG
	ERR_print_errors_fp(stdout);
	printf("%s",err_msg);
#endif
	for(;;){
		code=ERR_get_error();
		if(code==0){
			break;
		}
		err_code=code;
	}
	return ;
}
/**
  @brief 全コネクションクローズ
  開設中のすべてのSSLコネクションシャットダウン
  SSLリソースの解放はされません
  */
static void all_clear_SSL(void)
{
	int i;

	for(i=0;i<SERVER_MAX;i++){
		if(server_threads[i].status==ST_ALIVE){
			server_threads[i].status=ST_SHUTDOWN;
			SSL_shutdown(server_threads[i].ssl);
		}
	}
}
/**
  @brief コネクションが開設されたことを登録
  一覧表に新たなSSLコネクションを登録します。
  SSLリソースに変化はありません
  */
static int register_SSL(SSL *ssl)
{
	int i;

	if(0!=pthread_mutex_lock(&table_lock)){
		return -10;
	}
	for(i=0;i<SERVER_MAX;i++){
		if(server_threads[i].status==ST_INVALID){
			server_threads[i].status=ST_ALIVE;
			server_threads[i].ssl=ssl;
			pthread_mutex_unlock(&table_lock);
			return i;
		}
	}
	pthread_mutex_unlock(&table_lock);
	return -20;
}

static void delete_SSL(int key)
{
	pthread_mutex_lock(&table_lock);
	server_threads[key].status=ST_INVALID;
	server_threads[key].ssl=NULL;
	pthread_mutex_unlock(&table_lock);
}

static int  init_OpenSSL(void)
{
	if(!SSL_library_init()){
		err_info("** OpenSSL init failed");
		return -1;
	}
	SSL_load_error_strings();
	return 0;
}

/**************************
 * Failure due to lifetime of certification
 * must be success
 * ************************/

static int verify_callback(int ok, X509_STORE_CTX *store)
{
	int		err;
	//fprintf(stderr,"callbacked verify result=%d\n",ok);
	if(ok==0){//Failed
		err = X509_STORE_CTX_get_error(store);
		if(err==10||err==9){//Certificate Expire(10) or Future valid (9)
			ok=1;
		}
	}
	return ok;
}

/*****************************************
 * Check whether Subject Alt Name of Extension of X509v3 is host 
 * or whether CN is host
 * **************************************/
static long post_connection_check(SSL *ssl, char *host)
{
	X509				*cert;
	X509_NAME			*subj;
	X509_EXTENSION		*ext;
	char				data[256];
	int					i,extcount,ok;
	ASN1_OBJECT			*obj;

	if(host==NULL){
		goto err1;	
	}
	cert=SSL_get_peer_certificate(ssl);
	if(cert==NULL){
		goto err1;
	}

	//Check extension of  the certification
	extcount=X509_get_ext_count(cert);
	for(i=0,ok=0;i<extcount && ok==0;i++){
		ext=X509_get_ext(cert,i);
		obj=X509_EXTENSION_get_object(ext);
		if(obj==NULL){
			continue;
		}
	}//for(i =========================End of cheking  Extension Part
	//Check CN when extension check is failed
	if(ok==0){
		//Extract SUBJECT from cert
		subj=X509_get_subject_name(cert);
		if(subj==NULL){
			goto err1;
		}
		//Extract CommonName from Subject
		if(X509_NAME_get_text_by_NID(subj,NID_commonName,data,200)<=0){
			goto err1;
		}
		data[199]=0;
		if(strcasecmp((const char*)data,(const char*)host)!=0){
	  		printf("8 %s <=> %s\n",data,host);
			goto err1;
		}else{
			//CN matches to host
			ok=1;
		}
	}
	//This location is run only when ok is 1
	X509_free(cert);
	return X509_V_OK;
err1:
	if(cert)
		X509_free(cert);
	return X509_V_ERR_APPLICATION_VERIFICATION;
}

/*Create Client CTX*/
static SSL_CTX *setup_client_ctx(char *cert_file)
{
	SSL_CTX	*ctx;

	ctx=SSL_CTX_new(SSLv23_method());
	if(ctx==NULL) return NULL;
	//Read CA Certification
	if(SSL_CTX_load_verify_locations(ctx, cert_file, NULL)!=1){
		return NULL;
	}
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,verify_callback);
	SSL_CTX_set_verify_depth(ctx,1);

	return ctx;
}
/*Create Server CTX*/
static SSL_CTX	*setup_server_ctx(char *cert_file,char *priv_file)
{
	SSL_CTX	*actx;
	actx=SSL_CTX_new(SSLv23_method());
	if(actx==NULL) {
		err_info("setup_server_ctx is ");
		return NULL;
	}
	//Read Server certification
	if(SSL_CTX_use_certificate_chain_file(actx,cert_file)!=1){
		SSL_CTX_free(actx);
		return NULL;
	}
	//Read private key file
	if(SSL_CTX_use_RSAPrivateKey_file(actx,priv_file,SSL_FILETYPE_PEM)!=1){
		SSL_CTX_free(actx);
		err_info("setup_server_ctx RSA Keyfile invalid");
		return NULL;
	}
	return actx;
}


/********************************************************
 * ブロックインタフェース
 * ******************************************************/
//-----------------------------------------------------------TLS_Init
/**
	@brief OpenSSL初期化
	@return 0 成功
	@return -10 乱数初期化失敗
	@return -20	ミューテックスオブジェクト生成失敗
	@return -30 マルチスレッド化準備失敗

	最初に一度だけ呼び出します。2度目以降の呼び出しは効果を持たず0を返します。
	*/

int TLS_Init(void)
{
	static int init=0;
	int	i;
	
	if(init){
		return 0;
	}
	init_OpenSSL();
	if(0==seed_prng()){
		return -E_TLS-10;
	}
	if(0!=pthread_mutex_init(&table_lock,NULL)){
		return -E_TLS-20;
	}
	if(0!=thread_setup()){
		return -E_TLS-30;
	}
	for(i=0;i<SERVER_MAX;i++)
		server_threads[i].status=ST_INVALID;
	init=1;
	return 0;
}
//-----------------------------------------------------------TLS_Terminate
/**
  OpenSSLライブラリに利用終了
  */
void TLS_Terminate(void)
{
	thread_cleanup();
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}
/**
  SSLコネクションを切断する
  @param ssl(IN) 切断する対象のSSL
  */
//-----------------------------------------------------------TLS_Disconnect
void TLS_Disconnect(SSL *ssl)
{
	if(ssl==NULL) return;
	//pthread_mutex_lock(&ssl_lock);
	if(SSL_get_shutdown(ssl)&& SSL_RECEIVED_SHUTDOWN!=0){
		//Shutdown from peer
		SSL_clear(ssl);
	}else{
		//Shutdown from local
		SSL_shutdown(ssl);
	}
	SSL_free(ssl);
	//pthread_mutex_unlock(&ssl_lock);
	return;
}

#if 0

int TLS_Send_Data(SSL *ssl,char *buf,int len)
{
	int err;
	if(ssl==NULL) return -1;
	err=SSL_write(ssl,buf,len);
	return err;
}
#endif
//-----------------------------------------------------------TLS_Recv_Data
/**
  SSLコネクションからデータを受信する。タイムアウト付
  @param ssl(IN) 対象のSSL
  @param buf(OUT) 受信バッファ
  @param len(IN)  バッファ長
  @param timeout(IN) タイムアウト時間（秒）
  @param reason(OUT) エラー理由 
  @return >0 受信データ長
  @return 0 タイムアウト
  @return <0 エラー
  */
int TLS_Recv_Data(SSL *ssl,char *buf,int len,int timeout,int *reason)
{
	int err;
	int	fd;
	struct timeval tv;
	fd_set rfds;

	if(reason!=NULL){
		*reason=0;
	}
	if(SSL_pending(ssl)>0){
		err=SSL_read(ssl,buf,len);
		if(err<0){
			return -1;
		}
	}
	fd = SSL_get_fd(ssl);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	err= select(fd + 1, &rfds, NULL, NULL, &tv);
	if(err==0){
		//Time Out
		if(reason!=NULL){
			*reason=TLS_RECV_TIMEOUT;
		}
		return 0;
	}else if(err<0){
		return -1;
	}else if(FD_ISSET(fd, &rfds)==0){
		return 0;
	}
	/*
	if((err=SSL_pending(client_ssl))<=0){
		return 0;
	}
	*/
	err=SSL_read(ssl,buf,len);
	if(err<0){
		return -1;
	}
	return err;
}


int TLS_Error(char *msg,int len)
{
	int i;
	i=strlen(err_msg);
	if(i>=len){
#ifdef WIN32
		strncpy_s(msg,len,err_msg,len-1);
#else
		strncpy(msg,err_msg,len-1);
#endif
		msg[len]='\0';
	}else{
#ifdef WIN32
		strcpy_s(msg,len,err_msg);
#else
		strcpy(msg,err_msg);
#endif
	}
	return err_code;
}

void TLS_ClientShutdown(void)
{
	SSL_CTX_free(client_ctx);
	client_ctx=NULL;
}

int TLS_ClientSetup(char *cert_file)
{
#ifdef DEBUG
	printf("Client Server\n");
#endif
	SSL_CTX		*ctx;
	if(client_ctx!=NULL){
		return -100;
	}
	ctx=setup_client_ctx(cert_file);
	if(ctx==NULL){
		err_info("setup_client_ctx");
		return -200;
	}
	client_ctx=ctx;
	return 0;
}
/**********************************
 * Connect to TLS Server
 * ********************************/

SSL *TLS_Connect(char *host,int port,int *reason)
{
	BIO *conn;
	int i;
	long	err;
	char	hostport[64];
	SSL		*ssl;

	memset(err_msg,0,ERR_MSG);
	err_code=0;
	if(reason!=NULL){
		*reason=0;
	}
	if(client_ctx==NULL){
		*reason=-200;
		return NULL;
	}
#ifdef WIN32
	sprintf_s(hostport,64,"%s:%d",host,port);
#else
	sprintf(hostport,"%s:%d",host,port);
#endif
	conn=BIO_new_connect(hostport);
	if(!conn){
		err_info("BIO_new_connect");
		if(reason!=NULL){
			*reason=-300;
		}
		return NULL;
	}
	if(BIO_do_connect(conn)<=0){
		err_info("BIO_do_connect");
		if(reason!=NULL){
			*reason=-400;
		}
		return NULL;
	}
	if(!(ssl=SSL_new(client_ctx))){
		err_info("SSL_new");
		if(reason!=NULL){
			*reason=-500;
		}
		return NULL;
	}
	SSL_set_bio(ssl,conn,conn);
	if((i=SSL_connect(ssl))<=0){
		err_info("SSL_connect");
		SSL_free(ssl);
		if(reason!=NULL){
			*reason=-600;
		}
		return NULL;
	}
	//Validation of Server Cert
	err=post_connection_check(ssl,SERVERNAME);
	if(err!=X509_V_OK){
		SSL_shutdown(ssl);
		SSL_free(ssl);
		err_info("post_connection_check");
		//ERR_remove_state(0);
		if(reason!=NULL){
			*reason=-700;
		}
		return NULL;
	}
	return ssl;
}

/***************************************************************/


static void ConvertIP4(char *ptr,char *buff)
{
	int i;
	char    tmp[16];
	*buff='\0';

	for(i=0;i<4;i++){
		sprintf(tmp,"%u",(unsigned char)ptr[i]);
		strcat(buff,tmp);
		if(i!=3){
			strcat(buff,".");
		}
	}
}


static int BIO_get_peer_info(BIO *bio,char *ip,int *port)
{
	int sd;
	struct sockaddr_in addr;
	socklen_t len;
	len=sizeof(struct sockaddr_in);

	if(BIO_get_fd(bio,&sd)==-1) return -1;
	getpeername(sd,(struct sockaddr *)&addr,&len);
	ConvertIP4((char *)&addr.sin_addr,ip);
	*port=ntohs(addr.sin_port);
	return 0;
}


static void  THREAD_CC serverwork_thread(void *arg)
{
	int port;
	BIO *bio;
	SSL	*ssl;
	char	ip[32];
	int	key;
#ifdef DEBUG
	printf("New Server Work Thread\n");
#endif
#ifndef WIN32
	//detach
	pthread_detach(pthread_self());
	stat.accepted++;
#endif
	if((bio=(BIO *)arg)==NULL){
		err_info("BIO Parameter Error");
		goto err2;
	}
	if(!(ssl=SSL_new(server_ctx))){
		err_info("server context already invalid");
		goto err2; 
	}

	SSL_set_bio(ssl,bio,bio);
	BIO_get_peer_info(bio,ip,&port);
#ifdef DEBUG
	//printf("IP:%s\n",ip);
	//printf("PORT:%d\n",port);
#endif
	if((key=register_SSL(ssl))<0){
		err_info("Too much serverwork_therads");
		SSL_shutdown(ssl);
		stat.too_many_error++;
		goto err;
	}
	if(SSL_accept(ssl)>0){
#ifdef DEBUG
		printf("SSL connect opened\n");
#endif
		if(callback!=NULL){
			stat.callbacked++;
			(*callback)(ssl,ip,port);
		}
	}else{
		stat.accept_error2++;
	}
	SSL_clear(ssl);
err:
	SSL_free(ssl);
	delete_SSL(key);
err2:
	//ERR_remove_state(0);//against Memory Leak 
#ifdef DEBUG
//	printf("SSL Thread Ends\n");
//	fflush(stdout);
#endif
#ifdef WIN32
	_endthread();
	return ;
#else
	return NULL;
#endif
}

static void *ssl_main_thread(void *p)
{

	BIO	*peer;
	THREAD_TYPE	tid;
	int	ret=0;
	pthread_detach(pthread_self());
#ifdef DEBUG
	printf("New Main Server Thread\n");
#endif
	for(shutdown_flag=0;shutdown_flag==0;){
		if((ret=BIO_do_accept(server_bio))<=0){
#ifdef DEBUG
			printf("BIO_do_accept returned negative %d \n",ret);
#endif
			err_info("BIO_do_accept");
			stat.accept_error++;
			sleep(1);
			continue;
		}
		peer=BIO_pop(server_bio);
		/*
		if(BIO_do_handshake(peer)<=0){
			err_info("BIO_do_handshake in server main");
		}
		*/
		if(0!=(ret=THREAD_CREATE(tid,serverwork_thread,peer))){
#ifdef DEBUG
			printf("Thread Create Failed ret=%d\n",ret);
#endif
			stat.thread_error++;
			BIO_free_all(peer);
		}
	}
#ifdef DEBUG
	printf("main thread shutdown\n");
#endif
	SSL_CTX_free(server_ctx);
	server_ctx=NULL;
	BIO_free_all(server_bio);
	server_bio=NULL;
	callback=NULL;
	return NULL;
}

/***************************************************
 * TLS Server parameters settings
 * Call this function on the main thread which has stdio 
 * because of input pass phrase of server_cert
**************************************************/
int TLS_ServerSetup(int port,char *cert,char *priv,TLS_CALLBACK_T tls_callback)
{
	char	localport[16];
	SSL_CTX	*actx;
	BIO		*abio;

#ifdef DEBUG
	printf("Setup  Server\n");
#endif
	if(port==0) port=PORT;
	sprintf(localport,"%d",port);
	if(tls_callback==NULL||cert==NULL||priv==NULL){
		return -10;
	}
	if(server_ctx!=NULL||server_bio!=NULL){
		return -15;
	}
	actx=setup_server_ctx(cert,priv);
	if(!actx){
		return -20;
	}
	abio=BIO_new_accept(localport);
	if(!abio){
		SSL_CTX_free(actx);
		return -30;	
	}
	//the 1st time of do_accept is non blocking
	if(BIO_do_accept(abio)<0){
		SSL_CTX_free(actx);
		BIO_free(abio);
		err_info("BIO_do_accept");
		return -40;	
	}
	server_ctx=actx;
	server_bio=abio;
	callback=tls_callback;
	return 0;
}
/**************************************************
 待ちうけスレッドを生成してSSLをスタートさせる
 デーモン化する場合に、メインプロセスから呼び出すと
 待ち受けスレッドが親プロセスとともに消滅する。
 このために、子プロセスから呼ぶこと
 *************************************************/
int TLS_ServerStart(void)
{
	THREAD_TYPE	tid;

	if( server_ctx==NULL|| server_bio==NULL|| callback==NULL){
		return -100;
	}
	memset(&stat,0,sizeof(STAT));
//	if(0!=THREAD_CREATE(tid, ssl_main_thread, NULL)){
	if(0!=pthread_create(&tid, NULL,ssl_main_thread, NULL)){
		SSL_CTX_free(server_ctx);
		server_ctx=NULL;
		BIO_free(server_bio);
		server_bio=NULL;
		callback=NULL;
		return -110;
	}
	return 0;
}

void TLS_ServerShutdown(void)
{
	if( server_ctx==NULL|| server_bio==NULL|| callback==NULL)
		return;
	all_clear_SSL();
	BIO_reset(server_bio);
	shutdown_flag=1;
	sleep(2);
}	

int TLS_Status(STAT *p)
{
	int i;

	if( server_ctx==NULL|| server_bio==NULL|| callback==NULL){
#ifdef DEBUG
		printf("main thread shutdown\n");
#endif
		stat.active=0;
	}else{
		stat.active=1;
	}
	stat.shutdown=0;
	for(i=0;i<SERVER_MAX;i++){
		if(server_threads[i].status==ST_ALIVE){
			stat.active++;
		}else if(server_threads[i].status==ST_SHUTDOWN){
			stat.shutdown++;
		}
	}
#ifdef DEBUG
	//printf("Active=%d Shutdown=%d\n",stat.active,stat.shutdown);
#endif
	memcpy(p,&stat,sizeof(STAT));
	return stat.active + stat.shutdown;
}


/************************************
 * Mutithreading Facilities         *
 * **********************************/
unsigned long pthreads_thread_id(void)
{
	return(unsigned long)pthread_self();
}
void pthreads_locking_callback(int mode, int type, 
					const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
	} else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}
static int thread_setup(void)
 {
	int i;
	int n;
 	n=CRYPTO_num_locks();
	lock_cs=OPENSSL_malloc(n*sizeof(pthread_mutex_t));
	if(lock_cs==NULL){
		return -1;
	}
	for (i=0; i<n; i++){
		pthread_mutex_init(&(lock_cs[i]),NULL);
	}
	CRYPTO_set_id_callback(pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
	return 0;
}

static void thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
}

static int thread_create_linux(pthread_t *tid, void *(*entry)(void *), void *arg)
{
	pthread_attr_t	attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr,STACK_SIZE);
	return pthread_create(tid,&attr,entry,arg);
}



