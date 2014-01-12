
#ifndef __HAVE_LIB_H
#define __HAVE_LIB_H

#define LISP

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/select.h>
#include <signal.h>
#include <netdb.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/errno.h>

#include "radix/db.h"
#include "radix/db_table.h"
#include "radix/db_prefix.h"
#include "list/list.h"
#include "db.h"

#define	TRUE	1
#define	FALSE	0

#define BSIZE   2048
#define	OUTPUT_STREAM stdout	

/* referral action types */
#define	LISP_REFERRAL_NODE_REFERRAL	 0x0
#define	LISP_REFERRAL_MS_REFERRAL	 0x1
#define	LISP_REFERRAL_MS_ACK		 0x2
#define	LISP_REFERRAL_MS_NOT_REGISTERED	 0x3
#define	LISP_REFERRAL_DELEGATION_HOLE	 0x4
#define	LISP_REFERRAL_NOTE_AUTHORITATIVE 0x5

char * listening_address[2];	/* IPv4 address on which the server
					   listen */

union sockunion {
	struct  sockaddr sa;
	struct  sockaddr_in sin;
	struct  sockaddr_in6 sin6;
	struct  sockaddr_storage ss;
};

struct mapping_flags{
	uint16_t act:3,			/* Action bit */
		 A:1,			/* Authoritative bit */
		 version:12,		/* Version */
		 proxy:1;			/*Proxy-map-reply*/
	uint32_t ttl;			/* TTL */
	uint8_t referral:4;		/* Is referral */
	uint8_t incomplete:1;		/* incomplete DDT entry */
};
struct map_entry{
	union sockunion rloc;		/* RLOC address */
	uint8_t priority;		/* priority */
	uint8_t weight;			/* weight */
	uint8_t m_priority;		/* multicast priority */
	uint8_t m_weight;		/* multicast weight */
	uint8_t L:1,			/* Local locator */
		p:1,			/* RLOC-probing locator */
		r:1;			/* reachability bit */
};

struct stack_t{
	struct list_t stack;
	struct list_entry_t * curs;
};

	struct list_entry_t *
stack_push(struct stack_t * stk, struct list_entry_t * entry);

struct lisp_data{
	struct prefix eid_prefix;
	union sockunion itr_address;	
	uint64_t next_nonce; //nonce for next map-request
	uint8_t step; //steps of recur
	struct stack_t hops; //stack of next node to send map-request	
};

struct pk_req_entry{
	uint8_t emc:1;		/*Encapsulate Message Control*/
	uint8_t ddt:1;		/*Encapsulate Message Control*/
	uint8_t type;  	/*type of lisp message*/
	uint32_t nonce0; //nonce in map-request with ddt
	uint32_t nonce1; //nonce in map-request with ddt
	void * buf; /*package content */
	uint16_t buf_len; /*package len */
	union sockunion  si;
	struct lisp_data ldata;
};

struct pk_rpl_entry{
	void * buf; /*package content */
	uint16_t buf_len;
	void * curs;
	uint32_t request_id;
};

struct ms_entry {
	union sockunion addr;
	char * key;
};

/* communication abstraction */
struct communication_fct {
        /* communication management */
        void * (*start_communication)(void * context);
        void * (*stop_communication)(void * context);

        /* Map-Reply */
	/* create a new reply
	   @param nonce nonce of the reply
	   @return a identifier for the reply
	*/
        int (*reply_add)(uint32_t id);
	/* start a new record for the reply
	   @param id reply identifier
	   @return TRUE on success, otherwise a FALSE is returned
	 */
        int (*reply_add_record)(uint32_t id, struct prefix * p, uint32_t ttl, uint8_t lcount, uint32_t version, uint8_t A, uint8_t act);
	/* add a locator to the current record
	   @param id reply identifier
	   @param e map-entry information (locator, priority...)
	   @return TRUE on success, otherwise a FALSE is returned
	 */
        int (*reply_add_locator)(uint32_t id, struct map_entry * e);
	/* something wrong happened */
        int (*reply_error)(uint32_t id);
	/* Indicates that the reply construction is finished, post-processing
	   can be started */
        int (*reply_terminate)(uint32_t id);

        /* Map-Referral */
	/* create a new referral
	   @param nonce nonce of the referral
	   @return a identifier for the referral
	*/
        int (*referral_add)(uint32_t id);
	/* start a new record for the referral
	   @param id referral identifier
	   @return TRUE on success, otherwise a FALSE is returned
	 */
        int (*referral_add_record)(uint32_t id, struct prefix * p, uint32_t ttl, uint8_t lcount, uint32_t version, uint8_t A, uint8_t act, uint8_t i, uint8_t sigcnt);
	/* add a locator to the current record
	   @param id referral identifier
	   @param e map-entry information (locator, priority...)
	   @return TRUE on success, otherwise a FALSE is returned
	 */
        int (*referral_add_locator)(uint32_t id, struct map_entry * e);
	/* something wrong happened */
        int (*referral_error)(uint32_t id);
	/* Indicates that the referral construction is finished, post-processing
	   can be started */
        int (*referral_terminate)(uint32_t id);
        /* Map-Request */
	/* Obtain the EID associated to the request. p is set to the EID found
	   in the request
	   @param id request identifier
	   @param p eid prefix in the request
	   @return TRUE on success, otherwise a FALSE is returned
	 */
        int (*request_get_eid)(uint32_t id, struct prefix * p);
	/* Obtain the nonce associated to the request. nonce is set to the
	   nonce found in the request
	   @param id request identifier
	   @param nonce nonce in the request
	   @return TRUE on success, otherwise a FALSE is returned
	   XXX nonce is given in network byte order
	 */
        int (*request_get_nonce)(uint32_t id, uint64_t * nonce);
	int (*request_is_ddt)(uint32_t id, int * is_ddt);
	/* Obtain a source ITR address of the request
	   @param id request identifier
	   @param itr ITR address in the request
	   @return TRUE on success, otherwise a FALSE is returned
	 */
	int (*request_get_itr)(uint32_t id, union sockunion * itr);
	/* Obtain the UDP source port from the Map-Request
	   @param id request identifier
	   @param port port of the request
	   @return TRUE on success, otherwise a FALSE is returned
	 */
	int (*request_get_port)(uint32_t id, uint16_t * port);
	int (*request_add)(uint32_t id, uint8_t security, uint8_t ddt,\
			uint8_t A, uint8_t M, uint8_t P, uint8_t S,\
			uint8_t p, uint8_t s,\
			uint32_t nonce0, uint32_t nonce1,\
			const union sockunion * src, \
			const union sockunion * dst, \
			uint16_t source_port,\
			const struct prefix * eid );
	/* Indicates that the request has been processed completely */
        int (*request_terminate)(uint32_t id);
	/* Indicates that the DDT request construction is finished,
	   post-processing can be started 
	   @param id request identifier
	   @param server server where to send the DDT request
	   return TRUE on success, otherwise a FALSE is returned
	 */
	int (*request_ddt_terminate)(uint32_t id, const union sockunion * server, char terminal);
};
/* ! communication abstraction */

int generic_process_request(uint32_t request_id, struct communication_fct * fct);
void * generic_mapping_new(struct prefix * eid);
int generic_mapping_set_flags(void * mapping, const struct mapping_flags * mflags);
int generic_mapping_add_rloc(void * mapping, struct map_entry * entry);
int xtr_generic_process_request(uint32_t request_id, struct communication_fct * fct);

char * sk_get_ip(union sockunion * sk, char * ip);
int sk_get_port(union sockunion * sk);
void sk_set_ip(union sockunion * sk, char * ip);
void sk_set_port(union sockunion * sk, int port);
void reconfigure(int signum);


struct db_table * table;
char ip[INET6_ADDRSTRLEN];
char * config_file[4];


#define _FNC_XTR 	1
#define _FNC_MS		2
#define _FNC_MR		4
#define _FNC_NODE 	8

u_char _fncs;
#endif
