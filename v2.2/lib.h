
#ifndef __HAVE_LIB_H
	#define __HAVE_LIB_H
	#define LISP

#include        <stdio.h>
#include        <unistd.h>
#include        <stdlib.h>
#include        <errno.h>
#include        <netdb.h>
#include        <ifaddrs.h>
#include        <strings.h>
#include 		<signal.h>
#include 		<pthread.h>
#include 		<poll.h>
#include		<assert.h>
#include        <sys/types.h>
#include        <sys/param.h>
#include        <sys/socket.h>
#include 		<sys/select.h>
#include        <sys/ioctl.h>
#include 		<sys/uio.h>
#include 		<sys/errno.h>
#include        <netinet/in.h>
#include        <netinet/udp.h>
#include        <netinet/ip.h>
#include        <netinet/ip6.h>
#include        <arpa/inet.h>
#include        <net/if.h>
#include 		<net/route.h>

#include "radix/db.h"
#include "radix/db_table.h"
#include "radix/db_prefix.h"
#include "list/list.h"
#include "hmac/hmac_sha.h"
#include "db.h"
#include "thr_pool/thr_pool.h"

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

#define LISP_CP_PORT 4342

#define _FNC_XTR 	1
#define _FNC_MS		2
#define _FNC_MR		4
#define _FNC_NODE 	8

#define PKMSIZE	4096
#define MTTL 10	//max recuse map-referral

extern u_char _fncs;
extern char * config_file[];
extern struct db_table * table;
int PK_POOL_MAX;
int min_thread;
int max_thread;
int linger_thread;
	
int skfd, skfd6;
struct pollfd _sk[OPEN_MAX];

/* buffer for the current packet */
struct pk_req_entry ** _pk_req_pool;
struct pk_rpl_entry ** _pk_rpl_pool;
int *_pk_work_pool;
struct prefix ** _pk_req_prefix;
//int _pk_req_ttl[PK_POOL_MAX];
char ip[INET6_ADDRSTRLEN];
int pq_cur;
int pq_tail;
int pq_no;
int pr_cur;
int pr_tail;
int pr_no;
pthread_mutex_t pq_lock;
pthread_mutex_t pq_get_lock;
pthread_cond_t pq_cv;
pthread_mutex_t pr_lock;
pthread_mutex_t pr_get_lock;
pthread_cond_t pr_cv;
pthread_mutex_t work_lock;
pthread_cond_t work_cv;
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
        int (*referral_add_record)(uint32_t id, uint32_t iid, struct prefix * p, uint32_t ttl, uint8_t lcount, uint32_t version, uint8_t A, uint8_t act, uint8_t i, uint8_t sigcnt);
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
	int (*request_get_itr)(uint32_t id, union sockunion * itr, int afi);
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
void _make_nonce(uint64_t * nonce);
int _parser_config(const char * filename);
#endif
