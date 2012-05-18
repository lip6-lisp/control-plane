/* 
 *	map_register_reply.c --
 * 
 *	map_register_reply -- OpenLISP control-plane 
 *
 *	Copyright (c) 2012 LIP6 <http://www.lisp.ipv6.lip6.fr>
 *	Base on <Lig code> copyright by David Meyer <dmm@1-4-5.net>
 *	Base on <OpenLisp code> copyright by OpenLisp Project <openlisp.org>
 *	All rights reserved.
 *
 *	LIP6
 *	http://www.lisp.ipv6.lip6.fr
 *
 *Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     o Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the University nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *
 */


#include	"map_register_reply.h"
#include    <pthread.h>


/*
 *	globals
 */
void * mapreply(void *d);
void * send_map_register(void *threadarg);
void make_nonce(unsigned int *, unsigned int *);
void hexout(unsigned char *, int );
void * openlisp(void *threadarg);
static int seq;

int main(int argc, char *argv[])
{
    
    struct map_db params;
	getparameters_reg(&params, 0);
	//openlisp(&params);
	//exit;

	int		s,s6;	
	struct	map_register_data map_register_data;
	struct	map_reply_data map_reply_data;
	struct	map_reply_data map_reply_data6;

	pthread_t thread[4];
  	
  	struct addrinfo	    hints;
    struct addrinfo	    *res;
    struct protoent	    *proto;
  
	make_nonce(&map_register_data.nonce0, &map_register_data.nonce1);

    int i	= 0;		/* generic counter */
    int rc ,rc1, rc2, rc3; //Used for returning the handle for thread creation
        
    emr_inner_src_port	= 0;		
    char  emr_inner_src_port_str[NI_MAXSERV];

    int e		= 0;
    
    //Prepare sockets 
    if ((proto = getprotobyname("UDP")) == NULL) {
		perror ("getprotobyname");
		exit(BAD);
    }

    if ((s = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) {
		perror("SOCK_DGRAM (s)");
		exit(1);
    }

    if ((s6 = socket(AF_INET6,SOCK_DGRAM,proto->p_proto)) < 0) {
		perror("SOCK_DGRAM (s)");
		exit(1);
    }

	
	//Get source ip address, save in my_addr   		
	//Port 4342 for LISP map register  and map reply	
	emr_inner_src_port = LISP_CONTROL_PORT;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = proto->p_proto;

	sprintf(emr_inner_src_port_str, "%d", emr_inner_src_port);

	if ((e = getaddrinfo(NULL, emr_inner_src_port_str, &hints, &res)) != 0) {
		fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(BAD);
	}
	//Bind the socket to 4342 and the internet interface 
	if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
		perror("bind");
		exit(BAD);
	}

	map_register_data.register_socket=s;
	map_reply_data.sk=s;
	map_reply_data6.sk=s;
	freeaddrinfo(res);
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET6;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = proto->p_proto;

	if ((e = getaddrinfo(NULL, emr_inner_src_port_str, &hints, &res)) != 0) {
		fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(BAD);
	}
	//Bind the socket to 4342 and the internet interface 
	if (bind(s6, res->ai_addr, res->ai_addrlen) == -1) {
		perror("bind");
		exit(BAD);
	}

	map_register_data.register_socket6=s6;
	map_reply_data.sk6=s6;
	map_reply_data6.sk6=s6;

	freeaddrinfo(res);

	//Creating two thread, one to send register message and one to reply with request mapping
	map_reply_data.l_sk=s;
	map_reply_data6.l_sk=s6;

	//Map reply thread
	rc1=pthread_create( &(thread[1]), NULL, mapreply,(void *)&map_reply_data );
	if (rc1){
	   printf("ERROR; return code from pthread_create() is %d\n", rc1);
	  exit(-1);
	} 
	
	rc2=pthread_create( &(thread[2]), NULL, mapreply,(void *)&map_reply_data6 );
	if (rc2){
	   printf("ERROR; return code from pthread_create() is %d\n", rc3);
	  exit(-1);
	}

	rc3=pthread_create( &(thread[3]), NULL, openlisp,(void *)&params );

   	if (rc3){
		printf("ERROR; return code from pthread_create() is %d\n", rc3);
		exit(-1);
	}

	//Map register thread	
	while(1){    

		rc=pthread_create( &(thread[0]), NULL, send_map_register, (void *)&map_register_data );
		if (rc){
			printf("ERROR; return code from pthread_create() is %d\n", rc);
	        exit(-1);
		}
		pthread_join(thread[0], NULL);
		
		sleep (45); //send map-register every X seconds
	}
    
    
	
	pthread_join(thread[1], NULL);
	pthread_join(thread[2], NULL);
	pthread_join(thread[3], NULL);
    printf ("Main: Waited on thread %d.\n", i);
  
	
	pthread_exit(NULL);
	exit(GOOD);
}

//
//make sockaddr from subnet mask: /24 --> 255.255.255.0
//

void * mask2ip(int masklen, int ipv, struct addrinfo **res){

	char ip_str[INET6_ADDRSTRLEN];
	char *tmp, *ptr;
	unsigned char t;
	int iplen = (ipv == AF_INET)?4:16;
	tmp = (char *) malloc(iplen);
	memset(tmp,0,iplen);
	if(masklen % 8 ==0)
			memset(tmp,255,masklen / 8);
	else
			memset(tmp,255, (masklen / 8)+1);
	ptr = tmp;
	ptr = (char *)tmp + (masklen / 8);
	t = *ptr;
	t = t << (8-(masklen % 8));
	*ptr = t;

	inet_ntop(ipv, tmp, ip_str, INET6_ADDRSTRLEN);
	ip2sockaddr(ip_str, res, NULL);

	return 0;
}

//
//Add mapping to database of openlisp
//

void add_eid(int s, void *params, int db){
	
	struct eid_rloc_db * data_ptr = params;
	struct openlisp_mapmsg m_mapmsg;
	struct rloc_mtx rloc_mtx;
	uint8_t pkt_len, rlen;
	char *ptr;
	struct addrinfo *res;
	struct rloc_db * rloc = data_ptr->rloc;
	int t_len;

	memset(&m_mapmsg,0,8192+sizeof(struct map_msghdr));
	m_mapmsg.m_map.map_version = MAPM_VERSION;
	m_mapmsg.m_map.map_type =  MAPM_ADD;      
	m_mapmsg.m_map.map_flags = (db == 1? MAPF_DB: 0) | MAPF_STATIC | MAPF_UP; 
	m_mapmsg.m_map.map_addrs = MAPA_EID | MAPA_EIDMASK | MAPA_RLOC;
	m_mapmsg.m_map.map_pid = getpid();
	m_mapmsg.m_map.map_versioning = 0;
	m_mapmsg.m_map.map_errno = 0;
	
	ptr = m_mapmsg.m_space;


	m_mapmsg.m_map.map_seq = ++seq;

	pkt_len = sizeof(struct	map_msghdr);
	t_len =  SA_LEN(data_ptr->ed_ip.ss_family);
		
	memcpy(ptr, &(data_ptr->ed_ip), t_len);
	ptr = CO(ptr, t_len);
	pkt_len += t_len;
	mask2ip(data_ptr->eidlen, data_ptr->ed_ip.ss_family,&res); 
	memcpy(ptr, res->ai_addr, t_len);
	ptr = CO(ptr, t_len);
	pkt_len += t_len;
	m_mapmsg.m_map.map_rloc_count = 0;
	while (rloc != NULL) {
		t_len = SA_LEN(rloc->rl_ip.ss_family);
		memcpy(ptr, &rloc->rl_ip,t_len);
		ptr = CO(ptr, t_len);
		pkt_len += t_len;
		
		memset(&rloc_mtx,0,sizeof(struct rloc_mtx));
		rloc_mtx.priority	= rloc->priority;
		rloc_mtx.weight		= rloc->weight;
		rloc_mtx.flags		= 1;
		rloc_mtx.mtu		= 0;
		memcpy(ptr, &rloc_mtx, sizeof(struct rloc_mtx));
		ptr = CO(ptr, sizeof(struct rloc_mtx));
		pkt_len += sizeof(struct rloc_mtx);

		m_mapmsg.m_map.map_rloc_count = m_mapmsg.m_map.map_rloc_count+1;
		rloc = rloc->rl_next;
	}

	m_mapmsg.m_map.map_msglen = pkt_len;

	if ((rlen = write(s, (char *)&m_mapmsg, pkt_len)) < 0) {
		if (errno == EPERM)
			err(1, "writing to mapping socket");
		warn("writing to mapping socket");
		return;
	}
}

//
//Delete a mapping from Openlisp database
//

void del_eid(int s, void *params, int db){
	
	struct eid_rloc_db * data_ptr = params;
	struct openlisp_mapmsg m_mapmsg;

	char *ptr;
	struct addrinfo *res;
	int t_len,pkt_len, rlen;

	m_mapmsg.m_map.map_version = MAPM_VERSION;
	m_mapmsg.m_map.map_type =  MAPM_DELETE;      
	m_mapmsg.m_map.map_flags = (db == 1? MAPF_DB:0) | MAPF_STATIC | MAPF_UP; 
	m_mapmsg.m_map.map_addrs = MAPA_EID | MAPA_EIDMASK;
	m_mapmsg.m_map.map_pid = getpid();
	
	ptr = m_mapmsg.m_space;
	memset(ptr,0,8192);
	m_mapmsg.m_map.map_seq = ++seq;

	pkt_len = sizeof(struct	map_msghdr);
	t_len =  SA_LEN(data_ptr->ed_ip.ss_family);
		
	memcpy(ptr, &(data_ptr->ed_ip), t_len);
	ptr = CO(ptr, t_len);
	pkt_len += t_len;
	mask2ip(data_ptr->eidlen, data_ptr->ed_ip.ss_family,&res); 
	memcpy(ptr, res->ai_addr, t_len);
	ptr = CO(ptr, t_len);
	pkt_len += t_len;
	
	m_mapmsg.m_map.map_rloc_count = 0;
	
	m_mapmsg.m_map.map_msglen = pkt_len;
	
	if ((rlen = write(s, (char *)&m_mapmsg, pkt_len)) < 0) {
		if (errno == EPERM)
			err(1, "writing to mapping socket");
		warn("writing to mapping socket");
		return;
	};
}

//
//Read a mapping from Openlisp database
//

void get_eid(int s, void *params){
	
	struct eid_rloc_db * data_ptr = params;
	struct openlisp_mapmsg m_mapmsg;

	char *ptr;
	struct addrinfo *res;
	int t_len,pkt_len, rlen;
	int cseq;
	int pid;

	m_mapmsg.m_map.map_version = MAPM_VERSION;
	m_mapmsg.m_map.map_type =  MAPM_GET;      
	m_mapmsg.m_map.map_flags = MAPF_DB | MAPF_STATIC | MAPF_UP; 
	m_mapmsg.m_map.map_addrs = (data_ptr->eidlen > 0)?MAPA_EID | MAPA_EIDMASK: MAPA_EID;
	m_mapmsg.m_map.map_pid = pid = getpid();
	
	ptr = m_mapmsg.m_space;
	memset(ptr,0,8192);
	m_mapmsg.m_map.map_seq = cseq = ++seq;
	
	pkt_len = sizeof(struct	map_msghdr);
	t_len =  (data_ptr->ed_ip.ss_family == AF_INET)?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);
		
	memcpy(ptr, &(data_ptr->ed_ip), t_len);
	ptr = CO(ptr, t_len);
	pkt_len += t_len;
	if ((data_ptr->eidlen > 0)) {
		mask2ip(data_ptr->eidlen, data_ptr->ed_ip.ss_family,&res); 
		memcpy(ptr, res->ai_addr, t_len);
		ptr = CO(ptr, t_len);
		pkt_len += t_len;
	}
	
	m_mapmsg.m_map.map_rloc_count = 0;
	
	m_mapmsg.m_map.map_msglen = pkt_len;
	
	if ((rlen = write(s, (char *)&m_mapmsg, pkt_len)) < 0) {
		if (errno == EPERM)
			err(1, "writing to mapping socket");
		warn("writing to mapping socket");
		return;
	};

	do {
		rlen = read(s, (char *)&m_mapmsg, sizeof(m_mapmsg));
	} while (rlen > 0 && (m_mapmsg.m_map.map_seq != cseq || m_mapmsg.m_map.map_pid != pid));
	
	if (rlen < 0){
		perror("Read from mapping socket");
		return;
	}
	
}


//
//Main function of thread which intergrate with OpenLisp
//

struct eid_lookup lookups[MAX_LOOKUPS];

struct pollfd [MAX_LOOKUPS + 1];
int fds_idx[MAX_LOOKUPS +1];
nfds_t nfds = 0;
int tx;
int openlispsck;
struct sockaddr_storage my_addr;
struct sockaddr_storage map_resolver;
struct protoent	    *proto;
int udpproto;
int count   = COUNT;
int timeout = MAP_REPLY_TIMEOUT;

/* res = x - y */
int timespec_subtract(res, x, y)
     struct timespec *res, *x, *y;
{
    /* perform the carry for the later subtraction by updating y */
    if (x->tv_nsec < y->tv_nsec) {
        int sec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
        y->tv_nsec -= 1000000000 * sec;
        y->tv_sec += sec;
    }
    if (x->tv_nsec - y->tv_nsec > 1000000000) {
        int sec = (x->tv_nsec - y->tv_nsec) / 1000000000;
        y->tv_nsec += 1000000000 * sec;
        y->tv_sec -= sec;
    }

    res->tv_sec = x->tv_sec - y->tv_sec;
    res->tv_nsec = x->tv_nsec - y->tv_nsec;

    /* return 1 if result is negative */
    return x->tv_sec < y->tv_sec;
}

int check_eid(eid)
    struct sockaddr *eid;
{
    int i;
    for (i = 0; i < MAX_LOOKUPS; i++)
        if (lookups[i].active)
            if (!memcmp(eid, &lookups[i].eid, lookups[i].eid.ss_len))
                return 0;
    return 1;
} /* check_eid() */

void new_lookup(eid)
    struct sockaddr *eid;
{
    int i,e,r;
    uint16_t sport;             /* inner EMR header source port */
    char sport_str[NI_MAXSERV]; /* source port in string format */
    struct addrinfo hints;
    struct addrinfo *res;

    /* Find an inactive slot in the lookup table */
    for (i = 0; i < MAX_LOOKUPS; i++)
        if (!lookups[i].active)
            break;

    if (i >= MAX_LOOKUPS) {
	    return;
    }

    if ((r = socket(map_resolver.ss_family, SOCK_DGRAM, udpproto)) < 0) {
		perror("SOCK_DGRAM (s)");
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family    = map_resolver.ss_family;    /* Bind on AF based on AF of Map-Resolver */
    hints.ai_socktype  = SOCK_DGRAM;                /* Datagram socket */
    hints.ai_flags     = AI_PASSIVE;                /* For wildcard IP address */
    hints.ai_protocol  = udpproto;
    hints.ai_canonname = NULL;
    hints.ai_addr      = NULL;
    hints.ai_next      = NULL;

    e = -1;

	while (e == -1){
		sport = MIN_EPHEMERAL_PORT + random() % (MAX_EPHEMERAL_PORT - MIN_EPHEMERAL_PORT);
		sprintf(sport_str, "%d", sport);
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family    = map_resolver.ss_family; 
		hints.ai_socktype  = SOCK_DGRAM;                
		hints.ai_flags     = AI_PASSIVE;                
		hints.ai_canonname = NULL;
		hints.ai_addr      = NULL;
		hints.ai_next      = NULL;
		
		if ((e = getaddrinfo(NULL, sport_str, &hints, &res)) != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e));	
			e = -1;
			continue;
		}
		
		if ((e = bind(r, res->ai_addr, res->ai_addrlen)) == -1) {
			perror("BIND");				
			e = -1;
		}

		freeaddrinfo(res);
	}

    memcpy(&lookups[i].eid, eid, eid->sa_len);
    lookups[i].rx = r;
    lookups[i].sport = sport;
    clock_gettime(CLOCK_REALTIME, &lookups[i].start);
    lookups[i].count = -1;
    lookups[i].active = 1;
    send_mr(i);
} /* new_lookup() */

static void map_message_handler(void)
{
    struct timespec now;
    char msg[8192];         /* buffer for mapping messages */
    int n = 0;              /* number of bytes received on mapping socket */
    struct sockaddr *eid;

    n = read(openlispsck, msg, 8192);
    clock_gettime(CLOCK_REALTIME, &now);

    if (((struct map_msghdr *)msg)->map_type != MAPM_MISS_EID)
        return;

    eid = (struct sockaddr *)(msg + sizeof(struct map_msghdr));


    if (check_eid(eid)) {
        new_lookup(eid);
    }
} /* map_message_handler() */


int send_mr(idx)
    int idx;
{
    uint32_t nonce0, nonce1;
    struct timeval before;      /* Unused -- only present to avoid breaking the
                                   lig "API" when calling send_map_request() */
    time_t now;
    int cnt;
    struct sockaddr *eid = (struct sockaddr *)&lookups[idx].eid;
	//printf("count = %d-%d\n",lookups[idx].count, count);
    if (lookups[idx].count == count - 1) {
        lookups[idx].active = 0;
        close(lookups[idx].rx);
        return 0;
    }
	
	make_nonce(&nonce0,&nonce1);
    emr_inner_src_port = lookups[idx].sport;

   if (send_map_request(tx, nonce0, nonce1, &before, eid,
                (struct sockaddr *)&map_resolver, (struct sockaddr *)&my_addr,emr_inner_src_port)) {
        return 0;
    } else {
        cnt = ++lookups[idx].count;
        lookups[idx].nonce0[cnt] = nonce0;
        lookups[idx].nonce1[cnt] = nonce1;
    }   
    return 1;
} /* send_mr() */


int read_mr(idx)
    int idx;
{

	int i,j,k;
	int rcvl;
	char reply[4096];
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(struct sockaddr_storage);
	struct map_reply_pkt *map_reply;
	struct map_reply_eidtype *eidtype;
	struct map_reply_loctype *loctype;
	struct rloc_db * rloc;
	void *p;
	char ip[INET6_ADDRSTRLEN];
	struct addrinfo *res;
	struct eid_rloc_db *eid_db, *ptr;
	int nonce0, nonce1;
	i = idx;
	if ((rcvl = recvfrom(lookups[i].rx,
			 reply,
			 MAX_IP_PACKET,
			0,
			(struct sockaddr *)&from,
			&fromlen)) < 0) {
		return;
	}
	
		map_reply = (struct map_reply_pkt *)reply;
	//only accept map-reply
	if (map_reply->lisp_type != LISP_MAP_REPLY) {
		return;
	}
	
	map_reply	= (struct map_reply_pkt *) reply;
	//check nonce
	nonce0 = map_reply->lisp_nonce0;
	nonce1 = map_reply->lisp_nonce1;
	
	for (j = 1;j<=MAX_COUNT ; j++) {
		if (lookups[i].nonce0[j] == nonce0 && lookups[i].nonce1[j] == nonce1)
			return;		
	}

	if (map_reply->record_count <= 0)
		return;

	p = CO(map_reply,sizeof(struct  map_reply_pkt));
	ptr = eid_db = NULL;

	for (j = 0; j < map_reply->record_count; j++){
		if (j == 0) {
			eid_db = malloc(sizeof(struct eid_rloc_db));
			eid_db->ed_next = NULL;
			ptr = eid_db;
		}else{
			ptr->ed_next = malloc(sizeof(struct eid_rloc_db));
			ptr = ptr->ed_next;
			ptr->ed_next = NULL;
		}
		eidtype = (struct map_reply_eidtype *)p;

		//Building the map reply message
		ptr->record_ttl = ntohl(eidtype->record_ttl);
		int afi = ntohs(eidtype->eid_afi) == LISP_AFI_IP? AF_INET:AF_INET6;
		ptr->eidlen = eidtype->eid_mask_len;
		inet_ntop(afi, eidtype->eid_prefix, ip, INET6_ADDRSTRLEN);
		ip2sockaddr(ip, &res, 0);
		memcpy(&ptr->ed_ip, res->ai_addr, SA_LEN(res->ai_family));
		p = CO(p, sizeof(struct map_reply_eidtype)+ IA_LEN(res->ai_family));
		for (k = 0; k < eidtype->loc_count ;k++ ) {
			if (k == 0) {
				rloc = malloc(sizeof(struct rloc_db));
				rloc->rl_next = NULL;
				ptr->rloc = rloc;
			}else{
				rloc->rl_next = malloc(sizeof(struct rloc_db));
				rloc = rloc->rl_next;
				rloc->rl_next = NULL;
			}
			
			loctype = (struct map_reply_loctype *)p;
			rloc->priority = loctype->priority;
			rloc->weight = loctype->weight;
			rloc->local = loctype->reach_bit;
			afi = ntohs(eidtype->eid_afi) == LISP_AFI_IP? AF_INET:AF_INET6;
			inet_ntop(afi,loctype->locator, ip, INET6_ADDRSTRLEN);
			ip2sockaddr(ip, &res, 0);
			memcpy(&rloc->rl_ip, res->ai_addr, SA_LEN(res->ai_family));
			p = CO(p, sizeof(struct map_reply_loctype)+IA_LEN(res->ai_family));
		}
	}//end eid
	ptr = eid_db;
	while (ptr != NULL) {
		add_eid(openlispsck, (void *)ptr, 0);			
		ptr = ptr->ed_next;
	}
	lookups[i].active = 0;
    close(lookups[i].rx);

} /* read_mr() */


static void event_loop(void){

	for (;;) {
        int e, i, j, l = -1;
        int poll_timeout = INFTIM; /* poll() timeout in milliseconds. We initialize
                                   to INFTIM = -1 (infinity). If there are no
                                   active lookups, we wait in poll() until a
                                   mapping socket event is received. */
        struct timespec now, deadline, delta, to, tmp;
	
        to.tv_sec  = timeout;
        to.tv_nsec = 0;

        nfds = 1;

        clock_gettime(CLOCK_REALTIME, &now);

        for (i = 0; i < MAX_LOOKUPS; i++) {
            if (!(lookups[i].active)) continue;

            deadline.tv_sec = lookups[i].start.tv_sec + 
	                      (lookups[i].count +1) * timeout; 
            deadline.tv_nsec = lookups[i].start.tv_nsec;

            timespec_subtract(&delta, &deadline, &now);

            fds[nfds].fd     = lookups[i].rx;
            fds[nfds].events = POLLIN;
            fds_idx[nfds]    = i;
            nfds++;
            /* Find the minimum delta */
            if (timespec_subtract(&tmp, &delta, &to)) {
				//printf("delte = %d-%d\n",delta.tv_sec, to.tv_sec);
                to.tv_sec    = delta.tv_sec;
                to.tv_nsec   = delta.tv_nsec;
                poll_timeout = to.tv_sec * 1000 + to.tv_nsec / 1000000;
                if (to.tv_sec < 0) poll_timeout = 0;
                l = i;
            }
			//printf("poll_timeout = %d\n",poll_timeout);
        } /* Finished iterating through all lookups */
		
		//printf("poll_timeout = %d\n",poll_timeout);

        e = poll(fds, nfds, poll_timeout);
        if (e < 0) continue;
        if (e == 0)                             /* If timeout expires */
            if (l >= 0)                         /* and slot is defined */
	         send_mr(l);                    /* retry Map-Request */

        for (j = nfds - 1; j >= 0; j--) {
            if (fds[j].revents == POLLIN) {
                /*printf("event on fds[%d]\n", j);*/
                if (j == 0)
                    map_message_handler();
                else
                    read_mr(fds_idx[j]);
            }
        }
    }
} /* event_loop() */

//
//Main function of thread with intergrate with OpenLisp
//

void * openlisp(void *threadarg){

	//struct sockaddr_storage  * map_resolver_addr, *my_addr;
	int oplsck, mrsock;
	struct map_db * params = threadarg;
	struct eid_rloc_db *data_ptr;
	data_ptr = params->data;
	struct addrinfo  *res;
	int i;
	pthread_t sthread[3];
	int rc1, rc2, rc3;
	struct thread_params thr_params;

    struct protoent	    *proto;
    if ((proto = getprotobyname("UDP")) == NULL) {
		perror ("getprotobyname");
		exit(BAD);
    }
    udpproto = proto->p_proto;
	oplsck = openlispsck = socket(PF_MAP, SOCK_RAW, 0);

	fds[0].fd = oplsck;
    fds[0].events = POLLIN;
    fds_idx[0] = -1;
    nfds = 1;

	/* Initialize lookups[]: all inactive */
	for (i = 0; i < MAX_LOOKUPS; i++)
        lookups[i].active = 0;

	if (params->mr != NULL) {
		memcpy(&map_resolver,&(params->mr->ms_ip), SA_LEN(params->mr->ms_ip.ss_family));
	}
	else{
		ip2sockaddr("195.50.116.18", &res,  LISP_CONTROL_PORT_STR);
		memcpy(&map_resolver, res->ai_addr, SA_LEN(res->ai_family));
	}

	if (get_saddr(map_resolver.ss_family,&my_addr)) {
		fprintf(stderr, "No usable %s source address\n",
			(map_resolver.ss_family == AF_INET) ? "IPv4" : "IPv6");
		exit(-1);
	}

	thr_params.opl_socket = oplsck;
	
	if ((mrsock = tx =socket(map_resolver.ss_family,SOCK_DGRAM,proto->p_proto)) < 0) {
				perror("SOCK_DGRAM (s)");
				exit;
	}
	thr_params.mr_socket = mrsock;
	thr_params.map_resolver_addr = map_resolver;
	thr_params.my_addr = my_addr;

	//update mapping database
	while (data_ptr != NULL) {
		del_eid(oplsck, data_ptr, 1);
		add_eid(oplsck, data_ptr,1);
		data_ptr = data_ptr->ed_next;
	}	
	//printf("opl_socket = %d\n",thr_params.opl_socket);
	//printf("mr_socket = %d\n",thr_params.mr_socket);
	//hexout(&thr_params.map_resolver_addr, sizeof(struct sockaddr_storage));
	event_loop();
	
  	pthread_exit(NULL);
	return 0;
}

//
//Debug functions
//Print map request message fied by fied
//

void print_map_request(packet, length)
    struct map_request_pkt *packet;
	int length;
{
    printf("\nMap-Request Packet\n");
    printf("==========================\n");
	hexout((unsigned char *)packet,length);
	struct in_addr *tmp;
	struct in6_addr *tmp6;
    struct map_request_pkt *map_request = packet;
	if (((struct lisp_control_pkt *) packet)->type == LISP_ENCAP_CONTROL_TYPE)//Map encapsulated package
	{
		/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 / |                       IPv4 or IPv6 Header                     |
		OH |                      (uses RLOC addresses)                    |
		 \ |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 / |       Source Port = xxxx      |       Dest Port = 4342        |
		UDP+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 \ |           UDP Length          |        UDP Checksum           |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		LH |Type=8 |S|                  Reserved                           |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 / |                       IPv4 or IPv6 Header                     |
		IH |                  (uses RLOC or EID addresses)                 |
		 \ |                                                               |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 / |       Source Port = xxxx      |       Dest Port = yyyy        |
		UDP+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 \ |           UDP Length          |        UDP Checksum           |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		LCM|                      LISP Control Message                     |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		*/
		struct ip			*iph;
		struct ip6_hdr		*iph6;
		struct udphdr		*udph;

		char ip_s[INET6_ADDRSTRLEN];
		char ip_d[INET6_ADDRSTRLEN];
		int port_s;
		int port_d;

		//print source and destionation of Inner Header
		iph = (struct ip *)  CO(map_request,  sizeof(struct lisp_control_pkt));

		int ipversion = iph->ip_v;
		if (ipversion == 4) {
			iph = (struct ip *)  CO(map_request,  sizeof(struct lisp_control_pkt));
			inet_ntop(AF_INET, &(iph->ip_src), ip_s, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(iph->ip_dst), ip_d, INET_ADDRSTRLEN);
		}
		else{
			iph6 = (struct ip6_hdr *)  CO(map_request,  sizeof(struct lisp_control_pkt));
			inet_ntop(AF_INET6, &(iph6->ip6_src), ip_s, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(iph6->ip6_dst), ip_d, INET6_ADDRSTRLEN);
		}
		
		udph		= (struct udphdr *) CO(map_request, sizeof(struct lisp_control_pkt) + ((ipversion == 4)? sizeof(struct ip): sizeof(struct ip6_hdr)) );
		
		port_s = ntohs(udph->uh_sport);
		port_d = ntohs(udph->uh_dport);
		
		map_request = (struct map_request_pkt *)  CO(udph, sizeof(struct udphdr));
		
		printf("**** Encapsulated Control Message****\n");
	    printf("SourceIP \t\t= %s\n",ip_s);
	    printf("DestIP \t\t= %s\n",ip_d);
	    printf("SourcePort \t\t= %d\n",port_s);
	    printf("DestPort \t\t= %d\n",port_d);
		printf("\n");

	}
    printf("lisp_type\t\t= %d\n",map_request->lisp_type);
	printf("auth_bit\t\t= 0x%x\n", map_request->auth_bit);
    printf("map_data_present\t= %d\n",map_request->map_data_present);
    printf("rloc_probet\t\t= %d\n", map_request->rloc_probe);
	printf("smr_bit\t\t\t= %d\n", map_request->smr_bit);
	printf("pitr_bit\t\t\t= %d\n", map_request->pitr_bit);
	printf("smr_invoked\t\t\t= %d\n", map_request->smr_invoked);

    printf("lisp_nonce\t\t= 0x%08x-0x%08x\n",
	   ntohl(map_request->lisp_nonce0), 
	   ntohl(map_request->lisp_nonce1)); 
    printf("irc record_count\t\t= %d\n",map_request->irc);
	printf("record_count\t\t= %d\n",map_request->record_count);
    printf("source_eid_afi\t\t= %d\n",
	   ntohs(map_request->source_eid_afi));
	
	int i;
	void *ptr = CO(map_request, sizeof(struct map_request_pkt) - 2  );
	char ip6[INET6_ADDRSTRLEN]; 

	//Print EID AFI
	if (ntohs(map_request->source_eid_afi) == LISP_AFI_IP ) {
		tmp = (struct in_addr *)&map_request->itr_afi;
		ptr = CO(ptr, sizeof(struct in_addr));
		printf("itr afi - Source EID address\t= %s\n", inet_ntoa(*tmp));
	}
	else if (ntohs(map_request->source_eid_afi) == LISP_AFI_IPV6) {
		tmp6 = (struct in6_addr *)&map_request->itr_afi;
		inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
		printf("itr afi - Source EID address\t= %s\n", ip6);
		ptr = CO(ptr, sizeof(struct in6_addr));
	}
	
	//Print all ITR AFI,must there is at lease 1 ITR AFI
	for (i = 0; i<=map_request->irc; i++ ) {
	
		if (ntohs(*((ushort*)ptr)) == LISP_AFI_IP ) {
			tmp = (struct in_addr *) CO(ptr,2);
			printf("ITR %d: AFI = %d  ITR RLOC = %s\n",i,ntohs(*((ushort*)ptr)), inet_ntoa(*tmp));
			ptr = CO(ptr, sizeof(struct in_addr)+2);
		}
		else if (ntohs(*((ushort*)ptr)) == LISP_AFI_IPV6 ) {
			tmp6 = (struct in6_addr *)CO(ptr,2);
			inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
			printf("ITR %d: AFI = %d  ITR RLOC = %s\n",i,ntohs(*((ushort*)ptr)), ip6);
			ptr = CO(ptr, sizeof(struct in6_addr)+2);
		}
	}

	//Print all EID prefix
	struct	map_request_eid *map_request_eid;
	
	for (i = 0; i<  map_request->record_count; i++ ) {

		map_request_eid = (struct map_request_eid *) ptr;
	    printf("eid_mask_len\t\t= %d\n",map_request_eid->eid_mask_len);
		ptr = CO(ptr,2);
		if (ntohs(map_request_eid->eid_prefix_afi) == LISP_AFI_IP ) {
			tmp = (struct in_addr *)map_request_eid->eid_prefix;
			printf("EID %d: AFI = %d  EID prefix = %s\n",i,ntohs(map_request_eid->eid_prefix_afi), inet_ntoa(*tmp));
			ptr = CO(ptr, sizeof(struct in_addr)+2);
		}
		else if (ntohs(map_request_eid->eid_prefix_afi) == LISP_AFI_IPV6 ) {
			tmp6 = (struct in6_addr *)map_request_eid->eid_prefix;
			inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
			printf("EID %d: AFI = %d   EID prefix = %s\n",i,ntohs(map_request_eid->eid_prefix_afi), ip6);
			ptr = CO(ptr, sizeof(struct in6_addr)+2);
		}
	}
	printf("==========================\n");

}

//
//Print map reply fied by fied
//

void print_map_reply(map_reply, length)
    struct map_reply_pkt *map_reply;
	int length;
{
    printf("\nMap-Reply Packet\n");
    printf("==========================\n");
	hexout((unsigned char *)map_reply,length);


    printf("lisp_type\t\t= %d\n",map_reply->lisp_type);
	printf("rloc_probe\t\t= %d\n", map_reply->rloc_probe);
    printf("echo_nonce_capable\t= %d\n",map_reply->echo_nonce_capable);
    printf("security_bit\t\t= %d\n", map_reply->security_bit);
	printf("record_count\t\t\t= %d\n", map_reply->record_count);
    printf("lisp_nonce\t\t= 0x%08x-0x%08x\n", ntohl(map_reply->lisp_nonce0),  ntohl(map_reply->lisp_nonce1)); 

    struct in_addr *tmp;
	struct in6_addr *tmp6;
	int i,j;
	void *ptr = CO(map_reply, sizeof(struct map_reply_pkt)  );
	char ip6[INET6_ADDRSTRLEN]; 
	struct map_reply_eidtype * map_reply_eidtype;
	struct map_reply_loctype * map_reply_loctype;

	//print all record
	for (i = 0; i < map_reply->record_count ; i++ ) {
		map_reply_eidtype = (struct map_reply_eidtype *) ptr;
		printf("#Recodr%d\n",i);
	    printf("-------------\n");
		printf("record_ttl\t\t\t= %d\n", ntohl(map_reply_eidtype->record_ttl));
		printf("loc_count\t\t\t= %d\n", map_reply_eidtype->loc_count);
		printf("eid_mask_len\t\t\t= %d\n", map_reply_eidtype->eid_mask_len);
		printf("action\t\t\t= %d\n", map_reply_eidtype->action);
		printf("auth_bit\t\t\t= 0x%x\n", map_reply_eidtype->auth_bit);
	    printf("lisp_map_version\t\t= 0x%04x-0x%08x\n", map_reply_eidtype->lisp_map_version1,map_reply_eidtype->lisp_map_version2);
		printf("eid_afi\t\t\t= %d\n", ntohs(map_reply_eidtype->eid_afi));
		ptr = CO(ptr, sizeof(struct map_reply_eidtype));
		if (ntohs(map_reply_eidtype->eid_afi) == LISP_AFI_IP ) {
			tmp = (struct in_addr *)&map_reply_eidtype->eid_prefix;
			ptr = CO(ptr, sizeof(struct in_addr));
			printf("eid_prefix\t= %s\n", inet_ntoa(*tmp));
		}
		else if (ntohs(map_reply_eidtype->eid_afi) == LISP_AFI_IPV6) {
			tmp6 = (struct in6_addr *)&map_reply_eidtype->eid_prefix;
			inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
			printf("eid_prefix\t= %s\n", ip6);
			ptr = CO(ptr, sizeof(struct in6_addr));
		}
		//print rlocs
		for (j = 0; j < map_reply_eidtype->loc_count ; j ++ ) {
			map_reply_loctype = (struct map_reply_loctype *) ptr;
			printf("RLOC %d:\t\t\t", j);
			printf("priority %d\t", map_reply_loctype->priority);
			printf("weight %d\t", map_reply_loctype->weight);
			printf("mpriority %d\t", map_reply_loctype->mpriority);
			printf("mweight %d\t", map_reply_loctype->mweight);
			printf("rloc_local %d\t", map_reply_loctype->rloc_local);
			printf("rloc_prob %d\t", map_reply_loctype->rloc_prob);
			printf("reach_bit %d\t", map_reply_loctype->reach_bit);
			printf("loc_afi %d\t", ntohs(map_reply_loctype->loc_afi));
			ptr = CO(ptr,sizeof(struct map_reply_loctype));
			if (ntohs(map_reply_loctype->loc_afi) == LISP_AFI_IP ) {
				tmp = (struct in_addr *)&map_reply_loctype->locator;
				ptr = CO(ptr, sizeof(struct in_addr));
				printf("locator\t= %s\n", inet_ntoa(*tmp));
			}
			else if (ntohs(map_reply_loctype->loc_afi) == LISP_AFI_IPV6) {
				tmp6 = (struct in6_addr *)&map_reply_loctype->locator;
				inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
				printf("locator\t= %s\n", ip6);
				ptr = CO(ptr, sizeof(struct in6_addr));
			}

		}
	    printf("-------------\n");
	}
	
	printf("==========================\n");
}





//
//Print map register fied by fied
//

void print_map_register(map_register_ptr,length)
    void *map_register_ptr;
	int length;
{
	struct map_register_pkt * map_register;
	map_register = (struct map_register_pkt *)map_register_ptr;

	printf("\nMap-Register Packet\n");
    printf("==========================\n");
	hexout(map_register_ptr,length);

    printf("lisp_type\t\t= %d\n",map_register->lisp_type);
	printf("rloc_probe\t\t= %d\n", map_register->rloc_probe);
    printf("want_map_notify\t= %d\n",map_register->want_map_notify);
    printf("record_count\t\t= %d\n", map_register->record_count);
    printf("lisp_nonce\t\t= 0x%08x-0x%08x\n", ntohl(map_register->lisp_nonce0),  ntohl(map_register->lisp_nonce1)); 
	printf("key_id\t\t\t= %d\n", ntohs(map_register->key_id));
	printf("key_len\t\t\t= %d\n", ntohs(map_register->key_len));
	printf("auth_data\t\t\t=");
	hexout(map_register->auth_data,ntohs(map_register->key_len));

    struct in_addr *tmp;
	struct in6_addr *tmp6;
	int i,j;
	void *ptr = CO(map_register, sizeof(struct map_register_pkt)  );
	char ip6[INET6_ADDRSTRLEN]; 
	struct lisp_map_register_eidtype * map_register_eidtype;
	struct lisp_map_register_loctype * map_register_loctype;

	//print all record
	for (i = 0; i < map_register->record_count ; i++ ) {
		map_register_eidtype = (struct lisp_map_register_eidtype *) ptr;
		printf("#Recodr%d\n",i);
	    printf("-------------\n");
		printf("record_ttl\t\t\t= %d\n", ntohl(map_register_eidtype->record_ttl));
		printf("loc_count\t\t\t= %d\n", map_register_eidtype->loc_count);
		printf("eid_mask_len\t\t\t= %d\n", map_register_eidtype->eid_mask_len);
		printf("action\t\t\t= %d\n", map_register_eidtype->action);
		printf("auth_bit\t\t\t= 0x%x\n", map_register_eidtype->auth_bit);
	    printf("lisp_map_version\t\t= 0x%04x-0x%08x\n", map_register_eidtype->lisp_map_version1,map_register_eidtype->lisp_map_version2);
		printf("eid_afi\t\t\t= %d\n", ntohs(map_register_eidtype->eid_afi));
		ptr = CO(ptr, sizeof(struct lisp_map_register_eidtype));
		if (ntohs(map_register_eidtype->eid_afi) == LISP_AFI_IP ) {
			tmp = (struct in_addr *)&map_register_eidtype->eid_prefix;
			ptr = CO(ptr, sizeof(struct in_addr));
			printf("eid_prefix\t= %s\n", inet_ntoa(*tmp));
		}
		else if (ntohs(map_register_eidtype->eid_afi) == LISP_AFI_IPV6) {
			tmp6 = (struct in6_addr *)&map_register_eidtype->eid_prefix;
			inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
			printf("eid_prefix\t= %s\n", ip6);
			ptr = CO(ptr, sizeof(struct in6_addr));
		}
		//print rlocs
		for (j = 0; j < map_register_eidtype->loc_count ; j ++ ) {
			map_register_loctype = (struct lisp_map_register_loctype *) ptr;

			printf("RLOC %d:\t\t\t", j);
			//printf("addr priority %p\t", &map_register_loctype->priority);
			printf("priority %d\t", map_register_loctype->priority);

			printf("weight %d\t", map_register_loctype->weight);
			printf("mpriority %d\t", map_register_loctype->mpriority);
			printf("mweight %d\t", map_register_loctype->mweight);
			printf("rloc_local %d\t", map_register_loctype->rloc_local);
			printf("rloc_probe %d\t", map_register_loctype->rloc_probe);
			printf("reach_bit %d\t", map_register_loctype->reach_bit);
			printf("loc_afi %d\t", ntohs(map_register_loctype->loc_afi));
			ptr = CO(ptr,sizeof(struct lisp_map_register_loctype));
			if (ntohs(map_register_loctype->loc_afi) == LISP_AFI_IP ) {
				tmp = (struct in_addr *)&map_register_loctype->locator;
				ptr = CO(ptr, sizeof(struct in_addr));
				printf("locator\t= %s\n", inet_ntoa(*tmp));
			}
			else if (ntohs(map_register_loctype->loc_afi) == LISP_AFI_IPV6) {
				tmp6 = (struct in6_addr *)&map_register_loctype->locator;
				inet_ntop(AF_INET6, tmp6, ip6, INET6_ADDRSTRLEN);
				printf("locator\t= %s\n", ip6);
				ptr = CO(ptr, sizeof(struct in6_addr));
			}

		}
	    printf("-------------\n");
	}
	
	printf("==========================\n");
}

//
//Dump as hexa
//
void hexout(unsigned char *data, int datalen) {

	printf("0x");
	while (datalen-- > 0)
		printf("%02x",(unsigned char)*data++);
	printf("\n");
}


//Create nonce by ramdom 

void make_nonce(nonce0,nonce1)
     unsigned int	*nonce0;
     unsigned int	*nonce1;
{
    *nonce0 = random()^random();
    *nonce1 = random()^time(NULL);
}
