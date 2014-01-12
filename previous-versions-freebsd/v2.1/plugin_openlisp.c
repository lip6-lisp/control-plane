
#ifdefine OPENLISP
	#include <net/lisp/lisp.h>
	#include <net/lisp/maptables.h>


#include "lib.h"
#include "udp.h"

#define COUNT		3
#define MIN_COUNT		1
#define	MAX_COUNT		3
#define MAX_LOOKUPS     100 
#define MAP_REPLY_TIMEOUT	2
#define	MIN_EPHEMERAL_PORT	32768
#define	MAX_EPHEMERAL_PORT	65535
#define OUTPUT_ERROR	stderr
#define PSIZE	4089


struct eid_lookup {
    union sockunion eid;/* Destination EID */
    int rx;                     /* Receiving socket */
    uint32_t nonce0[MAX_COUNT]; /* First half of the nonce */
    uint32_t nonce1[MAX_COUNT]; /* Second half of the nonce */
    uint16_t sport;             /* EMR inner header source port */
    struct timespec start;      /* Start time of lookup */
    int count;                  /* Current count of retries */
    uint64_t active;            /* Unique lookup identifier, 0 if inactive */
	union sockunion * mr;					/* Point to mapresolver */
};

struct eid_lookup lookups[MAX_LOOKUPS];
struct pollfd fds[MAX_LOOKUPS + 1];
int fds_idx[MAX_LOOKUPS +1];
nfds_t nfds = 0;
struct protoent	    *proto;
int udpproto;
int maxcount   = COUNT;
int timeout = MAP_REPLY_TIMEOUT;
int seq;

static void map_message_handler(union sockunion * mr);
int check_eid(union sockunion *eid);
void  new_lookup(union sockunion *eid,  union sockunion * mr);
int  send_mr(int idx);
int read_rec(union map_reply_record_generic * rec);
int opl_add(int s, struct db_node * node, int db);
int opl_del(int s, struct db_node * node, int db);
int opl_get(int s, struct db_node * mapp, int db, struct db_node *rs);
int opl_update(int s, struct db_node * node);

	size_t
prefix2sockaddr(struct prefix * p, union sockunion * rs){
	
	switch(p->family){
		case AF_INET:
			rs->sin.sin_family = AF_INET;
			memcpy(&rs->sin.sin_addr, &p->u.prefix4, sizeof(struct in_addr));
			return sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			rs->sin.sin_family = AF_INET6;
			memcpy(&rs->sin6.sin6_addr, &p->u.prefix6, sizeof(struct in6_addr));
			return sizeof(struct sockaddr_in6);
			break;
		default:
			return 0;
	}
}

	size_t
sockaddr2prefix(union sockunion * rs,struct prefix * p){
	
	switch(rs->sa.sa_family){
		case AF_INET:
			p->family = AF_INET;
			memcpy(&p->u.prefix4, &rs->sin.sin_addr, sizeof(struct in_addr));	
			return sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			p->family = AF_INET6;
			memcpy(&p->u.prefix6, &rs->sin6.sin6_addr, sizeof(struct in6_addr));						
			return sizeof(struct sockaddr_in6);
			break;
		default:
			return 0;
	}
}

	size_t
_get_sock_size(union sockunion * eid)
{
	size_t ss_len;
	switch (eid->sa.sa_family)
	{
		case LISP_AFI_IP:
			ss_len = sizeof(struct sockaddr_in);
			break;
		case LISP_AFI_IPV6:
			ss_len = sizeof(struct sockaddr_in6);
			break;
		default:
			fprintf(OUTPUT_ERROR, "AF not support::%d\n",eid->sa.sa_family);
			return -1;
	}
	return ss_len;
}

/*Get a random map-resolver from list */

	union sockunion *
_get_ms()
{
	int nms;
	int rn;
	struct list_entry_t *rt;
	
	nms =xtr_mr->count;
	rn = ((random()^time(NULL) ) % nms)+1;
	rt = &xtr_mr->head;
	while(rt != &xtr_mr->tail && rn--)
		rt = rt->next;
	return ((union sockunion *)rt->data);	
}
/* res = x - y */
	int 
timespec_subtract(struct timespec *res, struct timespec *x, struct timespec *y)
{
    int sec;
	
	/* perform the carry for the later subtraction by updating y */
    if (x->tv_nsec < y->tv_nsec) {
        sec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
        y->tv_nsec -= 1000000000 * sec;
        y->tv_sec += sec;
    }

    if (x->tv_nsec - y->tv_nsec > 1000000000) {
        sec = (x->tv_nsec - y->tv_nsec) / 1000000000;
        y->tv_nsec += 1000000000 * sec;
        y->tv_sec -= sec;
    }

    res->tv_sec = x->tv_sec - y->tv_sec;
    res->tv_nsec = x->tv_nsec - y->tv_nsec;

	/* return 1 if result is negative */
    return x->tv_sec < y->tv_sec;
}

/* Process message from Openlis socket */
	static void 
map_message_handler(union sockunion * mr)
{
    struct timespec now;
    char msg[PSIZE];         /* buffer for mapping messages */
    int n = 0;              /* number of bytes received on mapping socket */
    union sockunion *eid;
	
    n = read(lookups[0].rx, msg, PSIZE);
    clock_gettime(CLOCK_REALTIME, &now);

    if (((struct map_msghdr *)msg)->map_type == MAPM_MISS_EID)
	{
        eid = (union sockunion *)CO(msg,sizeof(struct map_msghdr));
		if (check_eid(eid)){
			new_lookup(eid, mr);
		}
	}
}

/*Check if an EID-prefix exist in poll */
	int 
check_eid(union sockunion *eid)
{
    int i;
	
	for (i = 0; i < MAX_LOOKUPS; i++)
        if (lookups[i].active)
            if (!memcmp(eid, &lookups[i].eid, _get_sock_size(eid)))
                return 0;				
    return 1;
}

/*Add new EID to poll*/
	void 
new_lookup(union sockunion *eid,  union sockunion * mr)
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
	
	/*new socket for map-request */
	if ((r = socket(mr->sa.sa_family, SOCK_DGRAM, udpproto)) < 0) {
		fprintf(OUTPUT_ERROR, "Socket\n");
    }

    /*random source port of map-request */
	e = -1;
	while (e == -1){
		sport = MIN_EPHEMERAL_PORT + random() % (MAX_EPHEMERAL_PORT - MIN_EPHEMERAL_PORT);
		sprintf(sport_str, "%d", sport);
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family    = mr->sa.sa_family; 
		hints.ai_socktype  = SOCK_DGRAM;                
		hints.ai_flags     = AI_PASSIVE;                
		hints.ai_canonname = NULL;
		hints.ai_addr      = NULL;
		hints.ai_next      = NULL;
		
		if ((e = getaddrinfo(NULL, sport_str, &hints, &res)) != 0) {
			fprintf(OUTPUT_ERROR, "getaddrinfo: %s\n", gai_strerror(e));	
			e = -1;
			continue;
		}
		
		if ((e = bind(r, res->ai_addr, res->ai_addrlen)) == -1) {
			fprintf(OUTPUT_ERROR, "bind error to port %s\n", sport_str);
			e = -1;
			continue;
		}
		freeaddrinfo(res);
	}

    memcpy(&lookups[i].eid, eid, _get_sock_size(eid));
    lookups[i].rx = r;
    lookups[i].sport = sport;
    clock_gettime(CLOCK_REALTIME, &lookups[i].start);
    lookups[i].count = 0;
    lookups[i].active = 1;
    lookups[i].mr = mr;
    send_mr(i);
}

/* Send map-request */
	int 
send_mr(int idx)
{
    uint32_t nonce0, nonce1;
    int cnt;
    union sockunion *eid;
	char buf[PSIZE];
	struct lisp_control_hdr * lh;
	struct ip * ih;	
	struct udphdr * udp ;
	struct map_request_hdr * lcm;
	union afi_address_generic * itr_rloc;
	union map_request_record_generic * rec;
	union afi_address_generic afi_addr_src;
	union afi_address_generic afi_addr_dst;
	uint8_t * ptr;
	int sockaddr_len;
	size_t itr_size, ip_len;
	
	
	eid = &lookups[idx].eid;
	if (lookups[idx].count == COUNT) {
        lookups[idx].active = 0;
		close(lookups[idx].rx);
        return 0;
    }
	
	lh = (struct lisp_control_hdr *)buf;
	ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
	
	/*choose source/destionation ip */
	switch (lookups[idx].mr->sa.sa_family ){
		case AF_INET:
			afi_addr_dst.ip.afi = AF_INET;
			memcpy(&afi_addr_dst.ip.address,(struct in_addr *)&(lookups[idx].mr->sin.sin_addr),sizeof(struct in_addr));
			afi_addr_src.ip.afi = AF_INET;
			memcpy(&afi_addr_src.ip.address,(struct in_addr *)(listening_address[0]),sizeof(struct in_addr));
			udp = (struct udphdr *)CO(ih, sizeof(struct ip));
			sockaddr_len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			afi_addr_dst.ip6.afi = AF_INET6;
			memcpy(&afi_addr_dst.ip6.address,(struct in6_addr *)&(lookups[idx].mr->sin6.sin6_addr),sizeof(struct in6_addr));
			afi_addr_src.ip.afi = AF_INET6;
			memcpy(&afi_addr_src.ip6.address,(struct in6_addr *)(listening_address[1]),sizeof(struct in6_addr));
			udp = (struct udphdr *)CO(ih, sizeof(struct ip6_hdr));
			sockaddr_len = sizeof(struct sockaddr_in6);
			break;
		default:
			fprintf(OUTPUT_ERROR,"AF not support\n");
			return -1;
	}
	
	lcm = (struct map_request_hdr*)CO(udp, sizeof(struct udphdr));
	
	
	/*build message header*/
	/* set all the LISP flags  */
	uint64_t nonce;
	_make_nonce(&nonce);
	nonce0 = (uint32_t)(*(uint32_t *)&nonce);
	nonce1 = (uint32_t)(*(uint32_t *)(&nonce0+1));
	lh->type = LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE;
	lh->security_bit = 0;
	lh->ddt_originated = 0;
	lcm->lisp_type = LISP_TYPE_MAP_REQUEST;
	lcm->auth_bit = 1;
	lcm->map_data_present = 0;
	lcm->rloc_probe = 0;
	lcm->smr_bit = 0;
	lcm->pitr_bit = 0;
	lcm->smr_invoke_bit = 0;
	lcm->irc = 0;
	lcm->record_count = 1;
	lcm->lisp_nonce0 = htonl(nonce0);
	lcm->lisp_nonce1 = htonl(nonce1);
	
	/* set no source EID <AFI=0, addres is empty> -> jump of 2 bytes */
	/* nothing to do as bzero of the packet at init */
	itr_rloc = (union afi_address_generic *)CO(lcm, sizeof(struct map_request_hdr) + 2);

	/* set source ITR */
	itr_size = _get_address_size(&afi_addr_src);
	memcpy(itr_rloc, &afi_addr_src, itr_size);
	rec = (union map_request_record_generic *)CO(itr_rloc, itr_size);

	/* assign correctly the EID prefix */
	switch(eid->sa.sa_family){
		case AF_INET:
			/* EID prefix is an IPv4 so 32 bits (4 bytes) */
			rec->record.eid_mask_len = 32;
			rec->record.eid_prefix_afi = htons(LISP_AFI_IP);
            memcpy(&rec->record.eid_prefix, &(eid->sin.sin_addr), sizeof(struct in_addr));	
			ptr = (uint8_t *)CO(rec,4+4);	
			break;
		case AF_INET6:
			/* EID prefix is an IPv6 so 128 bits (16 bytes) */ 
			rec->record6.eid_mask_len = 128;
			rec->record.eid_prefix_afi = htons(LISP_AFI_IPV6);
            memcpy(&rec->record6.eid_prefix, &(eid->sin6.sin6_addr), sizeof(struct in6_addr));	
			ptr = (uint8_t *)CO(rec,4+16);	
			break;
		default:
			printf("not supported\n");
			return (FALSE);
	}
	
	/* set the UDP parameters */
#ifdef BSD
	udp->uh_sport = htons(lookups[idx].sport);
	udp->uh_dport = htons(PORT);
	udp->uh_ulen = htons((uint8_t *)ptr - (uint8_t *) udp);
	udp->uh_sum = 0;
#else
	udp->source = htons(lookups[idx].sport);
	udp->dest = htons(PORT);
	udp->len = htons((uint8_t *)ptr - (uint8_t *) udp );
	udp->check = 0;
#endif

	/* setup the IP parameters */
	switch (lookups[idx].mr->sin.sin_family ){
		case AF_INET:
			ip_len = (uint8_t *)ptr - (uint8_t *) ih;
			ih->ip_hl         = 5;
			ih->ip_v          = 4;
			ih->ip_tos        = 0;
			ih->ip_len        = htons(ip_len);
			ih->ip_id         = htons(0);
			ih->ip_off        = 0;
			ih->ip_ttl        = 255;
			ih->ip_p          = IPPROTO_UDP;
			ih->ip_sum        = 0;         
			ih->ip_src.s_addr = afi_addr_src.ip.address.s_addr;
			ih->ip_dst.s_addr = afi_addr_dst.ip.address.s_addr;
			ih->ip_sum = ip_checksum((unsigned short *)ih, ip_len);
			break;
		case AF_INET6:
			/* ip_len = (uint8_t *)ptr - (uint8_t *) ih;
			ih->ip_hl         = 5;
			ih->ip_v          = 4;
			ih->ip_tos        = 0;
			ih->ip_len        = htons(ip_len);
			ih->ip_id         = htons(0);
			ih->ip_off        = 0;
			ih->ip_ttl        = 255;
			ih->ip_p          = IPPROTO_UDP;
			ih->ip_sum        = 0;         
			ih->ip_src.s_addr = afi_addr_src.ip.address.s_addr;
			ih->ip_dst.s_addr = afi_addr_dst.ip.address.s_addr;
			ih->ip_sum = ip_checksum((unsigned short *)ih, ip_len); */
			break;		
	}
	
	/* ================================= */
	fprintf(OUTPUT_STREAM, "Map-Request");
	fprintf(OUTPUT_STREAM, " <");
	fprintf(OUTPUT_STREAM, "nonce=0x%x - 0x%x", nonce0, nonce1);
	fprintf(OUTPUT_STREAM, ">\n");
	/* ================================= */
		
	if (sendto(lookups[idx].rx, (void *)buf, (uint8_t *)ptr - (uint8_t *)lh, 0, &(lookups[idx].mr->sa), sockaddr_len) < 0) {
        return 0;
    } else {
        cnt = ++lookups[idx].count;
        lookups[idx].nonce0[cnt] = nonce0;
        lookups[idx].nonce1[cnt] = nonce1;
    }   
    return 1;
}

/* Process with map-reply */

	int
read_rec(union map_reply_record_generic * rec)
{
	size_t rlen;
	union map_reply_locator_generic * loc;
	char buf[BSIZE];
	size_t len;
	struct map_entry * entry;
	uint8_t lcount;
	struct prefix eid;
	struct mapping_flags mflags;
	void * mapping;
	struct db_node node;
	
	
	rlen = 0;
	bzero(buf, BSIZE);
	mapping = NULL;
	
	
	bzero(&eid, sizeof(struct prefix));
	switch(ntohs(rec->record.eid_prefix_afi)){
		case LISP_AFI_IP:
			eid.family = AF_INET;
			eid.u.prefix4 = rec->record.eid_prefix;
			inet_ntop(AF_INET, (void *)&eid.u.prefix4, buf, BSIZE);
			rlen += sizeof(struct map_reply_record);
			break;
		case LISP_AFI_IPV6:
			eid.family = AF_INET6;
			eid.u.prefix6 = rec->record6.eid_prefix;
			inet_ntop(AF_INET6, (void *)&eid.u.prefix6, buf, BSIZE);
			rlen += sizeof(struct map_reply_record6);
			break;
		default:
			fprintf(OUTPUT_STREAM, "unsuported family\n");
			return (0);
	}
	eid.prefixlen = rec->record.eid_mask_len;
	lcount = rec->record.locator_count;
	bzero(&mflags, sizeof(struct mapping_flags));
	mflags.act = rec->record.act;
	mflags.A = rec->record.a;
	mflags.version = rec->record.version;
	mflags.ttl = ntohl(rec->record.ttl);
	memcpy(&node.p, &eid, sizeof(struct prefix));
	generic_mapping_set_flags(&node, &mflags);
	node.info = list_init();
	
	/* ====================================================== */
	fprintf(OUTPUT_STREAM, "EID %s/%d: ", buf, eid.prefixlen);
	fprintf(OUTPUT_STREAM, "<");
	fprintf(OUTPUT_STREAM, "Lcount=%u", lcount);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "TTL=%u", mflags.ttl);

	if(lcount == 0){
		fprintf(OUTPUT_STREAM, ", ");
		fprintf(OUTPUT_STREAM, "ACT=%d", mflags.act);
	}

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "version=%u", mflags.version);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "A=%u", mflags.A);

	fprintf(OUTPUT_STREAM, ">\n");

	/* ====================================================== */

	loc = (union map_reply_locator_generic *)CO(rec, rlen);

	/* ==================== RLOCs ========================= */
	while(lcount--){
		char buf[BSIZE];
		bzero(buf, BSIZE);

		entry = (struct map_entry *)calloc(1, sizeof(struct map_entry));
		entry->priority = loc->rloc.priority;
		entry->weight = loc->rloc.weight;
		entry->m_priority = loc->rloc.m_priority;
		entry->m_weight = loc->rloc.m_weight;
		entry->r = loc->rloc.R;
		entry->L =loc->rloc.L;
		entry->p = loc->rloc.p;

		switch(ntohs(loc->rloc.rloc_afi)){
			case LISP_AFI_IP:
				entry->rloc.sin.sin_family = AF_INET;
				memcpy(&entry->rloc.sin.sin_addr, &loc->rloc.rloc, sizeof(struct in_addr));

				inet_ntop(AF_INET, (void *)&loc->rloc.rloc, buf, BSIZE);
				len = sizeof(struct map_reply_locator);
				break;
			case LISP_AFI_IPV6:
				entry->rloc.sin6.sin6_family = AF_INET6;
				memcpy(&entry->rloc.sin6.sin6_addr, &loc->rloc6.rloc, sizeof(struct in6_addr));

				inet_ntop(AF_INET6, (void *)&loc->rloc6.rloc, buf, BSIZE);
				len = sizeof(struct map_reply_locator6);
				break;
			default:
				fprintf(OUTPUT_STREAM, "unsuported family\n");
				free(entry);
				return (0);
		}
		fprintf(OUTPUT_STREAM, "\t•[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
				buf, \
				entry->priority, \
				entry->weight, \
				entry->m_priority, \
				entry->m_weight, \
				entry->r, \
				entry->L, \
				entry->p);

		/* add the locator to the table */
		
		assert((struct list_t *)node.info);
		list_insert((struct list_t *)node.info, entry, NULL);
		loc = (union map_reply_locator_generic *)CO(loc, len);
		rlen += len;
	}

	return (rlen);
}


	int 
read_mr(int idx)
{
	int i;
	int rcvl;
	char buf[PSIZE];
	union sockunion si;
	struct map_reply_hdr * lh;
	union map_reply_record_generic * lcm;
	uint32_t nonce0, nonce1;
	size_t sockaddr_len;
	int rec_len;
	
	if(lookups[idx].mr->sa.sa_family == AF_INET)
		sockaddr_len = sizeof(struct sockaddr_in);
	else
		sockaddr_len = sizeof(struct sockaddr_in6);
		
	/* read package */
	if ((rcvl = recvfrom(lookups[idx].rx,
			 buf,
			 PSIZE,
			0,
			(struct sockaddr *)&(si.sa),
			&sockaddr_len)) < 0) {
		return 0;
	}
	
	/*only accept map-reply with not empty record */
	lh = (struct map_reply_hdr *)buf;	
	if (lh->lisp_type != LISP_TYPE_MAP_REPLY) {
		return 0;
	}
	
	/* check nonce to see reply for what */
	nonce0 = ntohl(lh->lisp_nonce0);
	nonce1 = ntohl(lh->lisp_nonce1);
		
	for (i = 0;i <= MAX_COUNT ; i++) {
		if (lookups[idx].nonce0[i] == nonce0 && lookups[idx].nonce1[i] == nonce1)
			break;		
	}
	if (i > MAX_COUNT)
		return 0;
		
	if (lh->record_count <= 0)
		return 0;

	/* process map-reply */
	lcm = (union map_reply_record_generic *)CO(lh,sizeof(struct  map_reply_hdr));
	
	for (i = 0; i < lh->record_count; i++){
		if( (rec_len = read_rec(lcm)) < 0)
		{
			fprintf(OUTPUT_ERROR, "Record error\n");
			return -1;
		}
		lcm = (union map_reply_record_generic * )CO(lcm,rec_len);
	}
	
	lookups[idx].active = 0;
    close(lookups[idx].rx);
	return 0;
}

/* Main poll function */

	static void 
event_loop(void)
{
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

            deadline.tv_sec = lookups[i].start.tv_sec + (lookups[i].count +1) * timeout; 
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
                    map_message_handler(_get_ms());
                else
                    read_mr(fds_idx[j]);
            }
        }
    }
}

/* Main function of thread with intergrate with OpenLisp */

	void * 
plugin_openlisp(void *data)
{
	int openlispsck;
	int i;
	struct protoent	    *proto;

	
	if ((proto = getprotobyname("UDP")) == NULL) {
		perror ("getprotobyname");
		exit(0);
    }
    udpproto = proto->p_proto;
	
	openlispsck = socket(PF_MAP, SOCK_RAW, 0);

	fds[0].fd = openlispsck;
    fds[0].events = POLLIN;
    fds_idx[0] = -1;
    nfds = 1;

	/* Initialize lookups[]: all inactive */
	for (i = 0; i < MAX_LOOKUPS; i++)
        lookups[i].active = 0;
	
	event_loop();	
  	pthread_exit(NULL);
	return 0;
}



	int
sockunioncmp(void * m, void * n)
{
	union sockunion * sp, * dp;
	sp = m; dp = n;
	if(sp->sa.sa_family != dp->sa.sa_family)
		return -1;
		
	switch (sp->sa.sa_family){
		case AF_INET:
			return memcmp(&sp->sin.sin_addr, &dp->sin.sin_addr,sizeof(struct in_addr));
			break;
		case AF_INET6:
			return memcmp(&sp->sin6.sin6_addr, &dp->sin6.sin6_addr,sizeof(struct in6_addr));
			break;
		default:
			return -1;
	}
	return -1;		
}
/* process map-request with smr bit set */

	int 
smr_process(uint32_t request_id, union sockunion *sender)
{
	struct ip * ih;
	struct ip6_hdr *ih6;
	struct udphdr * udp;
	
	struct lisp_control_hdr * lh;
	struct map_request_hdr * lcm;
	union map_request_record_generic * rec;
	union afi_address_generic * eid_source, * itr_rloc;
	union sockunion itr_address;
	struct prefix * eid_prefix;
	struct db_node rs;
	int ret;	
	uint8_t icount;
	uint8_t rcount;
	void * packet;
	char buf[512];
	int s;
	size_t eid_size;
	
	struct db_node node;
	union sockunion * si;
	struct list_t * rll;
	
	packet = (void *)_pk_req_pool[request_id]->buf;
	si = (union sockunion *)&(_pk_req_pool[request_id]->si);
	
	lh = (struct lisp_control_hdr *)CO(packet, 0);
	fprintf(OUTPUT_STREAM, "LH: <type=%u>\n", lh->type);
	
	/*===================================================*/
	/* Encapsulated Control Message Format => decap first */
	if(lh->type == LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE){
		ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
		if (ih->ip_v == 4){
			ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
			ih6	= NULL;
			udp = (struct udphdr *)CO(ih, sizeof(struct ip));
		}
		else if (ih->ip_v == 6){
			ih		= NULL;
			ih6	= (struct ip6_hdr *) CO(lh, sizeof(struct lisp_control_hdr));
			udp	= (struct udphdr *) CO(ih6,  sizeof(struct ip6_hdr));
		}
		else{
			fprintf(OUTPUT_STREAM, "IP version not correct: Only support IPv4 and IPv6\n");
			return (0);
		}		
		
		lcm = (struct map_request_hdr *)CO(udp, sizeof(struct udphdr));
	}
	else {
		lcm = (struct map_request_hdr *)packet;
	}
	
	if(lcm->lisp_type != LISP_TYPE_MAP_REQUEST){
		fprintf(OUTPUT_STREAM, "only Map-Requests are supported\n");
		return (0);
	}

	fprintf(OUTPUT_STREAM, "LCM: <type=%u, A=%u, M=%u, P=%u, S=%u, p=%u, s=%u, IRC=%u, rcount=%u, nonce=0x%x - 0x%x>\n", \
			lcm->lisp_type,
			lcm->auth_bit, \
			lcm->map_data_present, \
			lcm->rloc_probe, \
			lcm->smr_bit, \
			lcm->pitr_bit, \
			lcm->smr_invoke_bit, \
			lcm->irc, \
			lcm->record_count, \
		       	ntohl(lcm->lisp_nonce0), \
			ntohl(lcm->lisp_nonce1));
			
	
	/*===================================================*/
	/* pass eid-source */
	eid_source = (union afi_address_generic *)CO(lcm, sizeof(struct map_request_hdr));
	ret = _afi_address_str(eid_source, buf, 512);

	/* check if the source EID is specified */
	if(ret){
		/* size is [Source EID AFI field + Source EID Address field] */
		eid_size = _get_address_size(eid_source);
	}
	else{
		/* size is [Source EID AFI field] as no address is provided */
		eid_size = 2;
	}
	
	/*===================================================*/
	/* jump to the ITR address list */
	itr_rloc = (union afi_address_generic *)CO(eid_source, eid_size);
	icount = lcm->irc + 1;
	
	/* get the first itr */	
	switch(_get_address_type(itr_rloc)){
		case LISP_AFI_IP:
			memcpy(&itr_address.sin.sin_addr, &itr_rloc->ip.address, sizeof(struct in_addr));
			itr_address.sin.sin_family = AF_INET;			
			break;
		case LISP_AFI_IPV6:
			memcpy(&itr_address.sin6.sin6_addr, &itr_rloc->ip6.address, sizeof(struct in6_addr));
			itr_address.sin6.sin6_family = AF_INET6;			
			break;
		default:
			fprintf(OUTPUT_ERROR,"AF not supported (only IPv4 and IPv6)\n");
			return (0);			
	}

	_afi_address_str(itr_rloc, buf, 512);	
	fprintf(OUTPUT_STREAM, "ITR-RLOC: %s\n", buf);
	
	/*bypass other itrs */
	icount--;	
	while(icount--){
		itr_rloc = (union afi_address_generic *)CO(itr_rloc, _get_address_size(itr_rloc));
	}
	
	/*===================================================*/
	/*get eid-prefix */
	rcount = lcm->record_count;
	rec = (union map_request_record_generic *)CO(itr_rloc, 0);
		 
	while(rcount--){
		bzero((void *)buf, 512);
		eid_prefix = &node.p;
		free(node.info);
		bzero(eid_prefix, sizeof(struct prefix));

		switch(ntohs(rec->record.eid_prefix_afi)){
			case LISP_AFI_IP:
				eid_prefix->family = AF_INET;
				memcpy(&eid_prefix->u.prefix4, &rec->record.eid_prefix, SA_LEN(AF_INET));

				inet_ntop(AF_INET, (void *)&rec->record.eid_prefix, buf, 512);
				break;
			case LISP_AFI_IPV6:
				eid_prefix->family = AF_INET6;
				memcpy(&eid_prefix->u.prefix6, &rec->record6.eid_prefix, SA_LEN(AF_INET6));

				inet_ntop(AF_INET6, (void *)&rec->record6.eid_prefix, buf, 512);
				break;
		}
		eid_prefix->prefixlen = rec->record.eid_mask_len;

		fprintf(OUTPUT_STREAM, "EID prefix: %s/%u\n", buf, rec->record.eid_mask_len);
		
		/*===================================================*/
		s = socket(PF_MAP, SOCK_RAW, 0);
		
		if (opl_get(s, &node, 0, &rs) < 0){
			fprintf(OUTPUT_STREAM, "EID prefix not in cache db, ignore\n");
			close(s);
			continue;
		}
		close(s);
		
		rll = rs.info;
		/* check if source location in rloc-list */
		if(!rll){
			continue;
		}
		fprintf(OUTPUT_STREAM, "Update EID");
		
		/*if source location not in rloc-list or exist only one rloc, send map-request to map-resolver */
		 if(!list_search(rll, (void *)si, sockunioncmp) || rll->count <=1){
			new_lookup(eid_prefix, _get_ms());
			return 0;
		}
			
		/*send to source locator */
		new_lookup(eid_prefix, si);
		return 0;
	}

	return 0;
}

	void *
opl_new_msg(uint16_t version, uint16_t map_type, uint32_t map_flags, uint16_t map_addrs,  int rloc_count)
{
	struct map_msghdr * mhdr;
		
	mhdr = calloc(PSIZE+sizeof(struct map_msghdr), sizeof(char));
	memset(mhdr,0,PSIZE+sizeof(struct map_msghdr));
	mhdr->map_version = version;
	mhdr->map_type =  map_flags;      
	mhdr->map_flags = map_type;
	mhdr->map_addrs = map_addrs;
	mhdr->map_pid = getpid();
	mhdr->map_versioning = 0;
	mhdr->map_errno = 0;
	mhdr->map_seq = ++seq;
	mhdr->map_msglen = sizeof(struct map_msghdr);
	return mhdr;
}
	size_t
opl_mask2sockaddr(int masklen, int af, union sockunion *rs){

	char ip[INET6_ADDRSTRLEN];
	char buf[16];
	char * p;
	char t;
	struct prefix pf;
		
	memset(buf,0,16);
	if(masklen % 8 ==0){
		memset(buf,255,masklen / 8);
	}
	else{
		memset(buf,255, (masklen / 8)+1);
		p = CO(buf,(masklen / 8)) ;
		t = *p;
		t = t << (8-(masklen % 8));
		*p = t;
	}
	
	inet_ntop(af, buf, ip, INET6_ADDRSTRLEN);
	str2prefix (ip, &pf);
	return prefix2sockaddr(&pf,rs);
}

	int 
opl_sockaddr2mask(union sockunion * sk, int *rs){
	
	u_char * buf;
	int max;
	
	buf = calloc(SIN_LEN(sk->sa.sa_family),sizeof(char));
	memcpy(buf,( (sk->sa).sa_family == AF_INET)?&((sk->sin).sin_addr):&((sk->sin6).sin6_addr), SIN_LEN(sk->sa.sa_family));
	max = (sk->sa.sa_family == AF_INET)?32:128;
	*rs = 0;
	while(max > 0){
		if (*buf == 255)
			*rs +=8;
		else{
			while(*buf > 0){
				*rs +=1;
				*buf = *buf <<1;
			}
			break;
		}

		buf = (u_char *)CO(buf,1);
		max = max - 8;
	}
	return 0;
}
/* Add a mapping to database of openlisp 
	db = 1:database, db=0:cache
*/
	int 
opl_add_mapp(void * buf, struct db_node * mapp)
{
	void * mcm;
	struct map_msghdr * mhdr;
	union sockunion eid;
	size_t l;
		
	mhdr = (struct map_msghdr *)buf;	
	mcm = CO(buf,sizeof(struct map_msghdr));
	mhdr->map_rloc_count = 0;
	
	/*add EID-prefix */
	if( (l = prefix2sockaddr(&mapp->p,&eid)) <=0){
		fprintf(OUTPUT_ERROR, "eid-prefix not correct\n");
		return -1;
	}	
	memcpy(mcm, &eid, l);
	mcm = CO(mcm,l);
	
	/*add EID-Mask */
	/*not include MAPA_EIDMASK if subnetmask =32(IPV4) or 128(IPV6)*/
	l = (eid.sa.sa_family == AF_INET)?32:128;
	if( (mapp->p.prefixlen > 0) && ( mapp->p.prefixlen  < l)){
		if( (l = opl_mask2sockaddr(mapp->p.prefixlen, eid.sa.sa_family, &eid)) <=0){
			fprintf(OUTPUT_ERROR, "eid-prefix not correct\n");
			return -1;
		}
		memcpy(mcm, &eid, l);
		mcm = CO(mcm,l);		
		mhdr->map_addrs |= MAPA_EIDMASK;
	}
	
	mhdr->map_msglen = (char *)mcm - (char *)mhdr;	
	return mhdr->map_msglen;
}

	int 
opl_add_rloc(void * buf, struct db_node * mapp)
{
	void * mcm;
	struct map_msghdr * mhdr;
	int lcount;
	struct list_t * ll;
	struct list_entry_t *rl_entry;
	struct map_entry * rl;
	struct rloc_mtx * mx;
		
	if(!mapp->info){
		return 0;
	}
	else{
		ll = (struct list_t *)mapp->info;
		lcount = ll->count;
	}
	
	mhdr = (struct map_msghdr *)buf;	
	mcm = CO(buf,mhdr->map_msglen);
	mhdr->map_rloc_count = 0;
	
	rl_entry = ll->head.next;
	while(rl_entry != &ll->tail){
		rl = (struct map_entry *)rl_entry->data;
		memcpy(mcm, &rl->rloc, SA_LEN(rl->rloc.sa.sa_family));
		mx = (struct rloc_mtx *)CO(mcm,SA_LEN(rl->rloc.sa.sa_family));
		mx->priority = rl->priority;
		mx->flags |= rl->L?RLOCF_LIF:0;
		mx->flags |= rl->r?RLOCF_UP:0;
		mcm = CO(mx,sizeof(struct rloc_mtx));
		mhdr->map_rloc_count +=1;
	}	
	mhdr->map_msglen = (char *)mcm - (char *)mhdr;	
	return mhdr->map_msglen;
}

	int 
opl_add(int s, struct db_node * mapp, int db)
{
	void * buf;
	size_t l;
	int lcount;
	struct list_t * ll;
	
	if(!mapp->info){
		lcount = 0;
	}else{
		ll = (struct list_t *)mapp->info;
		lcount = ll->count;
	}
	
	buf = opl_new_msg(MAPM_VERSION, \
						MAPM_ADD,\
						(db == 1? MAPF_DB: 0) | MAPF_STATIC | MAPF_UP,\
						MAPA_EID | ( (lcount <= 0 )? 0 : MAPA_RLOC),\
						lcount);
	
	if( (l=opl_add_mapp(buf, mapp)) < 0)
		return -1;
	if( (l=opl_add_rloc(buf, mapp))<0)
		return -1;
		
	/*send to openlisp database */
	if ((l = write(s, (char *)&buf, l)) < 0) {
		fprintf(OUTPUT_ERROR,"Writing to OpenLISP socket error\n");
		return -1;
	}
	return 0;
}

/* Delete a mapping from Openlisp database
	db: for future
*/
	int 
opl_del(int s, struct db_node * mapp, int db)
{
	
	void * buf;
	size_t l;
		
	buf = opl_new_msg(MAPM_VERSION, \
						MAPM_DELETE,\
						(db == 1? MAPF_DB: 0) | MAPF_STATIC | MAPF_UP,\
						MAPA_EID,
						0);
	
	if( (l=opl_add_mapp(buf, mapp)) < 0)
		return -1;
		
	/*send to openlisp database */
	if ((l = write(s, (char *)&buf, l)) < 0) {
		fprintf(OUTPUT_ERROR,"Writing to OpenLISP socket error\n");
		return -1;
	}
	return 0;
}

/* Find a mapping from Openlisp database */
	int 
opl_get(int s, struct db_node * mapp, int db, struct db_node *rs)
{
	void * buf;
	struct map_msghdr * mhdr;
	void * mmc;
	union sockunion * rc;
		
	size_t l;
	int c_seq;
	pid_t   c_pid;  
	
	buf = opl_new_msg(MAPM_VERSION, \
						MAPM_GET,\
						MAPF_ALL | MAPF_STATIC |MAPF_UP,\
						MAPA_EID,
						0);
	
	if( (l=opl_add_mapp(buf, mapp)) < 0)
		return -1;
	mhdr = (struct map_msghdr *)buf;	
	c_seq =	mhdr->map_seq;
	c_pid = mhdr->map_pid;
	
	/*send to openlisp database */
	if ((l = write(s, (char *)&buf,l)) < 0) {
		fprintf(OUTPUT_ERROR,"Writing to OpenLISP socket error\n");
		return -1;
	}
	
	/*wait for return from mapping soket*/
	do {
		l = read(s, (char *)&buf, PSIZE);
		mhdr = (struct map_msghdr *)buf;	
	} while (l > 0 && (mhdr->map_seq != c_seq || mhdr->map_pid != c_pid));
	
	/* get result */
	if (l < 0){
		fprintf(OUTPUT_ERROR,"Erorr: read from mapping socket\n");
		return -1;
	}
	
	mhdr = (struct map_msghdr *)buf;	
	mmc = CO(mhdr, sizeof(struct map_msghdr));
	
	/* check eid prefix */
	if ((mhdr->map_flags & MAPF_DONE) <=0) {
		//fprintf(OUTPUT_ERROR("Error:request not success\n");
		return -1;
	}

	/*get EID */ 
	if ( (mhdr->map_addrs & MAPA_EID) <= 0 ) {
		//fprintf(OUTPUT_ERROR("Error:request not success\n");
		return -1 ;
	}
	rc = mmc;
	if( (l = sockaddr2prefix(rc, &rs->p))<=0){
		//fprintf(OUTPUT_ERROR("Error:request not success\n");
		return -1 ;
	}
	rc = (union sockunion *)CO(rc,l);
	
	//get EID-masklen if exist
	if ( (mhdr->map_addrs & MAPA_EIDMASK ) > 0) {
		opl_sockaddr2mask(rc, (int *)&(rs->p.prefixlen));
		rc = (union sockunion * )CO(rc,SA_LEN(rc->sa.sa_family));
	}else
		rs->p.prefixlen = ((rc->sa).sa_family == AF_INET)?32:128;
	
	/*get Rloc if exist */
	if ( (mhdr->map_addrs & MAPA_RLOC ) > 0) {
		int i;
		struct list_t *rl;
		struct map_entry * re;
		struct rloc_mtx * mx;
		
		mapp->info = rl = list_init();
		for (i = 0; i < mhdr->map_rloc_count ; i++) {
			re = calloc(1,sizeof(struct map_entry));
			list_insert(rl,re, NULL);
			memcpy(&re->rloc, rc, SA_LEN(rc->sa.sa_family));
			mx = (struct rloc_mtx *)CO(rc,l);
			re->priority = mx->priority;
			re->weight = mx->weight;
			re->r = mx->flags & RLOCF_UP;
			re->L = mx->flags & RLOCF_LIF;
			rc = (union sockunion *)CO(mx,sizeof(struct rloc_mtx));
		}
	}
	return 0;
}

/* update db */
	int 
opl_update(int s, struct db_node *node)
{
	
	opl_del(s,node,0);
	opl_add(s,node,0);
	return 0;
}
#endif