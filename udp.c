#include "lib.h"
#include "udp.h"

uint32_t udp_prc_request(void *data);
uint32_t _register(void *data);
uint32_t _referral(void *data);
uint32_t _forward(void *data);

size_t _process_register_record(const union map_reply_record_generic *rec);
size_t _process_referral_record(const union map_referral_record_generic *rec, 
								union afi_address_generic *best_rloc, 
								struct db_node **node);                                                                                   
int  _ms_validate_register(struct lisp_db *db, const void *packet, int pkg_len, void **site_ptr);
void _ms_clean_site_mapping(struct list_entry_t *site);
size_t _ms_process_register_record(const union map_reply_record_generic *rec,uint8_t proxy_map_repl );

void *general_register_process(void *data);
void *mr_event_loop(void *context);
void *get_mr_ddt(void *);

/* ! Communication handling code */

/* UDP function binding */
struct communication_fct udp_fct = {\
	.start_communication	= udp_start_communication, \
	.stop_communication	= udp_stop_communication, \
	/* Map-Reply */
	.reply_add 		= udp_reply_add,\
	.reply_add_record	= udp_reply_add_record, \
	.reply_add_locator	= udp_reply_add_locator,\
	.reply_error		= udp_reply_error, \
	.reply_terminate	= udp_reply_terminate, \
	/* Map-Referral */
	.referral_add 		= udp_referral_add,\
	.referral_add_record	= udp_referral_add_record, \
	.referral_add_locator	= udp_referral_add_locator,\
	.referral_error		= udp_referral_error, \
	.referral_terminate	= udp_referral_terminate, \
	/* Map-Request */
	.request_add		= udp_request_add, \
	.request_terminate	= udp_request_terminate, \
	.request_get_eid	= udp_request_get_eid , \
	.request_get_nonce	= udp_request_get_nonce, \
	.request_is_ddt		= udp_request_is_ddt, \
	.request_get_itr	= udp_request_get_itr, \
	.request_get_port	= udp_request_get_port,\
	.request_ddt_terminate	= udp_request_ddt_terminate,\
};
/*------------helper function-------------------  */

/* Make new nonce base on random function
 * future need new method 
 */  
	void 
_make_nonce(uint64_t *nonce)
{
    uint32_t *nonce0;
    uint32_t *nonce1;
	
	nonce0  = (uint32_t *)nonce;
	nonce1  = (uint32_t *)(nonce0 + 1);
	*nonce0 = random() ^ random();
    *nonce1 = random() ^ time(NULL);
}

/* compare two ip address 
 * return 0 if equal	
 */
	int
addrcmp(union sockunion *src, union sockunion *dst)
{
	if (src->sa.sa_family != dst->sa.sa_family)
		return -1;
	
	switch (src->sa.sa_family) {
	case AF_INET:
		return memcmp((void *)&(src->sin.sin_addr), (void *)&(dst->sin.sin_addr), sizeof(struct in_addr));
	case AF_INET6:
		return memcmp((void *)&(src->sin6.sin6_addr), (void *)&(dst->sin6.sin6_addr), sizeof(struct in6_addr));				
	}	
	return -1;
}

	int
entrycmp(void *esrc, void *edst)
{	
	struct map_entry *src, *dst;
	
	src = (struct map_entry *)esrc;
	dst = (struct map_entry *)edst;
	if (src && dst)
		return addrcmp(&src->rloc, &dst->rloc);
	return -1;	
}
	
/* check if an address belong to one of machine interface
	if yes, return 1
	else not, return 0
	return -1 in error
 */
	int
is_my_addr(union sockunion *sk)
{
	struct ifaddrs *ifap, *ifa;
	char buf[NI_MAXHOST];
	int rt;
	
	if (getifaddrs(&ifap) == -1) 	
		return -1;	
    
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		/*ignore: */
			/*interface with not ip*/
		if (ifa->ifa_addr == NULL)
			continue;
			/*interface with not same afi */	
		if (ifa->ifa_addr->sa_family != sk->sa.sa_family)
			continue;
			/*look back interface */	
		if (getnameinfo(ifa->ifa_addr,SA_LEN(ifa->ifa_addr->sa_family),
		    buf,NI_MAXHOST,NULL,0,NI_NUMERICHOST) != 0) {
			continue;
	    }

    	if (!(strcmp(LOOPBACK,buf) && strcmp(LOOPBACK6,buf) &&  strncmp(LINK_LOCAL,buf,LINK_LOCAL_LEN)))
			continue;
		
		/*compare addr */
		switch (sk->sa.sa_family) {
		case AF_INET:
			rt = (0 == memcmp((void *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, (void *)&sk->sin.sin_addr,sizeof(struct in_addr)));
			break;
		case AF_INET6:
			rt = (0 == memcmp((void *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, (void *)&sk->sin6.sin6_addr,sizeof(struct in6_addr)));
			break;
		default:
			rt = -1;
		}
		
		if (rt) {
			freeifaddrs(ifap);
			return rt;
		}
	};/* end for */  
	return 0;
}	

	void *
_get_rpl_pool_place()
{
	struct pk_rpl_entry *rpk;
	
	rpk = (struct pk_rpl_entry *)calloc(1,sizeof(struct pk_rpl_entry));
	rpk->buf = calloc(PKBUFLEN,sizeof(char));
	return rpk;
}

/* a very basic function to remove a request package from queue */
	void 
_rm_rpl(void *entry)
{
	free(((struct pk_rpl_entry *)entry)->buf);
}

/* free function */
	int
rem(void *e)
{
	free(e);
	return TRUE;
}

	uint32_t
udp_free_pk(void *data)
{
	struct pk_req_entry *pke = data;
	
	if (pke) {
		if (pke->itr)
			list_destroy(pke->itr,rem);
		if (pke->eid)
			list_destroy(pke->eid,rem);
		free(pke->buf);
		free(pke);
		pthread_mutex_lock(&ipq_mutex);
		ipq_no--;
		pthread_mutex_unlock(&ipq_mutex);
		pthread_cond_signal(&ipq_cv);
	}else{
		return -1;
	}
	return 0;
}

	uint32_t
_free_rpl_pool_place(void *rpk, void (*fnc)(void *))
{
	fnc((void *)rpk);	
	free(rpk);
	return 0;
}
/*
 * Determine the LISP AFI type of an <AFI, address> tuple on the wire
 */
	inline static uint16_t
_get_address_type(const union afi_address_generic *addr)
{
	return (ntohs(addr->ip.afi));
}


/* Determine the actual size of an <AFI, address> tuple on the wire (only IPv4
 * and IPv6 supported)
 */
	inline size_t 
_get_address_size(const union afi_address_generic *addr)
{
	switch (_get_address_type(addr)) {
	case LISP_AFI_IP:
		return (sizeof(struct afi_address));
	case LISP_AFI_IPV6:
		return (sizeof(struct afi_address6));
	default:			
		assert(FALSE);
		return (0);
	}
}

/* 
 * Determine the actual size of a Map-Request record tuple on the wire (only
 * IPv4 and IPv6 supported)
 */
	inline size_t 
_get_record_size(const union map_request_record_generic *rec)
{
	switch (ntohs(rec->record.eid_prefix_afi)) {
	case LISP_AFI_IP:
		return (sizeof(struct map_request_record));
	case LISP_AFI_IPV6:
		return (sizeof(struct map_request_record6));
	default:
		cp_log(LDEBUG, "AF not support\n");			
		return (0);
	}
}

/* 
 * Determine the actual size of a Map-Reply record tuple on the wire (only
 * IPv4 and IPv6 supported)
 */
	inline size_t
_get_reply_record_size(const union map_reply_record_generic *rec)
{
	switch (ntohs(rec->record.eid_prefix_afi)) {
	case LISP_AFI_IP:
		return (sizeof(struct map_reply_record));
	case LISP_AFI_IPV6:
		return (sizeof(struct map_reply_record6));
	default:
		assert(FALSE);
		return (0);
	}
}

/* 
 * Determine the actual size of a Map-Referral record tuple on the wire (only
 * IPv4 and IPv6 supported)
 */
	inline size_t
_get_referral_record_size(const union map_referral_record_generic *rec)
{
	switch (ntohs(rec->record.eid_prefix_afi)) {
	case LISP_AFI_IP:
		return (sizeof(struct map_referral_record));
	case LISP_AFI_IPV6:
		return (sizeof(struct map_referral_record6));
	default:
		assert(FALSE);
		return (0);
	}
}

/*
 * Give the string representetion of the address
 *
 * @param addr <AFI, address> tuple to represent in string
 * @param buf buffer to store the string representation
 * @param len buffer length in bytes
 * @return TRUE if the address can be converted. Otherwise, a FALSE is returned
 */
	int
_afi_address_str(const union afi_address_generic *addr, char *buf, size_t len)
{
	int ret = TRUE;

	bzero(buf, len);
	switch (_get_address_type(addr)) {
	case LISP_AFI_IP:
		inet_ntop(AF_INET, (void *)&addr->ip.address, buf, len);
		break;
	case LISP_AFI_IPV6:
		inet_ntop(AF_INET6, (void *)&addr->ip6.address, buf, len);
		break;
	default:
		cp_log(LDEBUG, "address not present");
		ret = FALSE;
		break;
	}
	return ret;
}

/* convert union sockunio to afi_address */

	int 
_sockunion_to_afi_address(const union sockunion *su, union afi_address_generic *afi_address)
{
	bzero(afi_address, sizeof(union afi_address_generic));
	switch (su->sa.sa_family) {
	case AF_INET:
		afi_address->ip.afi = htons(LISP_AFI_IP);
		memcpy(&((afi_address->ip).address), &((su->sin).sin_addr), sizeof(struct in_addr));
		break;
	case AF_INET6:
		afi_address->ip6.afi = htons(LISP_AFI_IPV6);
		memcpy(&((afi_address->ip6).address), &((su->sin6).sin6_addr), sizeof(struct in6_addr));					
		break;
	default:
		assert(0);
		cp_log(LDEBUG, "AFI not supported union sockunion to afi_address\n");
		return (FALSE);
	}
	return (TRUE);
}

/*------------Main functions: Reply------------- */
	void *
udp_new_reply_entry(void *data)
{
	struct pk_req_entry *pke = data;
	struct pk_rpl_entry *rpk;
	
	if (!(rpk = _get_rpl_pool_place()))
		return NULL;
	rpk->curs = rpk->buf;
	rpk->buf_len = 0;
	rpk->request_id = pke;
	
	return rpk;
}

/* ========================================================== */
/* Map-register handing code */

	void *
udp_register_add(void *data)
{
	struct map_register_hdr *hdr;
	struct pk_rpl_entry *rpk;
	struct pk_req_entry *pke = data;
	
	if (!(rpk = udp_new_reply_entry(pke)))
		return NULL;
	
	hdr = (struct map_register_hdr *)rpk->buf;
	
	/* write the 64-bit nonce in two 32-bit fields
	 * need this trick because of the LITTLE_ENDIAN
	 */
	
	hdr->lisp_type = LISP_TYPE_MAP_REGISTER;	
	rpk->curs = CO(hdr, sizeof(struct map_register_hdr)
			    + HMAC_SHA1_DIGEST_LENGTH);
	rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;
	return rpk;
}

/* send map-register
	udp_register_add_record == udp_reply_add_record
	udp_register_add_locator == udp_reply_add_locator
 */
	int 
udp_register_add_record(void *data, struct prefix *p, 
					uint32_t ttl, uint8_t lcount, uint32_t version, uint8_t A, uint8_t act)
{
	return udp_reply_add_record(data, p, ttl, lcount, version, A, act);			
}

	int 
udp_register_add_locator(void *data, struct map_entry *e, int ex_info)
{
	union map_reply_locator_generic *loc;
	struct map_reply_locator_te *loc_te;
	int lc = 0;
	struct pk_rpl_entry *rpk = data;
	struct list_entry_t *ptr, *p;
	struct pe_entry *pe;
	struct lcaf_hdr *lcaf;
	union rloc_te_generic *hop;
	struct hop_entry *haddr;
	char buf[BSIZE];
	
	if ((_fncs & _FNC_XTR) && lisp_te && e->pe && ex_info) {
		ptr = e->pe->head.next;
		while (ptr != &e->pe->tail) {
			pe = (struct pe_entry*)ptr->data;
			loc_te = (struct map_reply_locator_te *)rpk->curs;
			
			loc_te->priority = pe->priority;
			loc_te->weight = pe->weight;
			loc_te->m_priority = pe->m_priority;
			loc_te->m_weight = pe->m_weight;
			loc_te->L = e->L;
			loc_te->p = e->p;
			loc_te->R = e->r;
			cp_log(LDEBUG, "\t•[rloc=TE, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
					pe->priority, \
					pe->weight, \
					pe->m_priority, \
					pe->m_weight, \
					pe->r, \
					pe->L, \
					pe->p);
			
			lcaf = (struct lcaf_hdr *)&(loc_te->lcaf);
			lcaf->afi = htons(LCAF_AFI);
			lcaf->type = LCAF_TE;
						
			/*list of hop */
			p = pe->hop->head.next;
			hop = rpk->curs = CO(loc_te, sizeof(struct map_reply_locator_te));
			
			while (p != &pe->hop->tail) {
				/* add chain hop to message */
				haddr = (struct hop_entry *)p->data;
				bzero(buf, BSIZE);
				switch (haddr->addr.sa.sa_family) {
				case AF_INET:
					hop->rloc.afi = htons(LISP_AFI_IP);
					hop->rloc.L	= haddr->L;
					hop->rloc.P  = haddr->P;
					hop->rloc.S  = haddr->S;
					memcpy(&hop->rloc.hop_addr, &haddr->addr.sin.sin_addr, sizeof(struct in_addr));
					inet_ntop(AF_INET, (void *)&haddr->addr.sin.sin_addr, buf, BSIZE);
					hop = rpk->curs = CO(hop, sizeof(struct rloc_te));
					break;
				case AF_INET6:
					hop->rloc.afi = htons(LISP_AFI_IPV6);
					hop->rloc.L	= haddr->L;
					hop->rloc.P  = haddr->P;
					hop->rloc.S  = haddr->S;
					memcpy(&hop->rloc6.hop_addr, &haddr->addr.sin6.sin6_addr, sizeof(struct in6_addr));
					inet_ntop(AF_INET6, (void *)&haddr->addr.sin6.sin6_addr, buf, BSIZE);
					hop = rpk->curs = CO(hop, sizeof(struct rloc6_te));						
					break;
				default:
					assert(FALSE);
				}
				cp_log(LDEBUG, "\t\t•[hop=%s]\n",buf);									
				
				p = p->next;				
			}
			/*rloc as last hop */
			switch (e->rloc.sa.sa_family) {
			case AF_INET:
				hop->rloc.afi = htons(LISP_AFI_IP);
				memcpy(&hop->rloc.hop_addr, &e->rloc.sin.sin_addr, sizeof(struct in_addr));
				inet_ntop(AF_INET, (void *)&hop->rloc.hop_addr, buf, BSIZE);
				hop = rpk->curs = CO(hop, sizeof(struct rloc_te));
				break;
			case AF_INET6:
				hop->rloc.afi = htons(LISP_AFI_IPV6);
				memcpy(&hop->rloc6.hop_addr, &e->rloc.sin6.sin6_addr, sizeof(struct in6_addr));
				inet_ntop(AF_INET6, (void *)&hop->rloc6.hop_addr, buf, BSIZE);
				hop = rpk->curs = CO(hop, sizeof(struct rloc6_te));
				break;
			default:
				assert(FALSE);
			}
			cp_log(LDEBUG, "\t\t•[hop=%s]\n",buf);									
						
			lcaf->payload_len = htons(((char *)rpk->curs - (char *)lcaf) - sizeof(struct lcaf_hdr));
			lc++;
			ptr = ptr->next;
		}
		rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;	
	}
	else{
		loc = (union map_reply_locator_generic *)rpk->curs;
		loc->rloc.priority = e->priority;
		loc->rloc.weight = e->weight;
		loc->rloc.m_priority = e->m_priority;
		loc->rloc.m_weight = e->m_weight;
		loc->rloc.L = e->L;
		loc->rloc.p = e->p;
		loc->rloc.R = e->r;

		switch (e->rloc.sa.sa_family) {
		case AF_INET:
			loc->rloc.rloc_afi = htons(LISP_AFI_IP);
			memcpy(&loc->rloc.rloc, &e->rloc.sin.sin_addr, sizeof(struct in_addr));
			rpk->curs = CO(loc, sizeof(struct map_reply_locator));
			break;
		case AF_INET6:
			loc->rloc6.rloc_afi = htons(LISP_AFI_IPV6);
			memcpy(&loc->rloc6.rloc, &e->rloc.sin6.sin6_addr, sizeof(struct in6_addr));
			rpk->curs = CO(loc, sizeof(struct map_reply_locator6));
			break;
		default:
			assert(FALSE);
		}
		rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;

		/* ================================================= */
		
		bzero(buf, BSIZE);
		switch (e->rloc.sa.sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, (void *)&e->rloc.sin.sin_addr, buf, BSIZE);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, (void *)&e->rloc.sin6.sin6_addr, buf, BSIZE);
			break;
		default:
			cp_log(LDEBUG, "unsuported family\n");
			return (FALSE);
		}
		cp_log(LDEBUG, "\t[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
					buf, \
					e->priority, \
					e->weight, \
					e->m_priority, \
					e->m_weight, \
					e->r, \
					e->L, \
					e->p);			
		lc++;
	}
	return (TRUE);
}

/* send map-register to ms */
	uint32_t
udp_register_terminate(void *data, union sockunion *ds)
{
	int skt;
	struct pk_rpl_entry *rpk = data;
	
	socklen_t slen = 0;
	if (_debug == LDEBUG) {	
		cp_log(LDEBUG, "send Map-Register ");
		cp_log(LDEBUG, "to %s:%d\n", 
				sk_get_ip(ds, ip), sk_get_port(ds) );
		cp_log(LDEBUG, "Sending packet... ");
	}
	
	skt = 0;
	if ((ds->sa).sa_family == AF_INET) {
		if ((skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			perror("socket");
			exit(0);
		}
		
		slen = sizeof(struct sockaddr_in);
	}else if ((ds->sa).sa_family == AF_INET6) {		
		if ((skt = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			perror("socket");
			exit(0);
		}
		slen = sizeof(struct sockaddr_in6);
	}
	else{
		cp_log(LDEBUG, "Map-server not correct::AF_NOT_SUPPORT\n");
		exit(0);
	}
	
	if (sendto(skt, (char *)rpk->buf, rpk->buf_len, 0, (struct sockaddr *)&(ds->sa), slen) == -1) {
		 cp_log(LLOG, "failed\n");
		 perror("sendto()");
		 close(skt);
		 return (FALSE);
	}
	
	close(skt);
	cp_log(LDEBUG, "done\n");
		
	return (TRUE);
}

	uint32_t
udp_register_error(void *data)
{
	cp_log(LDEBUG, "Error processing\n");
	return -1;
}

/* ========================================================== */
/* Map-Reply handling code */
/* make new map-reply header */
	void *
udp_reply_add(void *data)
{
	struct map_reply_hdr *hdr;
	uint32_t *nonce_trick;
	uint64_t nonce;
	struct pk_req_entry *pke = data;
	struct pk_rpl_entry *rpk;
	
	if (!(rpk = udp_new_reply_entry(pke)) ) {
		udp_free_pk(pke);
		return NULL;
	}
	
	hdr = (struct map_reply_hdr *)rpk->buf;
	
	/* write the 64-bit nonce in two 32-bit fields
	 * need this trick because of the LITTLE_ENDIAN
	*/
	 
	udp_request_get_nonce(pke, &nonce);
	nonce_trick = (void *)&nonce;
	hdr->lisp_type = LISP_TYPE_MAP_REPLY;
	hdr->lisp_nonce0 = htonl(*nonce_trick);
	hdr->lisp_nonce1 = htonl(*(nonce_trick + 1));
	if (_debug == LDEBUG) {
		/* ================================= */
		cp_log(LDEBUG, "Map-Reply ");
		cp_log(LDEBUG, " <nonce=0x%x - 0x%x>\n", ntohl(hdr->lisp_nonce0), ntohl(hdr->lisp_nonce1));
		/* ================================= */
	}
	
	rpk->curs = CO(hdr,sizeof(struct map_reply_hdr));
	rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;
	return rpk;
}

/* add new record to message */					
	int 
udp_reply_add_record(void *data, struct prefix *p, 
					uint32_t ttl, uint8_t lcount, uint32_t version, uint8_t A, uint8_t act)
{
	union map_reply_record_generic *rec;
	struct map_reply_hdr *hdr;
	struct pk_rpl_entry *rpk = data;
	struct map_request_hdr *mrh;
	
	hdr = (struct map_reply_hdr *)rpk->buf;
	hdr->record_count++;
	if (rpk->request_id && 
		(mrh = (struct map_request_hdr *)((struct pk_req_entry *)rpk->request_id)->lcm) &&
		mrh->rloc_probe)
			hdr->rloc_probe = 1;
	rec = (union map_reply_record_generic *)rpk->curs;
	rec->record.ttl = htonl(ttl);
	rec->record.locator_count = lcount;
	rec->record.eid_mask_len = p->prefixlen;
	
	/* Negative Map-Reply */
	if (0 == lcount) {
		rec->record.act = act;
	}
	rec->record.a = A;
	rec->record.version = htonl(version);

	switch (p->family) {
	case AF_INET:
		rec->record.eid_prefix_afi = htons(LISP_AFI_IP);
		memcpy(&rec->record.eid_prefix, &p->u.prefix4, sizeof(struct in_addr));
		rpk->curs = CO(rec, sizeof(struct map_reply_record));
		break;
	case AF_INET6:
		rec->record6.eid_prefix_afi = htons(LISP_AFI_IPV6);
		memcpy(&rec->record6.eid_prefix, &p->u.prefix6, sizeof(struct in6_addr));
		rpk->curs = CO(rec, sizeof(struct map_reply_record6));
		break;
	default:
		assert(FALSE);
		break;
	}
	rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;
	
	/* ==================================================== */
	char buf[BSIZE];

	bzero(buf, BSIZE);
	inet_ntop(p->family, (void *)&p->u.prefix, buf, BSIZE);
	
	if (_debug == LDEBUG) {
		cp_log(LDEBUG, "EID %s/%d: ", buf, p->prefixlen);
		cp_log(LDEBUG, "<Lcount=%u", lcount);
		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "TTL=%u", ttl);
	}
	
	if (lcount == 0) {
		if (_debug == LDEBUG) {
			cp_log(LDEBUG, ", ");
			cp_log(LDEBUG, "ACT=%d", act);
		}
	}

	if (_debug == LDEBUG) {
		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "version=%u", version);
		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "A=%u", A);
		cp_log(LDEBUG, ">\n");
	}
	
	if (lcount == 0) {
		cp_log(LDEBUG, "\tNegative reply\n");
	}
		
	return (TRUE);
}

/* add more locator to message */
	int
sockunioncmp(void *m, void *n)
{
	union sockunion *sp, *dp;
	
	sp = m; dp = n;
	if (sp->sa.sa_family != dp->sa.sa_family)
		return -1;
		
	switch (sp->sa.sa_family) {
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

	int 
udp_reply_add_locator(void *data, struct map_entry *e)
{
	union map_reply_locator_generic *loc;
	struct map_reply_locator_te *loc_te;
	int lc = 0;
	struct pk_rpl_entry *rpk = data;
	struct list_entry_t *ptr, *p;
	struct pe_entry *pe;
	struct lcaf_hdr *lcaf;
	union rloc_te_generic *hop;
	struct hop_entry *haddr;
	char buf[BSIZE];
	struct map_reply_hdr *rhdr;
	
	rhdr = (struct map_reply_hdr *)rpk->buf;
	if ((_fncs & (_FNC_XTR | _FNC_MS)) && lisp_te && e->pe) {
		ptr = e->pe->head.next;
		while (ptr != &e->pe->tail) {
			pe = (struct pe_entry*)ptr->data;
			loc_te = (struct map_reply_locator_te *)rpk->curs;

			loc_te->priority = pe->priority;
			loc_te->weight = pe->weight;
			loc_te->m_priority = pe->m_priority;
			loc_te->m_weight = pe->m_weight;
			loc_te->L = e->L;
			if (rhdr->rloc_probe) {
				if (sockunioncmp(&e->rloc, &((struct pk_req_entry *)rpk->request_id)->di) == 0)
					loc_te->p = 1;
			}else
				loc_te->p = 0;
			loc_te->R = e->r;
			
			lcaf = (struct lcaf_hdr *)&(loc_te->lcaf);
			lcaf->afi = htons(LCAF_AFI);
			lcaf->type = LCAF_TE;
			
			cp_log(LDEBUG, "\t•[rloc=TE, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
					loc_te->priority, \
					loc_te->weight, \
					loc_te->m_priority, \
					loc_te->m_weight, \
					loc_te->R, \
					loc_te->L, \
					loc_te->p);			
			
			/*list of hop */
			p = pe->hop->head.next;
			hop = rpk->curs = CO(loc_te, sizeof(struct map_reply_locator_te));
			while (p != &pe->hop->tail) {
				/* add chain hop to message */
				haddr = (struct hop_entry *)p->data;
				switch (haddr->addr.sa.sa_family) {
				case AF_INET:
					hop->rloc.afi = htons(LISP_AFI_IP);
					hop->rloc.L	= haddr->L;
					hop->rloc.P  = haddr->P;
					hop->rloc.S  = haddr->S;
					memcpy(&hop->rloc.hop_addr, &haddr->addr.sin.sin_addr, sizeof(struct in_addr));
					inet_ntop(AF_INET, (void *)&hop->rloc.hop_addr, buf, BSIZE);
					hop = rpk->curs = CO(hop, sizeof(struct rloc_te));						
					break;
				case AF_INET6:
					hop->rloc.afi = htons(LISP_AFI_IPV6);
					hop->rloc.L	= haddr->L;
					hop->rloc.P  = haddr->P;
					hop->rloc.S  = haddr->S;
					memcpy(&hop->rloc6.hop_addr, &haddr->addr.sin6.sin6_addr, sizeof(struct in6_addr));
					inet_ntop(AF_INET, (void *)&hop->rloc6.hop_addr, buf, BSIZE);
					hop = rpk->curs = CO(hop, sizeof(struct rloc6_te));						
					break;
				default:
					assert(FALSE);
				}
				cp_log(LDEBUG, "\t\t•[hop=%s]\n", buf);		
								
				p = p->next;				
			}
			/*rloc as last hop */
			switch (e->rloc.sa.sa_family) {
			case AF_INET:
				hop->rloc.afi = htons(LISP_AFI_IP);
				memcpy(&hop->rloc.hop_addr, &e->rloc.sin.sin_addr, sizeof(struct in_addr));
				inet_ntop(AF_INET, (void *)&hop->rloc.hop_addr, buf, BSIZE);
				hop = rpk->curs = CO(hop, sizeof(struct rloc_te));
				break;
			case AF_INET6:
				hop->rloc.afi = htons(LISP_AFI_IPV6);
				memcpy(&hop->rloc.hop_addr, &e->rloc.sin.sin_addr, sizeof(struct in6_addr));
				inet_ntop(AF_INET, (void *)&hop->rloc6.hop_addr, buf, BSIZE);
				hop = rpk->curs = CO(hop, sizeof(struct rloc6_te));
				break;
			default:
				assert(FALSE);
			}
			cp_log(LDEBUG, "\t\t•[hop=%s]\n", buf);		
			lcaf->payload_len = htons(((char *)rpk->curs - (char *)lcaf) - sizeof(struct lcaf_hdr));
			lc++;
			ptr = ptr->next;
		}
		rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;	
	}/* not te */
	else{
		loc = (union map_reply_locator_generic *)rpk->curs;

		loc->rloc.priority = e->priority;
		loc->rloc.weight = e->weight;
		loc->rloc.m_priority = e->m_priority;
		loc->rloc.m_weight = e->m_weight;
		loc->rloc.L = e->L;
		if (rhdr->rloc_probe) {
			if (sockunioncmp(&e->rloc, &((struct pk_req_entry *)rpk->request_id)->di) == 0)
				loc->rloc.p = 1;
		} else {
			loc->rloc.p = 0;
		}

		loc->rloc.R = e->r;

		switch (e->rloc.sa.sa_family) {
		case AF_INET:
			loc->rloc.rloc_afi = htons(LISP_AFI_IP);
			memcpy(&loc->rloc.rloc, &e->rloc.sin.sin_addr, sizeof(struct in_addr));
			rpk->curs = CO(loc, sizeof(struct map_reply_locator));
			break;
		case AF_INET6:
			loc->rloc6.rloc_afi = htons(LISP_AFI_IPV6);
			memcpy(&loc->rloc6.rloc, &e->rloc.sin6.sin6_addr, sizeof(struct in6_addr));
			rpk->curs = CO(loc, sizeof(struct map_reply_locator6));
			break;
		default:
			assert(FALSE);
		}

		rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;

		/* ================================================= */
		bzero(buf, BSIZE);
		switch (e->rloc.sa.sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, (void *)&e->rloc.sin.sin_addr, buf, BSIZE);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, (void *)&e->rloc.sin6.sin6_addr, buf, BSIZE);
			break;
		default:
			cp_log(LDEBUG, "unsuported family\n");
			return (FALSE);
		}
		cp_log(LDEBUG, "\t[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
					buf, \
					loc->rloc.priority, \
					loc->rloc.weight, \
					loc->rloc.m_priority, \
					loc->rloc.m_weight, \
					loc->rloc.R, \
					loc->rloc.L, \
					loc->rloc.p);			
		
		lc++;
	}
	return (TRUE);
}


/* send map-reply */
	int 
udp_reply_terminate(void *data)
{
	union sockunion local;
	int socket;
	socklen_t slen;
	struct pk_req_entry *pke;
	struct pk_rpl_entry *rpk = data;
	union sockunion itr;
	uint16_t itr_port;
	
	cp_log(LDEBUG, "Send Map-Reply ");
		
	pke = rpk->request_id;
		
	if (pke->type != LISP_TYPE_MAP_REQUEST) {
		memcpy(&local, &pke->si, sizeof(local));
	}else {
		/* choose one ITR */
		if (udp_request_get_itr(pke,&itr,0) <= 0)
			return -1;
		
		if (!pke->ecm) {
			if (pke->si.sin.sin_family == AF_INET)
                itr_port = pke->si.sin.sin_port;
            else
                itr_port = pke->si.sin6.sin6_port;
		}
		
		local.sin.sin_family = itr.sin.sin_family;
		if (itr.sin.sin_family == AF_INET) {	
			memcpy(&local.sin.sin_addr, &itr.sin.sin_addr, SIN_LEN(AF_INET));
			if (pke->ecm)
				local.sin.sin_port = pke->ih_si.sin.sin_port;
			else
				local.sin.sin_port = itr_port;
		}
		else{
			memcpy(&local.sin6.sin6_addr, &itr.sin6.sin6_addr, SIN_LEN(AF_INET6));
			if (pke->ecm)
				local.sin6.sin6_port = pke->ih_si.sin6.sin6_port;
			else
				local.sin6.sin6_port = itr_port;
		}	
	}

	if (_debug == LDEBUG) {
		cp_log(LDEBUG, "to %s:%d\n", 
				sk_get_ip(&local, ip), sk_get_port(&local) );
		cp_log(LDEBUG, "Sending packet... ");
	}

	socket = 0;
	if ((local.sa).sa_family == AF_INET) {
		socket = skfd;
		slen = sizeof(struct sockaddr_in);
	}
	else if ((local.sa).sa_family == AF_INET6) {
		socket = skfd6;
		slen = sizeof(struct sockaddr_in6);
	}
	
	if (socket) {
		if (sendto(socket, (char *)rpk->buf, rpk->buf_len, 0, (struct sockaddr *)&(local.sa), slen) == -1) {
			cp_log(LLOG, "failed\n");
			perror("sendto()");
			_free_rpl_pool_place(rpk, _rm_rpl);
			return (FALSE);
		}
	}	
	else{
		if (_debug == LDEBUG) {
			cp_log(LDEBUG, "failed\n");
			perror("select_socket");
		}
		
		_free_rpl_pool_place(rpk, _rm_rpl);
		return (FALSE);
	}
	cp_log(LDEBUG, "done\n");
	_free_rpl_pool_place(rpk, _rm_rpl);
	return (TRUE);
}

/* error when process */
	int 
udp_reply_error(void *data)
{
	cp_log(LDEBUG, "Unknown error\n");
	return (TRUE);
}

/* ========================================================== */
/*  Map-Referral handling code */
/* make new map-referral message */
	void *
udp_referral_add(void *data)
{
	struct map_referral_hdr *hdr;
	uint32_t *nonce_trick;
	uint64_t nonce;
	struct pk_req_entry *pke = data;
	struct pk_rpl_entry *rpk;
	
	rpk = _get_rpl_pool_place();
	rpk->curs = rpk->buf;
	rpk->buf_len = 0;
	rpk->request_id = pke;
	
	hdr = (struct map_referral_hdr *)rpk->buf;
	/* write the 64-bit nonce in two 32-bit fields
	*  need this trick because of the LITTLE_ENDIAN
	*/
	udp_request_get_nonce(pke, &nonce);
	nonce_trick = (void *)(&nonce);
	hdr->lisp_type = LISP_TYPE_MAP_REFERRAL;
	hdr->lisp_nonce0 = htonl(*nonce_trick);
	hdr->lisp_nonce1 = htonl(*(nonce_trick + 1));
	
	if (_debug == LDEBUG) {
		/* ================================= */
		cp_log(LDEBUG, "Map-Referral ");
		cp_log(LDEBUG, " <");
		cp_log(LDEBUG, "nonce=0x%x - 0x%x", ntohl(hdr->lisp_nonce0), ntohl(hdr->lisp_nonce1));
		cp_log(LDEBUG, ">\n");
		/* ================================= */
	}
	
	rpk->curs = (void *)CO(hdr, sizeof(struct map_referral_hdr));
	rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;
	return rpk;
}

/* add new record to map-referral */
	int 
udp_referral_add_record(void *data, uint32_t iid, struct prefix *p, uint32_t ttl, uint8_t lcount, 
						uint32_t version, uint8_t A, uint8_t act, uint8_t i, uint8_t sigcnt)
{
	union map_referral_record_generic *rec;
	struct map_referral_hdr *hdr;
	struct pk_rpl_entry *rpk = data;
	
	hdr = (struct map_referral_hdr *)rpk->buf;
	hdr->record_count++;
	
	rec = (union map_referral_record_generic *)rpk->curs;

	rec->record.ttl = htonl(ttl);
	rec->record.referral_count = lcount;
	rec->record.eid_mask_len = p->prefixlen;

	rec->record.act = act;
	rec->record.a = A;
	rec->record.version = htonl(version);
	rec->record.i = i;
	rec->record.sig_cnt = sigcnt;
	rec->record.lcaf.afi = htons(LCAF_AFI);
	rec->record.lcaf.type = 2;
	/*fix code */
	rec->record.lcaf.iid = iid;
	
	switch (p->family) {
	case AF_INET:
		rec->record.eid_prefix_afi = htons(LISP_AFI_IP);
		memcpy(&rec->record.eid_prefix, &p->u.prefix4, sizeof(struct in_addr));
		rpk->curs = CO(rec, sizeof(struct map_referral_record));
		rec->record.lcaf.length = htons(4+2+sizeof(struct in_addr));
		break;
	case AF_INET6:
		rec->record6.eid_prefix_afi = htons(LISP_AFI_IPV6);
		memcpy(&rec->record6.eid_prefix, &p->u.prefix6, sizeof(struct in6_addr));
		rpk->curs = CO(rec, sizeof(struct map_referral_record6));
		rec->record.lcaf.length = htons(4+2+sizeof(struct in6_addr));
		break;
	default:
		assert(FALSE);
		break;
	}
	
	rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;
	/* ==================================================== */
	char buf[BSIZE];

	bzero(buf, BSIZE);
	inet_ntop(p->family, (void *)&p->u.prefix, buf, BSIZE);
	if (_debug == LDEBUG) {
		cp_log(LDEBUG, "EID %s/%d: ", buf, p->prefixlen);

		cp_log(LDEBUG, "<");
		cp_log(LDEBUG, "ref_count=%u", lcount);
		
		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "TTL=%u", ttl);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "ACT=%d", act);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "version=%u", version);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "A=%u", A);

		cp_log(LDEBUG, ">\n");
	}
	
	if (lcount == 0)
		cp_log(LDEBUG, "\tNegative referral\n");
	
	/* ====================================================== */
	return (TRUE);
}

/* add new locator  to map-referral-record */
	int 
udp_referral_add_locator(void *data, struct map_entry *e)
{
	union map_referral_locator_generic *loc;
	struct pk_rpl_entry *rpk = data;
	
	loc = (union map_referral_locator_generic *)rpk->curs;

	loc->rloc.priority = e->priority;
	loc->rloc.weight = e->weight;
	loc->rloc.m_priority = e->m_priority;
	loc->rloc.m_weight = e->m_weight;
	loc->rloc.R = e->r;

	switch (e->rloc.sa.sa_family) {
	case AF_INET:
		loc->rloc.rloc_afi = htons(LISP_AFI_IP);
		memcpy(&loc->rloc.rloc, &e->rloc.sin.sin_addr, sizeof(struct in_addr));
		rpk->curs = CO(loc, sizeof(struct map_referral_locator));
		break;
	case AF_INET6:
		loc->rloc6.rloc_afi = htons(LISP_AFI_IPV6);
		memcpy(&loc->rloc6.rloc, &e->rloc.sin6.sin6_addr, sizeof(struct in6_addr));
		rpk->curs = CO(loc, sizeof(struct map_referral_locator6));
		break;
	default:
		assert(FALSE);
	}
	rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;
	/* ================================================= */
	char buf[BSIZE];
	bzero(buf, BSIZE);
	switch (e->rloc.sa.sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, (void *)&e->rloc.sin.sin_addr, buf, BSIZE);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, (void *)&e->rloc.sin6.sin6_addr, buf, BSIZE);
		break;
	default:
		cp_log(LDEBUG, "unsuported family\n");
		return (FALSE);
	}

	cp_log(LDEBUG, "\t[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d]\n", \
				buf, \
				e->priority, \
				e->weight, \
				e->m_priority, \
				e->m_weight, \
				e->r);
	
	/* ================================================= */

	return (TRUE);
}

	int 
udp_referral_error(void *data)
{
	cp_log(LDEBUG, "referral_error\n");
	return (TRUE);
}

/* send map-referral */
	int 
udp_referral_terminate(void *data)
{
	union sockunion local;
	int socket;
	struct pk_req_entry *pke;
	struct pk_rpl_entry *rpk = data;

	socklen_t slen;
	cp_log(LDEBUG, "send Map-Referral ");
	
	pke = rpk->request_id;
	memcpy(&local, &pke->si, sizeof(local));
	sk_set_port(&local,LISP_CP_PORT);
	
	if (_debug == LDEBUG) {
		cp_log(LDEBUG, "to %s:%d\n", 
				sk_get_ip(&local, ip), sk_get_port(&local) );
		cp_log(LDEBUG, "Sending packet... ");
	}
	
	socket = 0;
	if ((local.sa).sa_family == AF_INET) {
		socket = skfd;
		slen = sizeof(struct sockaddr_in);
	}
	else if ((local.sa).sa_family == AF_INET6) {
		socket = skfd6;
		slen = sizeof(struct sockaddr_in6);
	}
	
	if (socket) {
		if (sendto(socket, rpk->buf, rpk->buf_len, 0, (struct sockaddr *)&(local.sa), slen) == -1) {
			cp_log(LLOG, "failed\n");
			perror("sendto()");
			_free_rpl_pool_place(rpk, _rm_rpl);
			return (FALSE);
		}
	}
	else{
		if (_debug == LDEBUG) {
			cp_log(LDEBUG, "failed\n");
			perror("select_socket");
		}	
		_free_rpl_pool_place(rpk, _rm_rpl);
		
		return (FALSE);
	}
	cp_log(LDEBUG, "done\n");
	_free_rpl_pool_place(rpk, _rm_rpl);
	return (TRUE);	
}

/* ========================================================== */
/*  Map-Request handling code */

/* support function */

/* free map-request from queue */
	int 
udp_request_terminate(void *data)
{
	udp_free_pk(data);
	return (TRUE);
}

/* get first eid in map-request */
/* future need support many eid(s) in map-request */
	int 
udp_request_get_eid(void *data, struct prefix *pr)
{
	/* at this vesion, get the first eid in list */
	struct list_t * ll;
	struct list_entry_t *l;
	struct pk_req_entry *pke = data;
	
	if (!pke->eid)
		return -1;
	
	ll = (struct list_t *)pke->eid;	
	
	if (ll->count <=0)
		return -1;
	
	l = ll->head.next;
	memcpy(pr, l->data, sizeof(struct prefix));
	return (TRUE);
}

/* get nonce from map-request */
	int 
udp_request_get_nonce(void *data, uint64_t * nonce)
{
	uint32_t *nonce_trick;
	struct pk_req_entry *pke = data;

	nonce_trick = (uint32_t *)nonce;
	*nonce_trick = pke->nonce0;
	*(nonce_trick+1) = pke->nonce1;
	
	return (TRUE);
}

/* check if map-request is ddt bit set or not */
	int 
udp_request_is_ddt(void *data, int *is_ddt)
{
	struct pk_req_entry *pke = data;

	*is_ddt = pke->ddt;
	return (TRUE);
}
	
/* get itr suit with afi, if afi = 0, choose the first in list */	
	int 
udp_request_get_itr(void *data, union sockunion *itr, int afi)
{
	struct pk_req_entry *pke = data;
	struct list_t	*ll;
	struct list_entry_t *l;
	union afi_address_generic *afi_address;
	int i = 0;
	
	if (!pke->itr)
		return -1;
	
	ll = (struct list_t *)pke->itr;	
	if (ll->count <=0)
		return -1;
		
	l = pke->itr->head.next;
	/* run over itr list to choose the first itr match with afi */
	while (l != &pke->itr->tail) {
		afi_address = (union afi_address_generic *)l->data;
		/* afi ==0 --> get the first itr */
		if (afi == ntohs(afi_address->ip.afi) || afi == 0) {
			i++;
			switch (ntohs(afi_address->ip.afi)) {
			case AF_INET:
				memcpy(&itr->sin.sin_addr,&afi_address->ip.address,sizeof(struct in_addr));
				itr->sin.sin_family = AF_INET;
				break;
			case AF_INET6:
				memcpy(&itr->sin6.sin6_addr,&afi_address->ip6.address,sizeof(struct in6_addr));
				itr->sin6.sin6_family = AF_INET6;
				break;
			default:
				cp_log(LDEBUG, "AF not support\n");
				return -1;
			}
			break;
		}
		l = l->next;
	}	
	return (i>0);
}

/* get source port of OH's udp*/
	int 
udp_request_get_port(void *data, uint16_t *port)
{
	struct pk_req_entry *pke = data;
	union sockunion *si_other;

	if (pke->ecm)
		si_other = &(pke->ih_si);
	else
		si_other = &(pke->si);

	if ((si_other->sa).sa_family == AF_INET)
		*port = ntohs((si_other->sin).sin_port);
	else
		*port = ntohs((si_other->sin6).sin6_port);	
	
	return (TRUE);
}

/* generate checksum of IP header; nwords is the length of the header measured in 16-bit words */
	uint16_t
ip_checksum (uint16_t *buf, int nwords)
{
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/* make a new map-request message -	EMC package */
	void *
udp_request_add(void *data, uint8_t security, uint8_t ddt,\
		uint8_t A, uint8_t M, uint8_t P, uint8_t S,\
		uint8_t p, uint8_t s,\
		uint32_t nonce0, uint32_t nonce1,\
		const union sockunion *src,\
		const union sockunion *dst,\
		uint16_t source_port,\
		const struct prefix *eid)
{
	size_t itr_size;
	size_t ip_len;
	struct pk_req_entry *pke = data;
	struct pk_rpl_entry *rpk;
	/* the different parts of the packet */
	/* type 8 encapsulation part */
	struct lisp_control_hdr *lh;
	struct ip *ih;	/*set source and destination IPs */
	struct ip6_hdr *ih6;
	struct udphdr *udp /* dst port 4342 */;
	/* map request part */
	/* type 1 */
	struct map_request_hdr *lcm;
	union afi_address_generic *itr_rloc;
	//union map_request_record_generic_lcaf * rec;
	union map_request_record_generic *rec;
	union afi_address_generic afi_addr_src, afi_addr_dst;
		
	rpk = _get_rpl_pool_place();
	rpk->curs = rpk->buf;
	rpk->buf_len = 0;
	rpk->request_id = pke;
	
	_sockunion_to_afi_address(src, &afi_addr_src);
	_sockunion_to_afi_address(dst, &afi_addr_dst);
		
	/* point to the correct place in the packet */
	lh = (struct lisp_control_hdr *)rpk->buf;
	ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
	ih6 = (struct ip6_hdr *)CO(lh, sizeof(struct lisp_control_hdr));
	
	switch (eid->family) {
	case AF_INET: 
		udp = (struct udphdr *)CO(ih, sizeof(struct ip));
		break;
	case AF_INET6:
		udp = (struct udphdr *)CO(ih, sizeof(struct ip6_hdr));
		break;
	default:
		cp_log(LDEBUG, "AF not support, ignore \n");
		return NULL;
	}		
	lcm = (struct map_request_hdr*)CO(udp, sizeof(struct udphdr));

	/* set all the LISP flags  */
	lh->type = LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE;
	lh->security_bit = security;
	lh->ddt_originated = ddt;
	lcm->lisp_type = LISP_TYPE_MAP_REQUEST;
	lcm->auth_bit = A;
	lcm->map_data_present = M;
	lcm->rloc_probe = P;
	lcm->smr_bit = S;
	lcm->pitr_bit = p;
	lcm->smr_invoke_bit = s;
	/* XXX dsa hard coded */
	lcm->irc = 0;
	lcm->record_count = 1;
	lcm->lisp_nonce0 = htonl(nonce0);
	lcm->lisp_nonce1 = htonl(nonce1);
	
	/* set no source EID <AFI=0, addres is empty> -> jump of 2 bytes */
	/* nothing to do as bzero of the packet at init */
	itr_rloc = (union afi_address_generic *)CO(lcm, sizeof(struct map_request_hdr) + 2);

	/* set source ITR */
	struct list_t *ll;
	struct list_entry_t *l;
	
	ll = pke->itr;
	if (!ll)
		return NULL;
	l = ll->head.next;

	while (l != &ll->tail) {			
		memcpy(itr_rloc, l->data,sizeof(union afi_address_generic));
		if (ntohs(itr_rloc->ip.afi) == AF_INET)
			itr_rloc->ip.afi = htons(LISP_AFI_IP);
		else
			itr_rloc->ip6.afi = htons(LISP_AFI_IPV6)	;

		itr_size = _get_address_size(itr_rloc);
		itr_rloc = (union afi_address_generic *)CO(itr_rloc,itr_size);
		lcm->irc++;
		l = l->next;
	}
	lcm->irc--;/* ACTUAL NUMBER OF ITR-RLOCs is (IRC + 1 ) */
	
	rec = (union map_request_record_generic *)itr_rloc;
	
	switch (eid->family) {
	case AF_INET:
		rec->record.eid_mask_len = eid->prefixlen;
		rec->record.eid_prefix_afi = htons(LISP_AFI_IP);
		memcpy(&rec->record.eid_prefix, &eid->u.prefix4, sizeof(struct in_addr));

		/* EID prefix is an IPv4 so 32 bits (4 bytes) */
		rpk->curs = (void *)CO(rec, sizeof(struct map_request_record));
		break;
	case AF_INET6:
		rec->record6.eid_mask_len = eid->prefixlen;
		rec->record.eid_prefix_afi = htons(LISP_AFI_IPV6);
		memcpy(&rec->record6.eid_prefix, &eid->u.prefix6, sizeof(struct in6_addr));

		/* EID prefix is an IPv6 so 128 bits (16 bytes) */ 
		rpk->curs = (void *)CO(rec, sizeof(struct map_request_record6));
		break;
	default:
		cp_log(LDEBUG, "not supported\n");
		return NULL;
	}

	/* set the UDP parameters */
#ifdef BSD
	udp->uh_sport = htons(source_port);
	udp->uh_dport = htons(LISP_CP_PORT);
	udp->uh_ulen = htons((uint8_t *)rpk->curs - (uint8_t *) udp);
	udp->uh_sum = 0;
#else
	udp->source = htons(source_port);
	udp->dest = htons(LISP_CP_PORT);
	udp->len = htons((uint8_t *)rpk->curs - (uint8_t *) udp );
	udp->check = 0;
#endif

	/* setup the IP parameters */
	switch (eid->family) {
	case AF_INET: 
		ip_len = (uint8_t *)rpk->curs - (uint8_t *) ih;
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
		ih->ip_sum 		  = ip_checksum((uint16_t *)ih, (ih->ip_hl)*2);
		break;
	case AF_INET6:
		ip_len = (uint8_t *)rpk->curs - (uint8_t *) udp;
		ih6->ip6_vfc	  = 0x6E; //version
		ih6->ip6_plen	  = htons(ip_len); //payload length
		ih6->ip6_nxt      = IPPROTO_UDP;//nex header
		ih6->ip6_hlim     = 64; //hop limit      
		memcpy(&ih6->ip6_src, &afi_addr_src.ip6.address, sizeof(struct in6_addr));
		memcpy(&ih6->ip6_dst, &afi_addr_dst.ip6.address, sizeof(struct in6_addr));
		break;
	default:
		cp_log(LDEBUG, "AF not support, ignore \n");
		return NULL;
	}	
		
	rpk->buf_len = (char *)rpk->curs - (char *)rpk->buf;
	if (_debug == LDEBUG) {
		/* ================================= */
		cp_log(LDEBUG, "Map-Request-Referral ");
		cp_log(LDEBUG, " <");
		cp_log(LDEBUG, "nonce=0x%x - 0x%x", nonce0, nonce1);
		cp_log(LDEBUG, ">\n");
		/* ================================= */
	}
	return rpk;
}

	int 
udp_request_ddt_terminate(void *data, const union sockunion *server, char terminal)
{
	union sockunion servaddr;
	int skt;
	socklen_t slen;
	struct pk_rpl_entry *rpk = data;
	
	bzero(&servaddr,sizeof(servaddr));
	memcpy(&servaddr,server, sizeof(servaddr));
	/* for testing: fix soure of map-request-ddt to 4342 */
	if ((server->sa).sa_family == AF_INET) {
		skt = skfd;
		(servaddr.sin).sin_port=ntohs(LISP_CP_PORT);
		slen = sizeof(struct sockaddr_in);
	}else if ((server->sa).sa_family == AF_INET6) {
		skt = skfd6;
		(servaddr.sin6).sin6_port=ntohs(LISP_CP_PORT);
		slen = sizeof(struct sockaddr_in6);
	}
	else{
		return 0;
	}
	
	/* here is flow the ietf: choose a randome source port --> must listent to received the reply	
	
	if ((server->sa).sa_family == AF_INET) {
		(servaddr.sin).sin_port=ntohs(LISP_CP_PORT);
		if ((skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			perror("socket");
			exit(0);
		}
		slen = sizeof(struct sockaddr_in);
	}else if ((server->sa).sa_family == AF_INET6) {
		(servaddr.sin6).sin6_port=ntohs(LISP_CP_PORT);
		if ((skt = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			perror("socket");
			exit(0);
		}
		slen = sizeof(struct sockaddr_in6);
	}
	else
		return 0;
	*/
	
	/*=============================*/
	if (_debug == LDEBUG) {
		cp_log(LDEBUG,  "send Map-Request-Referral ");
		cp_log(LDEBUG,  "to %s:%d\n", 
				sk_get_ip(&servaddr, ip), sk_get_port(&servaddr) );
		cp_log(LDEBUG, "Sending packet... ");
	}
	/*=============================*/
	if (sendto(skt, rpk->buf, rpk->buf_len, 0, (struct sockaddr *)&(servaddr.sa),slen) < 0) {
			cp_log(LLOG, "failed\n");
			perror("sendto()");
			_free_rpl_pool_place(rpk, _rm_rpl);
			close(skt);
			return (FALSE);
	}
	
	cp_log(LLOG, "done\n");
	
	if (terminal) {
		udp_free_pk(rpk->request_id);
	}
	_free_rpl_pool_place(rpk, _rm_rpl);
	
	return (TRUE);		
}

/* ========================================================== */
/* forwarding package to outside network*/
	uint32_t 
_forward(void *data)
{
	/*
	 * XXX dsa: DANGER RISK OF BUG
	 * => code duplication with uint32_t udp_prc_request(const void *)
	 */
	struct pk_req_entry *pke = data;
	struct lisp_control_hdr *lh;
	struct ip *ih;
	struct ip6_hdr *ih6;
	struct udphdr *udp;
	struct map_request_hdr *lcm;
	union sockunion sin;
	int one;
	int s;
	void *packet = pke->buf;	
	union sockunion *si_other = &pke->si;
	
	
	cp_log(LDEBUG, "Forwardig.....\n");
	
	lh = (struct lisp_control_hdr *)CO(packet, 0);
	/* Encapsulated Control Message Format => decap first */
	if (lh->type != LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE) {
		cp_log(LDEBUG, "Forwarding works only on Encapsulated Control Message mode\n");
			
		return (FALSE);
	}
	
	ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
	if (ih->ip_v == 4) {
		ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
		ih6	= NULL;
		udp = (struct udphdr *)CO(ih, sizeof(struct ip));
	}
	else {
		if (ih->ip_v == 6) {
			ih		= NULL;
			ih6	= (struct ip6_hdr *) CO(lh, sizeof(struct lisp_control_hdr));
			udp	= (struct udphdr *) CO(ih6,  sizeof(struct ip6_hdr));
		}
		else{
			cp_log(LDEBUG, "IP version not correct: Only support IPv4 and IPv6\n");
				
			return (0);
		}
	}	
	udp = (struct udphdr *)CO(ih, sizeof(struct ip));
	lcm = (struct map_request_hdr *)CO(udp, sizeof(struct udphdr));

	if (lcm->lisp_type != LISP_TYPE_MAP_REQUEST) {
		cp_log(LDEBUG, "Forwarding works only with Map-Request\n");
			
		return (FALSE);
	}

	bzero(&sin, sizeof(sin));
	if ((si_other->sa).sa_family == AF_INET) {
		sin.sin.sin_family = (si_other->sin).sin_family;
		sin.sin.sin_port = (si_other->sin).sin_port;
	}else{
		sin.sin6.sin6_family = (si_other->sin6).sin6_family;
		sin.sin6.sin6_port = (si_other->sin6).sin6_port ;
	}

	ih->ip_len = ntohs(ih->ip_len);
	ih->ip_sum = 0; 
#ifdef BSD
	udp->uh_sum = 0;
#else
	udp->check = 0;
#endif

	cp_log(LDEBUG, "Sending packet...");                                                                                                                      
	if ((s = socket (PF_INET, SOCK_RAW, IPPROTO_IP)) < 0) {
		perror("socket");
		return (FALSE);
	}

	one = 1;
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0) {
		perror("setsockopt");
		close(s);
		return (FALSE);
	}
	if (sendto(s,(void *)ih, (ih->ip_len), 0, (struct sockaddr *)&sin, sizeof (struct sockaddr)) < 0) {
		perror("sendto");
		close(s);
		return (FALSE);
	}
	cp_log(LDEBUG, "done\n");
	close(s);
		
	return (TRUE);
}

/* forwarding to ETR */
	uint32_t 
_forward_to_etr(void *data, struct db_node *rn)
{
	/*
	 * XXX dsa: DANGER RISK OF BUG
	 * => code duplication with uint32_t udp_prc_request(const void *)
	 */
	struct pk_req_entry *pke = data; 
	struct lisp_control_hdr *lh;
	union sockunion sin;
	int skt = 0;
	int sin_len = 0;
	struct list_t *l = NULL;
	struct list_entry_t *_iter;
	struct map_entry *e = NULL;
	char ip[INET6_ADDRSTRLEN];
	void *packet = pke->buf;	
	int pkt_len = pke->buf_len;
	
	lh = (struct lisp_control_hdr *)CO(packet, 0);
	/* Encapsulated Control Message Format => decap first */
	if (lh->type != LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE) {
		cp_log(LDEBUG, "Forwarding works only on Encapsulated Control Message mode\n");
		return (FALSE);
	}

	lh->ddt_originated = 0;
	
	/*get first reachable ETR's rloc*/
	assert(rn);
	
	l = (struct list_t *)db_node_get_info(rn);
	assert(l);
	_iter = l->head.next;
	if (!_iter || _iter == &l->tail)
		return (0);
	
	while (_iter != &l->tail) {
		e = (struct map_entry*)_iter->data;
		if (e->r)
			break;
		_iter = _iter->next;
	}

	if (_iter == &l->tail)
		return (0);
	
	switch (e->rloc.sa.sa_family) {
	case AF_INET:
		sin.sin.sin_family = AF_INET;
		sin.sin.sin_port = ntohs(LISP_CP_PORT);
		memcpy(&(sin.sin.sin_addr), &(e->rloc.sin.sin_addr), sizeof(struct in_addr));
		inet_ntop(AF_INET, (void *)&(e->rloc.sin.sin_addr), ip, INET_ADDRSTRLEN);
		if ((skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			perror("socket");
			exit(0);
		}
		sin_len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		sin.sin6.sin6_family = AF_INET6;
		sin.sin6.sin6_port = ntohs(LISP_CP_PORT);
		memcpy(&(sin.sin6.sin6_addr), &(e->rloc.sin6.sin6_addr), sizeof(struct in6_addr));
		inet_ntop(AF_INET6, (void *)&e->rloc.sin.sin_addr, ip, INET6_ADDRSTRLEN);

		if ((skt = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			perror("socket");
			exit(0);
		}
		
		sin_len = sizeof(struct sockaddr_in6);
		break;
	default:
		assert(FALSE);
	}
	cp_log(LDEBUG, "Forwarding to %s\n",ip);
		
	if (sendto(skt,(void *)packet, pkt_len, 0, (struct sockaddr *)&sin.sa, sin_len) < 0) {
		perror("sendto");
		close(skt);
		return (-1);
	}
	close(skt);
	cp_log(LDEBUG, "done\n");
	return (TRUE);
}

/* ========================================================== */
/* Main process */

/* init ipv4 and ipv6 binding */
	int
udp_init_socket()
{
	struct addrinfo	    hints;
    struct addrinfo	    *res;
	int e;
	char _str_port[NI_MAXSERV];
	
	/*get port */
	sprintf(_str_port, "%d", LISP_CP_PORT);
	
	/* socket for bind ipv4 */
	if ((skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		perror("socket");
		exit(0);
	}
		
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = IPPROTO_UDP;
	
	if ((e = getaddrinfo(NULL, _str_port, &hints, &res)) != 0) {
		cp_log(LLOG, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(0);
	}
	
	if (bind(skfd, res->ai_addr, res->ai_addrlen) == -1) {
		perror("bind");
		close(skfd);
		exit(0);
	}
	int ip_recvaddr = 1;
	
	setsockopt(skfd, IPPROTO_IP, IP_RECVDSTADDR, &ip_recvaddr, sizeof(ip_recvaddr));
	
	/* socket for bind ipv6 */
	if ((skfd6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			perror("socket6");
			exit(0);
	}
		
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET6;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = IPPROTO_UDP;
	
	if ((e = getaddrinfo(NULL, _str_port, &hints, &res)) != 0) {
		cp_log(LLOG, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(0);
	}
		
	if (bind(skfd6, res->ai_addr, res->ai_addrlen) == -1) {
		perror("bind");
		close(skfd6);
		exit(0);
	}
	setsockopt(skfd6, IPPROTO_IPV6,IPV6_RECVPKTINFO , &ip_recvaddr, sizeof(ip_recvaddr));
	
	return 1;
}



/* process with new message in queue */
	void *
_lisp_process(void *data)
{
	void *buf;
	struct lisp_control_hdr *lh;
	struct info_msg_hdr *imh;
	int rt = 0;
	struct pk_req_entry *pke = data;	
	
	udp_preparse_pk(pke);
	buf = pke->buf;
	
	lh = (struct lisp_control_hdr *)CO(buf, 0);
	/* action depends on the LISP type */				
	switch (lh->type) {
		/* Map-Request or DDT Map-Request */
	case LISP_TYPE_MAP_NOTIFY:
		//_xtr_notify(request_id);				
		udp_free_pk(pke);
		break;
	case LISP_TYPE_MAP_REQUEST:
		/* Parse request message */
		if (_fncs & _FNC_XTR) {
			rt = udp_prc_request(pke);
			if (rt <= 0) {
				cp_log(LDEBUG, "Not correct map-request.....Ignore!\n");
				
				udp_free_pk(pke);
				break;
			}
			xtr_generic_process_request(pke, &udp_fct);						
		}
		udp_free_pk(pke);
		break;
	case LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE:
		/* Parse request message */
		rt = udp_prc_request(pke);
		if (rt <= 0) {
			cp_log(LDEBUG, "Not a map-request.....Ignore!\n");
				
			udp_free_pk(pke);
			break;
		}
		
		if (_fncs & _FNC_XTR) {
			xtr_generic_process_request(pke, &udp_fct);
			udp_free_pk(pke);	
			break;
		}		
		else{
			if ((rt = generic_process_request(pke, &udp_fct)) <= 0) {
				cp_log(LDEBUG, "Forwarding mode\n");
				
				_forward(pke);					
			}
			if (rt < 2)
				udp_free_pk(pke);		
		}
		break;
		/* Map-Register */
	case LISP_TYPE_MAP_REGISTER:
		if (_fncs & _FNC_MS)
			_register(pke);
		udp_free_pk(pke);
		break;
		/* Map-Referral */
	case LISP_TYPE_MAP_REFERRAL:
		 get_mr_ddt(pke);
		 udp_free_pk(pke);
		 break;
		/* Map-Reply */
	case LISP_TYPE_MAP_REPLY:
#ifdef OPENLISP
		if (!srcport_rand)
			get_mr(pke);
#endif			
		udp_free_pk(pke);
		break;			
		/* Info-Request | Info-Reply */
	case LISP_TYPE_INFO_MSG:
		imh = (struct info_msg_hdr *)lh;
		if (_fncs & _FNC_MS && !imh->R)
			ms_process_info_req(pke);
		if (_fncs & _FNC_XTR && imh->R)
			/* TODO */;
		udp_free_pk(pke);
		break;
		/* unsupported */
	default:			
		udp_free_pk(pke);
		cp_log(LDEBUG, "unsupported LISP type %hhd\n", lh->type);
	}
	return NULL;
}

	int 
udp_get_pk(int sockfd, socklen_t slen)
{
	ssize_t pk_len;
	union sockunion ssk, dsk; /* source/destination address */
	struct lisp_control_hdr *lh;	
	struct pk_req_entry *pke;
	char buf[PKBUFLEN];
	struct iovec iov[1];
	struct cmsghdr *ctrmsg;
	char ctrdata[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct msghdr msg;
	union union_pktinfo{
		struct in_addr pkif;
		struct in6_pktinfo pkif6;
	} *pktinfo;
	
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);
	ctrmsg = NULL;
	
	msg.msg_name = &ssk;
	msg.msg_namelen = slen;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &ctrdata;
	msg.msg_controllen = sizeof(ctrdata);

	/* get packet from socket */	
	bzero(buf, PKBUFLEN);
	
	if ((pk_len = recvmsg(sockfd, &msg,0)) < 0) {
		cp_log(LDEBUG,"recvmsg: can not read data\n");
		return -1;
	}else if (msg.msg_flags & MSG_TRUNC) {
		cp_log(LDEBUG, "recvmsg: datagram too large for buffer: truncated\n");
		return -1;
	}
	
	cp_log(LLOG,  "Received packet (%zd bytes) from  %s:%d\n", pk_len, sk_get_ip(&ssk, ip) , sk_get_port(&ssk));
	
	switch (ssk.sa.sa_family) {
	case AF_INET:
		for (ctrmsg = CMSG_FIRSTHDR(&msg); ctrmsg != NULL; ctrmsg = CMSG_NXTHDR(&msg, ctrmsg)) {
			if ((ctrmsg->cmsg_level == IPPROTO_IP) && (ctrmsg->cmsg_type == IP_RECVDSTADDR)) {
				pktinfo = (union union_pktinfo *)(CMSG_DATA(ctrmsg));
				dsk.sin.sin_family = AF_INET;
				dsk.sin.sin_addr =  pktinfo->pkif;
				inet_ntop(AF_INET, &dsk.sin.sin_addr,ip, INET6_ADDRSTRLEN);
				cp_log(LDEBUG, "To: %s\n",ip);
				break;
			}
		}
		break;
	case AF_INET6:		
		for (ctrmsg = CMSG_FIRSTHDR(&msg); ctrmsg != NULL; ctrmsg = CMSG_NXTHDR(&msg, ctrmsg)) {
			if ((ctrmsg->cmsg_level == IPPROTO_IPV6) && (ctrmsg->cmsg_type == IPV6_PKTINFO)) {
				pktinfo = (union union_pktinfo *)(CMSG_DATA(ctrmsg));
				dsk.sin6.sin6_family = AF_INET6;
				memcpy(&dsk.sin6.sin6_addr, &pktinfo->pkif6.ipi6_addr, sizeof(struct in6_addr));
				inet_ntop(AF_INET6, &dsk.sin6.sin6_addr,ip, INET6_ADDRSTRLEN);
				cp_log(LDEBUG, "To: %s\n",ip);
				break;
			}				
		}
		break;
	}		
    
	/* if LISP packet, continue, else drop */
	lh = (struct lisp_control_hdr *)CO(buf, 0);
		
	switch (lh->type) {
	case LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE:
	case LISP_TYPE_MAP_REQUEST:
	case LISP_TYPE_MAP_REPLY:
	case LISP_TYPE_MAP_REGISTER:
	case LISP_TYPE_MAP_NOTIFY:
	case LISP_TYPE_MAP_REFERRAL:
	case LISP_TYPE_INFO_MSG:
		pke  = calloc(1,sizeof(struct pk_req_entry));
		pke->buf = calloc(pk_len,sizeof(char));			
		memcpy((char *)pke->buf, (char *)buf, pk_len);
		pke->buf_len = pk_len;
		memcpy((char *)&pke->si, (char *)&ssk, sizeof(ssk));
		memcpy((char *)&pke->di, (char *)&dsk, sizeof(dsk));				
		thr_pool_queue(cpp, _lisp_process, pke);
		break;
	default:
		cp_log(LDEBUG, "unsupported LISP type %hhu\n", lh->type);
		return -1;
	}
	return 1;
}
/* get message and push to queue */

	int 
udp_preparse_pk(void *data)
{
	struct lisp_control_hdr *lh;
	struct map_request_hdr *lcm;
	struct ip *ih;
	struct ip6_hdr *ih6;
	struct udphdr *udph;
	uint32_t hdr_len = 0;
	union sockunion *ih_si;
	struct pk_req_entry *pke = data;
	
	pke->ttl = 0;
	pke->hop = 0;
	pke->itr = pke->eid = NULL;	
	lh = (struct lisp_control_hdr *)CO(pke->buf, 0);
	if (pke->buf_len < sizeof(struct lisp_control_hdr))
		return -1;
		
	if (lh->type == LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE) {
		pke->lh = lh;
		pke->ecm = 1;
		pke->ddt = lh->ddt_originated;		
		lh = (struct lisp_control_hdr *)CO(lh, sizeof(struct lisp_control_hdr));
		hdr_len += sizeof(struct lisp_control_hdr);
		
		/* by pass UDP IH */
		pke->ih = ih = (struct ip *)lh;
		ih6 = (struct ip6_hdr *)lh;
		ih_si = (union sockunion *)&(pke->ih_si);
		if (((char *)ih - (char *)pke->buf + sizeof(struct ip) + sizeof(struct udphdr) ) > pke->buf_len)
			return -1;
			
		switch (ih->ip_v) {
		case 4:
			pke->udp = udph = (struct udphdr *)CO(lh,sizeof(struct ip));
			hdr_len += sizeof(struct ip) + sizeof(struct udphdr);							
			ih_si->sin.sin_family = AF_INET;
			#ifdef BSD
				ih_si->sin.sin_port = udph->uh_sport;					
			#else
				ih_si->sin.sin_port = udph->source;					
			#endif
			ih_si->sin.sin_addr = ih->ip_src;				
			break;
		case 6:
			pke->udp = udph = (struct udphdr *)CO(lh,sizeof(struct ip6_hdr));
			hdr_len += sizeof(struct ip6_hdr) + sizeof(struct udphdr);
			ih_si->sin.sin_family = AF_INET6;								
			#ifdef BSD
				ih_si->sin6.sin6_port = udph->uh_sport;					
			#else
				ih_si->sin6.sin6_port = udph->source;					
			#endif
			ih_si->sin6.sin6_addr = ih6->ip6_src;				
			break;
		default:
			cp_log(LDEBUG, "IP version not correct: Only support IPv4 and IPv6\n");
			return -1;
		}
			
		lh = (struct lisp_control_hdr *)CO(udph,sizeof(struct udphdr));			
	}
	
	if (((char *)lh - (char *)pke->buf + sizeof(struct lisp_control_hdr) + _NONESIZE) > pke->buf_len )
		return -1;

	switch (lh->type) {
	case LISP_TYPE_MAP_REQUEST:
	case LISP_TYPE_MAP_REPLY:
	case LISP_TYPE_MAP_REGISTER:
	case LISP_TYPE_MAP_NOTIFY:
	case LISP_TYPE_MAP_REFERRAL:
	case LISP_TYPE_INFO_MSG:
		pke->lcm = lcm = (struct map_request_hdr *)lh;
		pke->type = lh->type;
		pke->nonce0 = ntohl(lcm->lisp_nonce0);
		pke->nonce1 = ntohl(lcm->lisp_nonce1);
		break;	
	default:
		cp_log(LDEBUG, "unsupported LISP type %hhu\n", lh->type);
			
		return -1;
	}
	return 1;	
}
	
/* start control center */
	void *
udp_start_communication(void *context)
{
	int nready;
	int sockfd = 0;
	int pk_id;
	pthread_t _thr_map_register_process;
	pthread_t _thr_lisp_mr;
			
	socklen_t slen = 0;
	pthread_mutex_init(&ipq_mutex, NULL);
	pthread_cond_init(&ipq_cv,NULL);
				
	/* infinite loop to listen packets comming */
	_sk[0].fd = skfd;
	_sk[1].fd = skfd6;
	
	_sk[0].events = POLLRDNORM;
	_sk[1].events = POLLRDNORM;
	
	/*map-register process thread*/
	
	if (_fncs & _FNC_XTR) {
		pthread_create(&_thr_map_register_process, NULL, general_register_process, NULL);				
	}
	
#ifdef OPENLISP	
	pthread_t _thr_openlisp_plugin;
	if (_fncs & (_FNC_XTR | _FNC_RTR))
		pthread_create(&_thr_openlisp_plugin, NULL, plugin_openlisp, NULL);		
#endif	
	
	if (_fncs & _FNC_MR)
		pthread_create(&_thr_lisp_mr, NULL, mr_event_loop, NULL);

	cpp = thr_pool_create(min_thread,max_thread,linger_thread, NULL);	
	
	ipq_no = 0;	
	for (;;) {
		/* reset buffers */
		nready = poll(_sk, 2, INFTIM);
		if (nready <=0)
			continue;
		/* check socket ready to read */
		if (_sk[0].revents & POLLRDNORM) {
			sockfd = _sk[0].fd;
			slen = sizeof(struct sockaddr_in);
		}else if (_sk[1].revents & POLLRDNORM) {
			sockfd = _sk[1].fd;
			slen = sizeof(struct sockaddr_in6);
		}
		else
			continue;
		/* get next packet if number packet waitting < PK_POOL_MAX */
		if ((pk_id = udp_get_pk(sockfd,slen)) < 0) {
				cp_log(LDEBUG, "can not get package\n");
				continue;
		}
		pthread_mutex_lock(&ipq_mutex);
		if (ipq_no+1 >= PK_POOL_MAX)
			pthread_cond_wait(&ipq_cv, &ipq_mutex);
		
		ipq_no++;
		pthread_mutex_unlock(&ipq_mutex);					
	}	
	return NULL;
}

/* stop control center */
	void *
udp_stop_communication(void *context)
{
	cp_log(LDEBUG, "bye\n");
		
	return (NULL);	
}

/*
 * Process Map-Request
 * @param Map-Request LISP Control Message 
 */
	uint32_t 
udp_prc_request(void *data)
{
	struct lisp_control_hdr *lh;
	struct map_request_hdr *lcm;
	union afi_address_generic *eid_source;
	union afi_address_generic *itr_rloc;		/* current ITR-RLOC */
	union map_request_record_generic *rec;		/* current record */
	int ret;
	struct prefix *eid_prefix;
	union afi_address_generic *itr_address;
	struct pk_req_entry *pke = data;
	size_t eid_size;
	uint8_t icount;
	uint8_t rcount;
	char buf[BSIZE];
		
	/* Encapsulated Control Message Format => decap first */
	lcm = (struct map_request_hdr *)pke->lcm;
	
	if (pke->ecm) {
		lh = (struct lisp_control_hdr *)pke->lh;
		if (_debug == LDEBUG) {
			cp_log(LDEBUG, "LH: <type=%u>\n", lh->type);
			cp_log(LDEBUG, "Encapsulated Control Message mode <S=%u, D=%u>\n", lh->security_bit, lh->ddt_originated);
		}	
	}
	
	if (lcm->lisp_type != LISP_TYPE_MAP_REQUEST) {
		cp_log(LDEBUG, "only Map-Requests are supported\n");
			
		return (0);
	}
	
	/* parse LCM */
	cp_log(LDEBUG, "LCM: <type=%u, A=%u, M=%u, P=%u, S=%u, p=%u, s=%u, IRC=%u, rcount=%u, nonce=0x%x - 0x%x>\n", \
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
	
	
	eid_source = (union afi_address_generic *)CO(lcm, sizeof(struct map_request_hdr));
	
	ret = _afi_address_str(eid_source, buf, BSIZE);
	/* check if the source EID is specified */
	if (ret) {
		/* size is [Source EID AFI field + Source EID Address field] */
		eid_size = _get_address_size(eid_source);
	}
	else{
		/* size is [Source EID AFI field] as no address is provided */
		eid_size = 2;
	}
	cp_log(LDEBUG, "Source EID: %s\n", buf);

	/* jump to the ITR address list */
	itr_rloc = (union afi_address_generic *)CO(eid_source, eid_size);
	pke->itr = list_init();
	
	/* XXX dsa: DANGER RISK OF BUG 
	 * ==> ACTUAL NUMBER OF ITR-RLOCs is (IRC + 1 )
	 */
	icount = lcm->irc + 1;
	/* Browse all the ITR-RLOC
	 * XXX dsa: at the end of the loop, itr_rloc point at the END of the last ITR-RLOC 
	 * 	    "INV": itr_rloc points to the rloc to process
	 */
	//get all ITR-RLOC
	while (icount--) {
		itr_address = calloc(1,sizeof(union afi_address_generic));
		
		switch (_get_address_type(itr_rloc)) {
		case LISP_AFI_IP:
			memcpy(&itr_address->ip.address, &itr_rloc->ip.address, sizeof(struct in_addr));
			itr_address->ip.afi = htons(AF_INET);
			break;
		case LISP_AFI_IPV6:
			memcpy(&itr_address->ip6.address, &itr_rloc->ip6.address, sizeof(struct in6_addr));
			itr_address->ip6.afi = htons(AF_INET6);
			break;
		default:
			cp_log(LDEBUG, "not supported (only IPv4 and IPv6)\n");
				
			return (-1);	
		}
		list_insert(pke->itr,itr_address, NULL);
		_afi_address_str(itr_rloc, buf, BSIZE);
		cp_log(LDEBUG, "ITR-RLOC: %s\n", buf);
			
		itr_rloc = (union afi_address_generic *)CO(itr_rloc, _get_address_size(itr_rloc));			
	}
	
	/* XXX dsa: DANGER RISK OF BUG
	 * ==> ACTUAL NUMBER OF REC is (RECORD COUNT) WHICH IS NOT FOLLOWING
	 *     THE SAME DEFINITION THAN IRC
	 */
	rcount = lcm->record_count;
	rec = (union map_request_record_generic *)CO(itr_rloc, 0);
	
	/* Browse all the EID-prefix
	 * XXX dsa: at the end of the loop, rec point at the END of the last record 
	 * 	    "INV": rec points to the record to process
	 */
	pke->eid = list_init();	
	while (rcount--) {
		bzero(buf, BSIZE);
		eid_prefix = calloc(1,sizeof(struct prefix));
		eid_prefix->prefixlen = rec->record.eid_mask_len;
		if (ntohs(rec->record.eid_prefix_afi) == LCAF_AFI)
			rec = (union map_request_record_generic *)CO(rec,12);

		switch (ntohs(rec->record.eid_prefix_afi)) {
		case LISP_AFI_IP:
			eid_prefix->family = AF_INET;
			eid_prefix->u.prefix4 = rec->record.eid_prefix;

			inet_ntop(AF_INET, (void *)&rec->record.eid_prefix, buf, BSIZE);
			break;
		case LISP_AFI_IPV6:
			eid_prefix->family = AF_INET6;
			eid_prefix->u.prefix6 = rec->record6.eid_prefix;

			inet_ntop(AF_INET6, (void *)&rec->record6.eid_prefix, buf, BSIZE);
			break;
		default:
			cp_log(LDEBUG, "AF not support\n");
				
			return -1;				
		}
		cp_log(LDEBUG, "EID prefix: %s/%u\n", buf, eid_prefix->prefixlen);
			
		list_insert(pke->eid,eid_prefix, NULL);
		rec = (union map_request_record_generic *)CO(rec, _get_record_size(rec));
	}
	return (1);
}

	size_t 
_process_referral_record(const union map_referral_record_generic *rec, union afi_address_generic *best_rloc, struct db_node **node)
{
	size_t rlen;
	union map_referral_locator_generic *loc;
	char buf[BSIZE];
	size_t len;
	struct map_entry *entry;
	uint8_t lcount;
	struct prefix eid;
	struct mapping_flags mflags;
	void *mapping;
	uint8_t best_priority;

	rlen = 0;
	bzero(buf, BSIZE);
	*node  = mapping = NULL;
	/* this version only support lcaf type=2 */
	if (ntohs(rec->record.lcaf.afi) == LCAF_AFI) {
		if (rec->record.lcaf.type !=2) {
			cp_log(LLOG, "Only support lcaf with type is 2\n");
			return 0;
		}
	}
	
	bzero(&eid, sizeof(struct prefix));
	switch (ntohs(rec->record.eid_prefix_afi)) {
	case LISP_AFI_IP:
		eid.family = AF_INET;
		eid.u.prefix4 = rec->record.eid_prefix;

		inet_ntop(AF_INET, (void *)&eid.u.prefix4, buf, BSIZE);
		break;
	case LISP_AFI_IPV6:
		eid.family = AF_INET6;
		eid.u.prefix6 = rec->record6.eid_prefix;

		inet_ntop(AF_INET6, (void *)&eid.u.prefix6, buf, BSIZE);
		break;
	default:
		cp_log(LDEBUG, "unsuported family\n");
		return (-1);
	}
	eid.prefixlen = rec->record.eid_mask_len;

	lcount = rec->record.referral_count;
	bzero(&mflags, sizeof(struct mapping_flags));
	mflags.act = rec->record.act;
	mflags.A = 0;
	mflags.version = rec->record.version;
	mflags.incomplete = rec->record.i;
	mflags.ttl = ntohl(rec->record.ttl);
	mflags.referral = rec->record.act+1;
	mflags.iid = rec->record.lcaf.iid;

	if (rec->record.sig_cnt > 0) {
		cp_log(LDEBUG, "Signature not implemented\n");
	}

	/* to mapping table */
	/* add the locator to the table only incomplete is 0*/
	if (!mflags.incomplete) { 
		*node = mapping = generic_mapping_new(&eid);
		generic_mapping_set_flags(mapping, &mflags);
		ms_node_update_type(mapping,_MAPP);
	}

	/* ====================================================== */
	if (_debug == LDEBUG) {
		cp_log(LDEBUG, "EID %s/%d: ", buf, eid.prefixlen);

		cp_log(LDEBUG, "<");
		cp_log(LDEBUG, "ref_count=%u", lcount);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "TTL=%u", mflags.ttl);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "ACT=%d", mflags.act);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "version=%u", mflags.version);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "A=%u", mflags.A);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "i=%u", mflags.incomplete);

		cp_log(LDEBUG, ">\n");
	}

	if (lcount == 0) {
		cp_log(LDEBUG, "\tNegative referral\n");
	}
	/* ====================================================== */

	size_t rhdr_len = _get_referral_record_size(rec);
	rlen += rhdr_len;
	loc = (union map_referral_locator_generic *)CO(rec, rhdr_len);

	/* ==================== RLOCs ========================= */
	best_priority = 0xff;
	while (lcount--) {
		char buf[BSIZE];
		bzero(buf, BSIZE);

		entry = (struct map_entry *)calloc(1, sizeof(struct map_entry));

		/* get locator parameters  and address */
		entry->priority = loc->rloc.priority;
		entry->weight = loc->rloc.weight;
		entry->m_priority = loc->rloc.m_priority;
		entry->m_weight = loc->rloc.m_weight;
		entry->r = loc->rloc.R;
		switch (ntohs(loc->rloc.rloc_afi)) {
		case LISP_AFI_IP:
			entry->rloc.sin.sin_family = AF_INET;
			memcpy(&entry->rloc.sin.sin_addr, &loc->rloc.rloc, sizeof(struct in_addr));

			inet_ntop(AF_INET, (void *)&loc->rloc.rloc, buf, BSIZE);
			len = sizeof(struct map_referral_locator);
			break;
		case LISP_AFI_IPV6:
			entry->rloc.sin6.sin6_family = AF_INET6;
			memcpy(&entry->rloc.sin6.sin6_addr, &loc->rloc6.rloc, sizeof(struct in6_addr));

			inet_ntop(AF_INET6, (void *)&loc->rloc6.rloc, buf, BSIZE);
			len = sizeof(struct map_referral_locator6);
			break;
		default:
			cp_log(LDEBUG, "unsuported family\n");
				
			free(entry);
			return (-1);
		}
		
		if (mapping) {
			generic_mapping_add_rloc(mapping, entry);
		}
		cp_log(LDEBUG, "\t•[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
					buf, \
					entry->priority, \
					entry->weight, \
					entry->m_priority, \
					entry->m_weight, \
					entry->r, \
					entry->L, \
					entry->p);
				
		/* determine if it is the best locator */
		if (best_rloc != NULL && entry->priority < best_priority) {
			best_priority = entry->priority;
			memcpy(best_rloc, &loc->rloc.rloc_afi, \
					(ntohs(loc->rloc.rloc_afi) == LISP_AFI_IP)?sizeof(struct afi_address):\
					(ntohs(loc->rloc.rloc_afi) == LISP_AFI_IPV6?sizeof(struct afi_address6):0));
		}

		loc = (union map_referral_locator_generic *)CO(loc, len);
		rlen += len;
		if (!mapping) {
			free(entry);
		}
	}
	if (mflags.act == LISP_REFERRAL_MS_ACK)
		return 0;
		
	return (rlen);
}

/* Map-notify */
	int
_register_notify(void *data, struct site_info *site )
{
	struct pk_req_entry *pke;
	union sockunion ds;
	void *buf;
	void *pkbuf;
	size_t pklen;
	struct map_register_hdr *lcm;
	size_t slen;
	int skt;
	HMAC_SHA1_CTX	ctx;
	unsigned char	macbuf[BUFLEN];    	  	    
	uint16_t auth_len = HMAC_SHA1_DIGEST_LENGTH;
	int i;
	
	/* content of map-notify same as map-register except not include P,M bit set*/
	pke = data;
	buf = calloc(pke->buf_len, sizeof(char));
	memcpy(buf,pke->buf,pke->buf_len);
	/* set type and bit set for map-notify */
	lcm = buf;
	lcm->lisp_type = LISP_TYPE_MAP_NOTIFY;
	lcm->proxy_map_reply = 0;
	lcm->want_map_notify = 0;
	/* recal the HMAC data */
	for (i = 0; i < auth_len; i++)
		lcm->auth_data[i]=0;
		
	pkbuf = calloc(pke->buf_len, sizeof(char));	
	memcpy(pkbuf,buf,pke->buf_len);
	HMAC_SHA1_Init(&ctx);
	HMAC_SHA1_UpdateKey(&ctx, (unsigned char *)site->key, strlen((char *)site->key));
	HMAC_SHA1_EndKey(&ctx);
	HMAC_SHA1_StartMessage(&ctx);
	HMAC_SHA1_UpdateMessage(&ctx, pkbuf,pke->buf_len);
	HMAC_SHA1_EndMessage(macbuf, &ctx);
	for (i = 0; i < auth_len; i++) {
		lcm->auth_data[i]=macbuf[i];
	}
	free(pkbuf);
	memcpy(&ds, &pke->si, sizeof(union sockunion));
	sk_set_port(&ds,LISP_CP_PORT);
	pklen = pke->buf_len;
	
	if (_debug == LDEBUG) {
		cp_log(LDEBUG, "send Map-Notify ");
		cp_log(LDEBUG, "to %s:%d\n", 
					sk_get_ip(&ds, ip), sk_get_port(&ds) );
		cp_log(LDEBUG, "Sending packet... ");
	}
	
	/* select socket for ds */	
	switch ((ds.sa).sa_family ) {
	case AF_INET:
		skt = skfd;
		slen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		skt = skfd6;
		slen = sizeof(struct sockaddr_in6);
		break;
	default:
		cp_log(LDEBUG, "ETR address not correct::AF_NOT_SUPPORT\n");
		free(buf);	
		return -1;
	}
		
	if (sendto(skt, (char *)buf, pklen, 0, (struct sockaddr *)&(ds.sa), slen) == -1) {
			cp_log(LDEBUG, "failed\n");
			perror("sendto()");
			free(buf);
			return (-1);
	}
	cp_log(LDEBUG, "done\n");
	free(buf);	
	return (TRUE);	
}

/* Process Map-Register */
	uint32_t 
_register(void *data)
{
	struct map_register_hdr *lcm;
	union map_reply_record_generic *rec;		/* current record */
	size_t lcm_len;
	uint8_t rcount;
	size_t packet_len;
	struct list_entry_t *site;
	int proxy_flg;
	struct pk_req_entry *pke = data;
	void *packet = pke->buf;	
	int rt;
	int pkg_len = pke->buf_len;
	lcm = (struct map_register_hdr *)CO(packet, 0);
	rcount = lcm->record_count;
	cp_log(LDEBUG, "LCM: <type=%u, P=%u, M=%u, rcount=%u, nonce=0x%x - 0x%x, key id=%u, auth data length=%u\n", \
				lcm->lisp_type,
				lcm->proxy_map_reply, \
				lcm->want_map_notify,
				rcount, \
				ntohl(lcm->lisp_nonce0), \
				ntohl(lcm->lisp_nonce1), \
				ntohs(lcm->key_id), \
				ntohs(lcm->auth_data_length));
		
	lcm_len = sizeof(struct map_register_hdr) + ntohs(lcm->auth_data_length);
	packet_len = lcm_len;
	
	if ((rt = _ms_validate_register(ms_db, packet, pkg_len, (void *)&site)) >=0 ) {
		/* update */
		if (rt) {
			cp_log(LDEBUG, "Map-register:: Valide - OK\n");
			cp_log(LDEBUG, "Map-register:: Preparing to update database\n");
			
			/* cleare mapping of site in database */
			_ms_clean_site_mapping(site);
			
			/* add new mapping to database */
			rec = (union map_reply_record_generic *)CO(lcm, lcm_len);
			proxy_flg = lcm->proxy_map_reply;
			/* ==================== RECORDs ========================= */
			size_t rlen = 0;
			while (rcount--) {
				rlen = _ms_process_register_record(rec, proxy_flg);
				packet_len += rlen;
				rec = (union map_reply_record_generic *)CO(rec, rlen);
			}
			cp_log(LDEBUG, "Map-register:: Update......Success\n");
			cp_log(LDEBUG, "Map-register:: Finish update database\n");
			
		}		
		/* Send map-notify if required */
		if (lcm->want_map_notify && site->data) {
			_register_notify(pke, site->data);
		}
		return 1;
	}
	return 0;
}

/* Cal hashing of package */
	void *
_ms_recal_hashing(const void *packet, int pk_len, void *key, void *rt, int no_nonce)
{
	
    void *packet2;
	struct map_register_hdr *map_register;
    HMAC_SHA1_CTX	ctx;
	unsigned char	buf[BUFLEN];    	  	    
	u_char auth_len;
	int i;
 		
	packet2 = calloc(pk_len,sizeof(char));
	memcpy(packet2, packet, pk_len);
	map_register = (struct map_register_hdr *)packet2;				
	auth_len = ntohs(map_register->auth_data_length);
	for (i = 0; i < auth_len; i++) {
		map_register->auth_data[i]=0;
	}
	
	if (no_nonce) {
		/*ignore when hashing */
		memset((char *)&map_register->lisp_nonce0,0,4);
		memset((char *)&map_register->lisp_nonce1,0,4);
			
	}
	
	/* Calculate Hash and fill in Authentication Data field */
	HMAC_SHA1_Init(&ctx);
	HMAC_SHA1_UpdateKey(&ctx, key, strlen((char *)key) );
	HMAC_SHA1_EndKey(&ctx);
	HMAC_SHA1_StartMessage(&ctx);
	HMAC_SHA1_UpdateMessage(&ctx, packet2,pk_len);
	HMAC_SHA1_EndMessage(buf, &ctx);

	char hex_output[auth_len*2+1];
	for (i = 0; i < auth_len; i++) {
		sprintf(hex_output + i * 2, "%02x", buf[i]);
		map_register->auth_data[i]=buf[i];
	}
	memcpy((char *)rt, (char *)map_register->auth_data, auth_len);
	free(packet2);
	return NULL;
}

/* Check validate of one eid */
	struct list_entry_t * 
_ms_validate_eid(struct lisp_db *lisp_db, const union map_reply_record_generic *rec,  size_t *rlen)
{
	union map_reply_locator_generic *loc;
	size_t len;
	uint8_t lcount;
	struct prefix eid;
	struct db_table *db;
	struct db_node *node;
	struct list_entry_t *n_ex_info;
	
	/* get EID-prefix */
	*rlen = 0;	
	bzero(&eid, sizeof(struct prefix));
	switch (ntohs(rec->record.eid_prefix_afi)) {
	case LISP_AFI_IP:
		eid.family = AF_INET;
		eid.u.prefix4 = rec->record.eid_prefix;
		break;
	case LISP_AFI_IPV6:
		eid.family = AF_INET6;
		eid.u.prefix6 = rec->record6.eid_prefix;
		break;
	default:			
		cp_log(LDEBUG, "unsuported family\n");
		return (0);
	}
	eid.prefixlen = rec->record.eid_mask_len;

	lcount = rec->record.locator_count;
	
	/* ====================================================== */

	size_t rhdr_len = _get_reply_record_size(rec);
	*rlen += rhdr_len;
	loc = (union map_reply_locator_generic *)CO(rec, rhdr_len);

	//Run over rlocs
	/* ==================== RLOCs ========================= */
	struct lcaf_hdr *lcaf;
	void *barr;
	union rloc_te_generic *hop;
	while (lcount--) {
		switch (ntohs(loc->rloc.rloc_afi)) {
		case LISP_AFI_IP:
			len = sizeof(struct map_reply_locator);
			break;
		case LISP_AFI_IPV6:
			len = sizeof(struct map_reply_locator6);
			break;
		case LCAF_AFI:
			/*only support LISP_TE for rloc at currently version */
			lcaf = (struct lcaf_hdr *)&loc->rloc.rloc_afi;
			if (lcaf->type != LCAF_TE)
				return 0;
			barr = CO(lcaf,sizeof(struct lcaf_hdr)+ ntohs(lcaf->payload_len));
			hop = (union rloc_te_generic *)CO(lcaf,sizeof(struct lcaf_hdr));
			len = sizeof(struct map_reply_locator) - 2 - sizeof(struct in_addr)+sizeof(struct lcaf_hdr);
			while ((void *)hop < barr) {
				switch (ntohs(hop->rloc.afi)) {
				case LISP_AFI_IP:
						len += sizeof(struct rloc_te);
						hop = (union rloc_te_generic *)CO(hop,sizeof(struct rloc_te));
						break;
				case LISP_AFI_IPV6:
						len += sizeof(struct rloc6_te);
						hop = (union rloc_te_generic *)CO(hop,sizeof(struct rloc6_te));
						break;
					default:
						cp_log(LDEBUG, "unsuported family rlocs:%d\n",ntohs(hop->rloc.afi));
						return 0;	
				}					
			}
			break;
		default:
			cp_log(LDEBUG, "unsuported family rlocs:%d\n",loc->rloc.rloc_afi);
			return (0);
		}
		
		loc = (union map_reply_locator_generic *)CO(loc, len);
		*rlen += len;		
	}
	
	
	//Check EID-prefix, must: belong to one active site
	db = ms_get_db_table(lisp_db,&eid);
	node = db_node_match_prefix(db,&eid);
	
	if (node) {
		while (node != db->top) {
			if (ms_node_is_type(node,_EID))
				break;		
			node = node->parent;			
		}	
		
		/* atleast eid match with root 0/0 */
		if (node == db->top) {
			cp_log(LDEBUG, "EID::%s:: not in registed range\n",(char *)prefix2str(&eid) );
			return NULL;
		} else {
			n_ex_info = ((struct mapping_flags *)node->flags)->rsvd;
			//show_site_info(n_ex_info->data);
			return (n_ex_info);		
		}
	}
	return NULL;
}

/* Validate map-register
	if ok, check if need update db or not
	if not, ignore
*/	
	int  
_ms_validate_register(struct lisp_db *db, const void *packet, int pkg_len, void **site_ptr)
{
	struct map_register_hdr *lcm;
	union map_reply_record_generic *rec;		/* current record */
	size_t lcm_len;
	uint8_t rcount;
	size_t packet_len, auth_len;
	void *pt;
	size_t rlen = 0;
	void *site = NULL;
	struct site_info *s_info;
	void *s_hashing;
	void *s_hmac;
	void *info_hashing;
	void *info_hmac;
	lcm = (struct map_register_hdr *)CO(packet, 0);
	rcount = lcm->record_count;
	auth_len = ntohs(lcm->auth_data_length);
	lcm_len = sizeof(struct map_register_hdr);
	
	cp_log(LDEBUG, "Map-register: Validate processing....\n");
	/* ==================== Auth data ========================= */
	//get hashing
	info_hmac = CO(lcm,lcm_len);
		
	lcm_len += auth_len;
	packet_len = lcm_len;
	rec = (union map_reply_record_generic *)CO(lcm, lcm_len);
	
	
	/* ==================== RECORDs ========================= */
	//Check eid in map-register
	//all eid must for the same site
	
	//if map-register empty, ignore
	
	if (!rcount)
		return -1;
		
	while (rcount--) {		
		pt = _ms_validate_eid(db, rec, &rlen);
		if (pt == NULL)
			return -1;			
				
		if ((site != NULL) && (site != pt) ) {
			cp_log(LDEBUG, "Map-register: All eid not belong to same site\n");
			return -1;			
		}
		site = pt;
		packet_len += rlen;
		rec = (union map_reply_record_generic *)CO(rec, rlen);		
	}
	*site_ptr = site;
	cp_log(LDEBUG, "Map-register: Compare with stored hashing..........\n");
	
	/* ============================================= */
	/*check if need update or not by compare stored hasing and package's hashing */
	s_info = (struct site_info *)((struct list_entry_t *)site)->data;
	
	info_hashing = s_info->hashing;
	s_hashing = calloc(auth_len, sizeof(char));
	_ms_recal_hashing(packet, pkg_len, s_info->key, s_hashing, 1);
	
	if ((info_hashing != NULL) && (strncmp((char *)info_hashing,(char *)s_hashing,auth_len) == 0)) {
		cp_log(LDEBUG, "Map-register: Not need update\n");
		cp_log(LDEBUG, "Map-register:: Finish update database\n");
		
		free(s_hashing);
		return 0;		
	}
	
	cp_log(LDEBUG, "Map-register: Authenticate processing........\n");
	/* ============================================= */
	//check again hashing
	s_hmac = calloc(auth_len, sizeof(char));
	_ms_recal_hashing(packet, pkg_len, s_info->key, s_hmac, 0);
	
	if (strncmp((char *)info_hmac, (char *)s_hmac,auth_len) != 0) {
		cp_log(LDEBUG, "Map-register: Authentication not success....., ignore package\n");
		free(s_hmac);
		return -1;
	}
	
	/* update site information: hashing, TTL.. */
	free(info_hashing);
	info_hashing = s_info->hashing = calloc(auth_len, sizeof(char));
	memcpy((char *)info_hashing, (char *)s_hashing,auth_len );
	free(s_hashing);
	
	return (1);
}

/* Delete an old mapping */
	void 
_ms_clean_eid_mapping(struct db_node *node)
{
	struct db_node * tmp_node;
	struct db_node *papa;
	assert(node);
	papa = node->parent;
	if (papa != NULL) {
		if (papa->l_left == node)
			papa->l_left = NULL;
		else
			papa->l_right = NULL;
	}
	
	node->parent = NULL;	
	while (node) {
		if (node->l_left) {
			node = node->l_left;
			continue;
		}

		if (node->l_right) {
			node = node->l_right;
			continue;
		}

		tmp_node = node;
		node = node->parent;

		if (node != NULL) {
			if (node->l_left == tmp_node)
				node->l_left = NULL;
			else
				node->l_right = NULL;

			ms_free_node(tmp_node);
		} else {
			ms_free_node (tmp_node);
			break;
		}
	}

	
	
}

/* Delete mapping of site */
	void 
_ms_clean_site_mapping(struct list_entry_t *site)
{
	struct list_t *eid_l;
	struct list_entry_t *cur;
	struct db_node *node;
	uint8_t range;
	void *rsvd;
	
	assert(site);
	eid_l = ((struct site_info *)site->data)->eid;
	cur = eid_l->head.next;
	show_site_info((struct site_info *)site->data);
	while (cur != &(eid_l->tail)) {
		node = (struct db_node *)cur->data;
		
		if (node->l_left) {
			_ms_clean_eid_mapping(node->l_left);
			node->l_left = NULL;
		}
		if (node->l_right) {
			_ms_clean_eid_mapping(node->l_right);	
			node->l_right = NULL;
		}
		db_node_set_info(node,NULL);
		
		if (node->flags) {
			range = ((struct mapping_flags *)node->flags)->range;
			rsvd = ((struct mapping_flags *)node->flags)->rsvd;
			bzero(node->flags,sizeof(struct mapping_flags));
			if (range > _MAPP)
				range = range & ~_MAPP;
				
			((struct mapping_flags *)node->flags)->range = range;	
			((struct mapping_flags *)node->flags)->rsvd = rsvd;	
		} else {
			node->flags = NULL;
		}	
		cur = cur->next;
	}
}

/* Create a new mapping */
	void *
_ms_generic_mapping_new(struct db_table *tb, struct prefix *eid)
{
	struct db_node *rn;
	struct list_t *locs;
	
	rn = db_node_get(tb, eid);
	if (!rn)
		return (NULL);
		
	ms_node_update_type(rn, _MAPP);
	locs = list_init();
	db_node_set_info(rn, locs);

	return ((void *)rn);
}

/* Update a mapping */
	size_t 
_ms_process_register_record(const union map_reply_record_generic *rec, uint8_t proxy_map_repl)
{
	size_t rlen;
	union map_reply_locator_generic *loc;
	char buf[BSIZE];
	size_t len;
	struct map_entry *entry;
	uint8_t lcount;
	struct prefix eid;
	struct mapping_flags mflags;
	struct db_node *mapping;
		
	rlen = 0;
	bzero(buf, BSIZE);
	mapping = NULL;

	bzero(&eid, sizeof(struct prefix));
	switch (ntohs(rec->record.eid_prefix_afi)) {
	case LISP_AFI_IP:
		eid.family = AF_INET;
		eid.u.prefix4 = rec->record.eid_prefix;

		inet_ntop(AF_INET, (void *)&eid.u.prefix4, buf, BSIZE);
		break;
	case LISP_AFI_IPV6:
		eid.family = AF_INET6;
		eid.u.prefix6 = rec->record6.eid_prefix;

		inet_ntop(AF_INET6, (void *)&eid.u.prefix6, buf, BSIZE);
		break;
	default:
		cp_log(LDEBUG, "unsuported family\n");
			
		return (0);
	}
	eid.prefixlen = rec->record.eid_mask_len;
		
	lcount = rec->record.locator_count;
	bzero(&mflags, sizeof(struct mapping_flags));
	mflags.act = rec->record.act;
	mflags.A = rec->record.a;
	mflags.version = rec->record.version;
	mflags.ttl = ntohl(rec->record.ttl);
	mflags.referral = 0;
	mflags.proxy = proxy_map_repl;
	mflags.range = _MAPP;

	/* add entry to mapping table */
	mapping = generic_mapping_new(&eid);
	generic_mapping_set_flags(mapping, &mflags);
	
	/* ====================================================== */
	if (_debug == LDEBUG) {	
		cp_log(LDEBUG, "EID %s/%d: ", buf, eid.prefixlen);

		cp_log(LDEBUG, "<");
		cp_log(LDEBUG, "Lcount=%u", lcount);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "TTL=%u", mflags.ttl);
	}
	
	if (lcount == 0) {
		if (_debug == LDEBUG) {
			cp_log(LDEBUG, ", ");
			cp_log(LDEBUG, "ACT=%d", mflags.act);
		}
	}
	
	if (_debug == LDEBUG) {
		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "version=%u", mflags.version);

		cp_log(LDEBUG, ", ");
		cp_log(LDEBUG, "A=%u", mflags.A);

		cp_log(LDEBUG, ">\n");
	}
	
	if (lcount == 0) {
		cp_log(LDEBUG, "\tNegative reply\n");
	}
	/* ====================================================== */

	size_t rhdr_len = _get_reply_record_size(rec);
	rlen += rhdr_len;
	loc = (union map_reply_locator_generic *)CO(rec, rhdr_len);
	
	struct lcaf_hdr *lcaf;
	union rloc_te_generic *hop;
	void *barr;
	struct pe_entry *pe;
	struct hop_entry *he;
	int pec;
	/* ==================== RLOCs ========================= */
	while (lcount--) {
		bzero(buf, BSIZE);
		
		entry = (struct map_entry *)calloc(1, sizeof(struct map_entry));
		entry->priority = loc->rloc.priority;
		entry->weight = loc->rloc.weight;
		entry->m_priority = loc->rloc.m_priority;
		entry->m_weight = loc->rloc.m_weight;
		entry->r = loc->rloc.R;
		entry->L =loc->rloc.L;
		entry->p = loc->rloc.p;
		
		
		lcaf = (struct lcaf_hdr *)&loc->rloc.rloc_afi;	
		if (ntohs(lcaf->afi) == LCAF_AFI && lcaf->type == LCAF_TE) {
						
			barr = (void *)CO(lcaf,sizeof(struct lcaf_hdr)+ntohs(lcaf->payload_len));
			hop = (union rloc_te_generic *)CO(lcaf,sizeof(struct lcaf_hdr));
			/* run over pe 
				if lisp_te && proxy_map_repl, get all hop					
				else, only get last hop				
			*/
			pec = 0;
			if (pec == 0) {
				pe = calloc(1,sizeof(struct pe_entry));
				entry->pe = list_init();
				list_insert(entry->pe,pe,NULL);
				pe->hop = list_init();
				pe->priority = entry->priority;
				pe->weight = entry->weight;
				pe->m_priority = entry->m_priority;
				pe->m_weight = entry->m_weight;
				pe->r = entry->r;
				pe->L = entry->L;
				pe->p = entry->p;					
			}
			cp_log(LDEBUG, "\t•[rloc=TE, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
						entry->priority, \
						entry->weight, \
						entry->m_priority, \
						entry->m_weight, \
						entry->r, \
						entry->L, \
						entry->p);
						
			while ((char *)hop < (char *)barr) {
				switch (ntohs(hop->rloc.afi)) {
				case LISP_AFI_IP:
					if (lisp_te && proxy_map_repl && (CO(hop,sizeof(struct rloc_te) < (char *)barr ))) {
						he = calloc(1, sizeof(struct hop_entry));
						he->L = hop->rloc.L;
						he->P = hop->rloc.P;
						he->S = hop->rloc.S;
						he->addr.sin.sin_family = AF_INET;
						memcpy(&he->addr.sin.sin_addr,&hop->rloc.hop_addr,sizeof(struct in_addr));
						list_insert(pe->hop,he,NULL);
						if (_debug == LDEBUG) {
							inet_ntop(he->addr.sin.sin_family, (void *)&he->addr.sin.sin_addr, buf, BSIZE);
							cp_log(LDEBUG, "\t\t•[hop=%s]\n",buf); 								
						}
					}
					
					if ((CO(hop,sizeof(struct rloc_te) >= (char *)barr ))) {
						entry->rloc.sin.sin_family = AF_INET;
						memcpy(&entry->rloc.sin.sin_addr,&hop->rloc.hop_addr,sizeof(struct in_addr));
						if (_debug == LDEBUG) {
							inet_ntop(entry->rloc.sin.sin_family, (void *)&entry->rloc.sin.sin_addr, buf, BSIZE);
							cp_log(LDEBUG, "\t\t•[hop=%s]\n",buf); 
						}		
					}	
					hop = (union rloc_te_generic *)CO(hop,sizeof(struct rloc_te));
					break;						
				case LISP_AFI_IPV6:
					if (lisp_te && proxy_map_repl && (CO(hop,sizeof(struct rloc6_te) < (char *)barr ))) {
						he = calloc(1, sizeof(struct hop_entry));
						he->L = hop->rloc6.L;
						he->P = hop->rloc6.P;
						he->S = hop->rloc6.S;
						he->addr.sin6.sin6_family = AF_INET6;
						memcpy(&he->addr.sin6.sin6_addr,&hop->rloc6.hop_addr,sizeof(struct in6_addr));							
						list_insert(pe->hop,he,NULL);
						if (_debug == LDEBUG) {
							inet_ntop(he->addr.sin6.sin6_family, (void *)&he->addr.sin6.sin6_addr, buf, BSIZE);
							cp_log(LDEBUG, "\t\t•[hop=%s]\n",buf); 
						}
					}
					
					if ((CO(hop,sizeof(struct rloc6_te) >= (char *)barr ))) {
						entry->rloc.sin6.sin6_family = AF_INET6;
						memcpy(&entry->rloc.sin6.sin6_addr,&hop->rloc6.hop_addr,sizeof(struct in6_addr));
						if (_debug == LDEBUG) {
							inet_ntop(entry->rloc.sin6.sin6_family, (void *)&entry->rloc.sin6.sin6_addr, buf, BSIZE);
							cp_log(LDEBUG, "\t\t•[hop=%s]\n",buf); 
						}		
					}	
					hop = (union rloc_te_generic *)CO(hop,sizeof(struct rloc6_te));
					break;
				default:
					cp_log(LLOG, "unsuported family\n");
					free(entry);
					return (0);
				}
				pec++;
			}
			
			loc = barr;		
		}
		else{
			switch (ntohs(loc->rloc.rloc_afi)) {
			case LISP_AFI_IP:
				entry->rloc.sin.sin_family = AF_INET;
				memcpy(&entry->rloc.sin.sin_addr, &loc->rloc.rloc, sizeof(struct in_addr));					
				len = sizeof(struct map_reply_locator);
				break;
			case LISP_AFI_IPV6:
				entry->rloc.sin6.sin6_family = AF_INET6;
				memcpy(&entry->rloc.sin6.sin6_addr, &loc->rloc6.rloc, sizeof(struct in6_addr));					
				len = sizeof(struct map_reply_locator6);
				break;
			default:
				cp_log(LLOG, "unsuported family\n");
				free(entry);
				return (0);
			}
			if (_debug == LDEBUG) {
				inet_ntop(entry->rloc.sin.sin_family, (void *)&loc->rloc.rloc, buf, BSIZE);
				cp_log(LDEBUG, "\t•[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
						buf, \
						entry->priority, \
						entry->weight, \
						entry->m_priority, \
						entry->m_weight, \
						entry->r, \
						entry->L, \
						entry->p);
			}
			loc = (union map_reply_locator_generic *)CO(loc, len);	
		}
		
		/* add the locator to the table */
		rlen = (char *)loc - (char *)rec;	
		assert((struct list_t *)mapping->info);
		if (entry->rloc.sa.sa_family) {
			struct list_entry_t *m;
			struct map_entry *n_entry;
			if (!(m = list_search(mapping->info, entry,entrycmp))) {
				list_insert((struct list_t *)mapping->info, entry, NULL);
			} else{				
				/* new rloc exist, only updat priority and pe */
				struct list_entry_t *lt;
				n_entry = (struct map_entry *)m->data;
				if (!n_entry->pe && !entry->pe ) {
					if (n_entry->priority > entry->priority) { 
						m->data = entry;					
						free(n_entry);
					}
				}else{
					if (!n_entry->pe) {
						n_entry->pe = entry->pe;
					}
					else if (entry->pe) {
							lt = entry->pe->head.next;
							while (lt != &entry->pe->tail) {
								list_insert(n_entry->pe, lt->data,NULL);
								lt = lt->next;
							}
					}						
					free(entry);
					entry = n_entry;
				}				
			}		
		}else{
			free(entry);
			return 0;
		}		
	}
	
	return (rlen);
}

/* Map-register process thread */
	void *
general_register_process(void *data)
{
	struct pk_rpl_entry *rpk;
	struct pk_rpl_entry *rpk_ex=NULL;
	struct list_entry_t *ptr;
	struct db_node *node;
	struct ms_entry *ms;
	struct mapping_flags *mflags;
	struct map_register_hdr *hr;
	HMAC_SHA1_CTX	ctx;
	unsigned char	buf[BUFLEN];
	struct map_entry *e = NULL;
	struct list_entry_t *_iter, *pr;
	struct list_t *l = NULL;
	u_char pkbuf[PKMSIZE];
	uint64_t	nonce;
	uint32_t	*nonce_trick;
	int count;
	int buflen;
	
	count = 0;
	for (; ;) {
		pr = xtr_ms->head.next;		
		while (pr != &xtr_ms->tail) {
			ms = (struct ms_entry *)pr->data;
			
			/* init map-register message */
			while (!(rpk = udp_register_add(NULL)) ) {
				sleep(1);
				continue;
			}
			
			if(lisp_te && (_fncs & _FNC_XTR)){
				while( !(rpk_ex = udp_register_add(NULL)) ){
					sleep(1);
					continue;		
				}
			}	
			
			/* add mapping to map-register message */
			ptr = ms->eids->head.next;
			while (ptr != &ms->eids->tail) {
				node = (struct db_node *)ptr->data;
				mflags = node->flags;			
				l = (struct list_t *)db_node_get_info(node);
				assert(l);
				_iter = l->head.next;
			
				if (!_iter) {
					ptr = ptr->next;
					continue;				
				}
				
				/* only include PE in map-register message WITH proxy-reply */
				if (ms->proxy && lisp_te && (_fncs & _FNC_XTR)) {
					/* cal number of pe */
					int lcount = 0;
					while (_iter != &l->tail) {
						e = (struct map_entry*)_iter->data;
						if (e->pe)
							lcount += e->pe->count;
						else
							lcount++;
						_iter = _iter->next;	
					}
					udp_register_add_record(rpk, &node->p, mflags->ttl, lcount, mflags->version, mflags->A, mflags->act);
				}else{
					udp_register_add_record(rpk, &node->p, mflags->ttl, l->count, mflags->version, mflags->A, mflags->act);
				}	
				
				/* insert RLOC */
				_iter = l->head.next;				
				while (_iter != &l->tail) {
					e = (struct map_entry*)_iter->data;
					udp_register_add_locator(rpk, e, 0);
					if (lisp_te && (_fncs & _FNC_XTR))
						udp_register_add_locator(rpk_ex, e, 1);
					
					_iter = _iter->next;
				}
				ptr = ptr->next;
			}; /* add mapping to map-register message */	
			
			/* make nonce, cal authen data and send */
			hr = (struct map_register_hdr *)rpk->buf;
			buflen = rpk->buf_len;
			hr->proxy_map_reply = ms->proxy;
			hr->key_id = htons(01);
			hr->auth_data_length = htons(HMAC_SHA1_DIGEST_LENGTH);
			if (!(count %15)) {
				hr->want_map_notify = 1;
				count = 0;
			}
			count++;
			
			/*Calc auth data */
			memset(hr->auth_data, 0, hr->auth_data_length);
			
			_make_nonce(&nonce);
			nonce_trick = (void *)&nonce;
			hr->lisp_nonce0 = htonl((*nonce_trick));
			hr->lisp_nonce1 = htonl((*(nonce_trick + 1)));
			memcpy(pkbuf, hr,buflen);
			HMAC_SHA1_Init(&ctx);
			HMAC_SHA1_UpdateKey(&ctx, (unsigned char *)ms->key, strlen((char *)ms->key));
			HMAC_SHA1_EndKey(&ctx);
			HMAC_SHA1_StartMessage(&ctx);
			HMAC_SHA1_UpdateMessage(&ctx, pkbuf,buflen);
			HMAC_SHA1_EndMessage(buf, &ctx);
			memcpy(hr->auth_data, buf, hr->auth_data_length);
			
			cp_log(LDEBUG, "Map-Register ");
			cp_log(LDEBUG, " <");
			cp_log(LDEBUG, "nonce=0x%x - 0x%x", ntohl(hr->lisp_nonce0), ntohl(hr->lisp_nonce1));
			cp_log(LDEBUG, ">\n");
						
			/*Send */
			udp_register_terminate(rpk, (union sockunion *)&(ms->addr));
			_free_rpl_pool_place(rpk, _rm_rpl);	
			pr = pr->next;
		};/* send map-regiter finish */
		
		/* wake up each 1 minute to send map-register */		
		sleep(60);
	}
	return NULL;
}

/* helper function */
/* print in hexa */
	void 
hexout(unsigned char *data, int datalen)
{
	printf("0x");
	while (datalen-- > 0)
		printf("%02x",(unsigned char)*data++);
	printf("\n");
}

/* get ip of sockunion */
	
	char *
sk_get_ip(union sockunion *sk, char *ip)
{
	int afi;
	
	afi = (sk->sa).sa_family;
	if (afi == AF_INET) {
		inet_ntop(afi, &(sk->sin).sin_addr,ip,INET_ADDRSTRLEN);
	}
	else if (afi == AF_INET6) {
		inet_ntop(afi, &(sk->sin6).sin6_addr,ip,INET6_ADDRSTRLEN);
	}else{
		cp_log(LLOG, "Type not support\n");
		return NULL;
	}
	return ip;
}

/* get ip of sockunion */
	int 
sk_get_port(union sockunion *sk)
{
	int afi;
	
	afi = (sk->sa).sa_family;
	if (afi == AF_INET) {
		return ntohs((sk->sin).sin_port);
	}
	else if (afi == AF_INET6) {
		return ntohs((sk->sin6).sin6_port);
	}else{
		cp_log(LLOG, "Type not support\n");
	}
	return 0;
}

/* set port of sockunion */
	void 
sk_set_port(union sockunion *sk, int port)
{
	int afi;
	
	afi = (sk->sa).sa_family;
	if (afi == AF_INET) {
		(sk->sin).sin_port = htons(port);
	}
	else if (afi == AF_INET6) {
		(sk->sin6).sin6_port = htons(port);
	}else{
		cp_log(LLOG, "Type not support\n");
	}	
}

/* general free function */
	int 
_destroy_fct(void *data)
{
	free(data);
	return 1;
}

/* make DDT-map-request */

int udpproto;
struct pollfd mr_fds[MAX_LOOKUPS + 1];
struct pollfd mr_fds6[MAX_LOOKUPS + 1];
int mr_fds_idx[MAX_LOOKUPS +1];
int mr_fds_idx6[MAX_LOOKUPS +1];
nfds_t mr_nfds = 0;
int maxcount   = COUNT;
int timeout = MAP_REPLY_TIMEOUT;
int seq;

struct eid_pending {
    struct prefix *last_eid;		/* Last eid-prefix received by MR - to prevent loop*/
    int rx;                     /* Receiving socket */
    int rx6;                     /* Receiving socket */
    uint32_t nonce0;			 /* First half of the nonce */
    uint32_t nonce1; /* Second half of the nonce */
    struct timespec start;      /* Start time of lookup */
    int count;                  /* Current count of retries */
    uint64_t active;            /* Unique lookup identifier, 0 if inactive */
	struct list_t *rlocs;		/* List of next RLOC for map-request */
	struct list_entry_t *rloc_cur;				/* Point to next RLOC to send map-request */
	void *orgi_pkg;				/* IH package */
	void *pke;	 /* orig packet */
	uint16_t orgi_pkg_len;
} mr_lookups[MAX_LOOKUPS];


	int 
send_mr_ddt(uint32_t idx)
{
	int skt;
	void *buf;
	uint16_t buf_len;
	union sockunion servaddr, *rloc;
	struct map_entry *e;
	socklen_t slen;
	
	if (mr_lookups[idx].active) {
		buf = mr_lookups[idx].orgi_pkg;
		buf_len = mr_lookups[idx].orgi_pkg_len;
		
		if (!mr_lookups[idx].rloc_cur) {
			mr_lookups[idx].count = MR_MAX_LOOKUP+1;
			return 1;
		}	
		e = (struct map_entry *)mr_lookups[idx].rloc_cur->data;
		rloc = &(e->rloc);
		bzero(&servaddr,sizeof(servaddr));
		memcpy(&servaddr,rloc, sizeof(union sockunion));
				
		if ((rloc->sa).sa_family == AF_INET) {
			skt = mr_lookups[idx].rx;
			servaddr.sin.sin_port=htons(LISP_CP_PORT);
			slen = sizeof(struct sockaddr_in);
		}else if ((rloc->sa).sa_family == AF_INET6) {
			skt = mr_lookups[idx].rx6;
			servaddr.sin6.sin6_port=htons(LISP_CP_PORT);			
			slen = sizeof(struct sockaddr_in6);
		}
		else{
			cp_log(LDEBUG,"AF not support\n");
			mr_lookups[idx].count++;	
			return 1;
		}
		 
		cp_log(LDEBUG, "send Map-Request ");
		cp_log(LDEBUG, "to %s:%d\n", sk_get_ip(&servaddr, ip),sk_get_port(&servaddr));
		cp_log(LDEBUG, "Sending packet... ");
				
		if (sendto(skt, (char *)buf, buf_len, 0, (struct sockaddr *)&(servaddr.sa), slen) == -1) {
			cp_log(LLOG, "failed\n");
			perror("sendto()");
			mr_lookups[idx].count++;
			return (FALSE);
		}
		mr_lookups[idx].count++;
		
		struct list_t *l;
		struct list_entry_t *lr, *ld;
		l = mr_lookups[idx].rlocs;
		lr = mr_lookups[idx].rloc_cur;
		if (l->count >= 1) {
			ld = lr;
			if (l->count > 1)
				lr = lr->previous;
			else
				lr = NULL;
			list_remove(l,ld,NULL);	
		}	
		else
			lr = NULL;
		mr_lookups[idx].rloc_cur = lr;		
	}
	return (TRUE);
}

/*Add new EID to poll*/
	void 
mr_new_lookup(void *data,struct communication_fct *fct,struct db_node *rn)
{
    int i,e,r,r6;
    uint16_t sport,sport6;             /* inner EMR header source port */
    char sport_str[NI_MAXSERV]; /* source port in string format */
    struct addrinfo hints;
    struct addrinfo *res;
	uint32_t *nonce0, *nonce1;
	uint64_t nonce;
	struct pk_req_entry *pke = data;

	/* Find an inactive slot in the lookup table */
    for (i = 0; i < MAX_LOOKUPS; i++)
        if (!mr_lookups[i].active)
            break;

    if (i >= MAX_LOOKUPS) {
	    return;
    }
	
	/*new socket for map-request */
	if ((r = socket(AF_INET, SOCK_DGRAM, udpproto)) < 0) {
		cp_log(LLOG, "Socket\n");
    }

	if ((r6 = socket(AF_INET6, SOCK_DGRAM, udpproto)) < 0) {
		cp_log(LLOG, "Socket6\n");
    }
    /*random source port of map-request */
	e = -1;
	while (e == -1) {
		sport = MIN_EPHEMERAL_PORT + random() % (MAX_EPHEMERAL_PORT - MIN_EPHEMERAL_PORT);
		sprintf(sport_str, "%d", sport);
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family    = AF_INET; 
		hints.ai_socktype  = SOCK_DGRAM;                
		hints.ai_flags     = AI_PASSIVE;                
		hints.ai_canonname = NULL;
		hints.ai_addr      = NULL;
		hints.ai_next      = NULL;
		
		if ((e = getaddrinfo(NULL, sport_str, &hints, &res)) != 0) {
			cp_log(LLOG, "getaddrinfo: %s\n", gai_strerror(e));	
			e = -1;
			continue;
		}
		
		if ((e = bind(r, res->ai_addr, res->ai_addrlen)) == -1) {					
			cp_log(LLOG, "bind error to port %s\n", sport_str);
			e = -1;
			continue;
		}
		freeaddrinfo(res);
	}
	
	e = -1;
	while (e == -1) {
		sport6 = MIN_EPHEMERAL_PORT + random() % (MAX_EPHEMERAL_PORT - MIN_EPHEMERAL_PORT);
		sprintf(sport_str, "%d", sport6);
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family    = AF_INET6; 
		hints.ai_socktype  = SOCK_DGRAM;                
		hints.ai_flags     = AI_PASSIVE;                
		hints.ai_canonname = NULL;
		hints.ai_addr      = NULL;
		hints.ai_next      = NULL;
		
		if ((e = getaddrinfo(NULL, sport_str, &hints, &res)) != 0) {
			cp_log(LLOG, "getaddrinfo: %s\n", gai_strerror(e));	
			e = -1;
			continue;
		}
		
		if ((e = bind(r6, res->ai_addr, res->ai_addrlen)) == -1) {
			cp_log(LLOG, "bind error to port %s\n", sport_str);
			e = -1;
			continue;
		}
		freeaddrinfo(res);
	}
	
	struct prefix eid;
	struct lisp_control_hdr *lh;
	int pkg_len;
	
	fct->request_get_eid(pke, &eid);
    
	mr_lookups[i].last_eid = NULL;
	mr_lookups[i].rx = r;
    mr_lookups[i].rx6 = r6;
    mr_lookups[i].count = 0;
    mr_lookups[i].active = 1;
	mr_lookups[i].pke = pke;
	mr_lookups[i].orgi_pkg = pke->lh;
	mr_lookups[i].orgi_pkg_len = pke->buf_len;
	pkg_len = pke->buf_len - (pke->lh - pke->buf);
	mr_lookups[i].orgi_pkg = calloc(pkg_len, sizeof(char));
	memcpy(mr_lookups[i].orgi_pkg, pke->lh, pkg_len);
	mr_lookups[i].orgi_pkg_len = pkg_len;
	lh = mr_lookups[i].orgi_pkg;	
	lh->ddt_originated  = 1;
	fct->request_get_nonce(pke, &nonce);
	nonce0 = (void *)&nonce;
	nonce1 = (uint32_t *)(nonce0+1);
	mr_lookups[i].nonce0  = *nonce0;
	mr_lookups[i].nonce1  = *nonce1;
		
	struct list_t *l,*lr;
	struct list_entry_t *_iter;
	struct map_entry *rl;
	
	l = mr_lookups[i].rlocs = list_init();;
	lr= (struct list_t *)db_node_get_info(rn);
	if (lr) {
		_iter = lr->head.next;
		while (_iter != &lr->tail) {
			rl = calloc(1,sizeof(struct map_entry));
			memcpy(rl,_iter->data,sizeof(struct map_entry));
			list_insert(l,rl,NULL);	
			_iter = _iter->next;
		}
	}	
	if (l->count >0)
		mr_lookups[i].rloc_cur = l->tail.previous;
	else
		mr_lookups[i].rloc_cur = NULL;
	clock_gettime(CLOCK_REALTIME, &mr_lookups[i].start);	
	send_mr_ddt(i);
}

/*if exist request, reset count, else add to request pending */
	int 
pending_request(void *data, struct communication_fct *fct, struct db_node *rn)
{
	uint64_t nonce;
	uint32_t *nonce0, *nonce1;
	int i, l;
	struct pk_req_entry *pke = data;
	fct->request_get_nonce(pke, &nonce);
	nonce0  = (void *)&nonce;
	nonce1  = (uint32_t *)(nonce0+1);
	l = -1;
	
	for (i = 0; i < MAX_LOOKUPS; i++) {
		if (!(mr_lookups[i].active)) continue;
		if (*nonce0 == mr_lookups[i].nonce0 && *nonce1 == mr_lookups[i].nonce1) {
			l = i;
			break;
		}
	}
	/*if request exist in pendig queue, reset count */
	if (l >= 0) {
		mr_lookups[l].count = 0;
		send_mr_ddt(l);
	}
	else{
		/* add new request to pending queue */		
		mr_new_lookup(pke,fct,rn);
	}	
	return 0;
}

	void
free_lookups(int idx)
{
	if (mr_lookups[idx].active) {
		udp_free_pk(mr_lookups[idx].pke);
		free(mr_lookups[idx].last_eid);
		mr_lookups[idx].last_eid = NULL;
		list_destroy(mr_lookups[idx].rlocs,rem);
		close(mr_lookups[idx].rx);
		close(mr_lookups[idx].rx6);
		mr_lookups[idx].active = 0;
	}
}

	void *
read_mr_ddt(void *enid)
{
	int rcvl;
	/* enid: encoding of idx and type of socket 
		enid = idx *2 + (ipv4?1:0);
	*/
	int idx = *((int *)enid) / 2;
	int ipv4 = *((int *)enid) % 2;
	char buf[PKBUFLEN];
	union sockunion si;
	struct map_referral_hdr *lcm;
	union map_referral_record_generic *rec;		/* current record */
	uint32_t nonce0, nonce1;
	socklen_t sockaddr_len;
	size_t lcm_len;
	uint8_t rcount;
	size_t rlen = 0;
	union afi_address_generic best_rloc;
	struct prefix *pf;
	
	free(enid);
	
	/* read package */
	if (ipv4) {
		sockaddr_len = sizeof(struct sockaddr_in);
		if ((rcvl = recvfrom(mr_lookups[idx].rx,
			 buf,
			 PKBUFLEN,
			0,
			(struct sockaddr *)&(si.sa),
			&sockaddr_len)) < 0) {
			return NULL;
		}
	}
	else{
		sockaddr_len = sizeof(struct sockaddr_in6);
		if ((rcvl = recvfrom(mr_lookups[idx].rx6,
			 buf,
			 PKBUFLEN,
			0,
			(struct sockaddr *)&(si.sa),
			&sockaddr_len)) < 0) {
			return NULL;
		}
	}
	
	/* reply must be map-referrel */
	lcm = (struct map_referral_hdr *)buf;	
	if (lcm->lisp_type != LISP_TYPE_MAP_REFERRAL) {
		return NULL;
	}
	
	/* check nonce for security*/
	nonce0 = ntohl(lcm->lisp_nonce0);
	nonce1 = ntohl(lcm->lisp_nonce1);
		
	if (mr_lookups[idx].nonce0 != nonce0 || mr_lookups[idx].nonce1 != nonce1)
		return NULL;		
	
	
	rcount = lcm->record_count;	
	if (rcount <= 0) {
		cp_log(LDEBUG, "NO RECORD\n");
		
		return NULL;
	}
	cp_log(LDEBUG, "LCM: <type=%u, rcount=%u nonce=0x%x - 0x%x>\n", \
				lcm->lisp_type, \
				rcount, \
				ntohl(lcm->lisp_nonce0), \
				ntohl(lcm->lisp_nonce1));
	
	lcm_len = sizeof(struct map_referral_hdr);
	rec = (union map_referral_record_generic *)CO(lcm, lcm_len);
	pf = calloc(1,sizeof(struct prefix));
	
		/* get new rloc */
	rlen = 0;
	struct db_node *node;		
	while (rcount--) {
		bzero(&best_rloc, sizeof(union afi_address_generic));
		/* check if eid return not loop */
		pf->family = rec->record.eid_prefix_afi;
		pf->prefixlen = rec->record.eid_mask_len;
		memcpy(&pf->u.prefix4,&rec->record.eid_prefix, SIN_LEN(pf->family));
		switch (rec->record.act) {
		case LISP_REFERRAL_MS_ACK:
			rlen = _process_referral_record(rec, &best_rloc, (struct db_node **)&node);
			cp_log(LDEBUG, "Reach to Map Server...Finish\n");				
			free_lookups(idx);
			free(pf);
			return NULL;
			break;
		case LISP_REFERRAL_NODE_REFERRAL:
		case LISP_REFERRAL_MS_REFERRAL:
			rlen = _process_referral_record(rec, &best_rloc, (struct db_node **)&node);
			if (mr_lookups[idx].last_eid && !prefix_match(mr_lookups[idx].last_eid,pf)) {
				cp_log(LDEBUG, "Error: Map-referral loop\n");
				free(pf);
				free_lookups(idx);
				return NULL;
			}
			
			/* update rloc of pending-eid */
			if (!mr_lookups[idx].last_eid || (pf->prefixlen > mr_lookups[idx].last_eid->prefixlen) ) {
				if (!mr_lookups[idx].last_eid)
					mr_lookups[idx].last_eid = calloc(1,sizeof(struct prefix));
				memcpy(mr_lookups[idx].last_eid, pf, sizeof(struct prefix));
				struct list_t *l,*lr;
				struct list_entry_t *_iter;
				struct map_entry *rl;
				
				l = mr_lookups[idx].rlocs;
				lr= (struct list_t *)db_node_get_info(node);
				if (lr) {
					_iter = lr->head.next;
					while (_iter != &lr->tail) {
						rl = calloc(1,sizeof(struct map_entry));
						memcpy(rl,_iter->data,sizeof(struct map_entry));
						list_insert(l,rl,NULL);	
						_iter = _iter->next;
					}
					if (l->count > 0)
						mr_lookups[idx].rloc_cur = l->tail.previous;
					else
						mr_lookups[idx].rloc_cur = NULL;
				}
			}
			break;
		case LISP_REFERRAL_MS_NOT_REGISTERED:
			if (mr_lookups[idx].rlocs->count == 1) {
				/* send map-negative-reply */	
			}
			break;	
		case LISP_REFERRAL_DELEGATION_HOLE:
			/* send map-negative-reply */
			free(pf);
			free_lookups(idx);
			return NULL;
			break;
		case LISP_REFERRAL_NOT_AUTHORITATIVE:
			/* clear cache */
			free(pf);
			free_lookups(idx);
			return NULL;
			break;			
		}
		rec = (union map_referral_record_generic *)CO(rec, rlen);
	}
	free(pf);
	send_mr_ddt(idx);
	return NULL;
}

	void *
get_mr_ddt(void *data)
{
	int idx;
	struct map_referral_hdr *lcm;
	union map_referral_record_generic *rec;		/* current record */
	uint32_t nonce0, nonce1;
	size_t lcm_len;
	uint8_t rcount;
	size_t rlen = 0;
	union afi_address_generic best_rloc;
	struct pk_req_entry *pke = data;
	void *buf = pke->buf;
	struct prefix *pf;
		
	/* reply must be map-referrel */
	lcm = (struct map_referral_hdr *)buf;	
	if (lcm->lisp_type != LISP_TYPE_MAP_REFERRAL) {
		return NULL;
	}
	
	/* check nonce for security*/
	nonce0 = ntohl(lcm->lisp_nonce0);
	nonce1 = ntohl(lcm->lisp_nonce1);
	for (idx = 0 ; idx < mr_nfds - 1; idx++) {
		if (_debug == LDEBUG) {		
			fprintf(OUTPUT_STREAM, "idx=%d, nonce=0x%x - 0x%x>\n", \
				idx, \
				mr_lookups[idx].nonce0, \
				mr_lookups[idx].nonce1);
		}
		if (mr_lookups[idx].nonce0 == nonce0 && mr_lookups[idx].nonce1 == nonce1)
			break;
	}
	printf("Match with idx:%d\n",idx);
	if (_debug == LDEBUG) {		
		fprintf(OUTPUT_STREAM, "LCM: <type=%u, nonce=0x%x - 0x%x>\n", \
				lcm->lisp_type, \
				ntohl(lcm->lisp_nonce0), \
				ntohl(lcm->lisp_nonce1));
	}
	
	if (idx >= mr_nfds -1)
		return NULL;
	
	rcount = lcm->record_count;	
	if (rcount <= 0) {
		if (_debug == LDEBUG)	
			fprintf(OUTPUT_STREAM, "NO RECORD\n");
		
		return NULL;
	}
	if (_debug == LDEBUG) {		
		fprintf(OUTPUT_STREAM, "LCM: <type=%u, rcount=%u nonce=0x%x - 0x%x>\n", \
				lcm->lisp_type, \
				rcount, \
				ntohl(lcm->lisp_nonce0), \
				ntohl(lcm->lisp_nonce1));
	}
	
	lcm_len = sizeof(struct map_referral_hdr);
	rec = (union map_referral_record_generic *)CO(lcm, lcm_len);
	pf = calloc(1,sizeof(struct prefix));
	
		/* get new rloc */
	rlen = 0;
	struct db_node *node;		
	while (rcount--) {
		bzero(&best_rloc, sizeof(union afi_address_generic));
		/* check if eid return not loop */
		switch (ntohs(rec->record.eid_prefix_afi)) {
		case LISP_AFI_IP:
			pf->family = AF_INET;
			break;
		case LISP_AFI_IPV6:
			pf->family = AF_INET6;	
			break;
		default:
			printf("Get_mr_dtt function: not support AF\n");
			return NULL;
		}		
		
		pf->prefixlen = rec->record.eid_mask_len;
		memcpy(&pf->u.prefix4,&rec->record.eid_prefix, SIN_LEN(pf->family));
		switch (rec->record.act) {
		case LISP_REFERRAL_MS_ACK:
			rlen = _process_referral_record(rec, &best_rloc, (struct db_node **)&node);
			if (_debug == LDEBUG)	
				fprintf(OUTPUT_STREAM, "Reach to Map Server...Finish\n");				
			free_lookups(idx);
			free(pf);
			return NULL;
			break;
		case LISP_REFERRAL_NODE_REFERRAL:
		case LISP_REFERRAL_MS_REFERRAL:
			rlen = _process_referral_record(rec, &best_rloc, (struct db_node **)&node);
			if (mr_lookups[idx].last_eid && !prefix_match(mr_lookups[idx].last_eid,pf)) {
				if (_debug == LDEBUG)	
					fprintf(OUTPUT_STREAM,"Error: Map-referral loop\n");
				free(pf);
				free_lookups(idx);
				return NULL;
			}
				
			/* update rloc of pending-eid */
			if (!mr_lookups[idx].last_eid || (pf->prefixlen > mr_lookups[idx].last_eid->prefixlen) ) {
				if (!mr_lookups[idx].last_eid)
					mr_lookups[idx].last_eid = calloc(1,sizeof(struct prefix));
				memcpy(mr_lookups[idx].last_eid, pf, sizeof(struct prefix));
				struct list_t *l,*lr;
				struct list_entry_t *_iter;
				struct map_entry *rl;
				
				l = mr_lookups[idx].rlocs;
				lr= (struct list_t *)db_node_get_info(node);
				if (lr) {
					_iter = lr->head.next;
					while (_iter != &lr->tail) {
						rl = calloc(1,sizeof(struct map_entry));
						memcpy(rl,_iter->data,sizeof(struct map_entry));
						list_insert(l,rl,NULL);	
						_iter = _iter->next;
					}
					if (l->count > 0)
						mr_lookups[idx].rloc_cur = l->tail.previous;
					else
						mr_lookups[idx].rloc_cur = NULL;
				}
			}
			break;
		case LISP_REFERRAL_MS_NOT_REGISTERED:
			if (mr_lookups[idx].rlocs->count == 1) {
				//send map-negative-reply					
			}
			break;	
		case LISP_REFERRAL_DELEGATION_HOLE:
			printf("HOLE: send map-negative-reply\n");
			struct pk_rpl_entry *rpk;
			rpk = udp_reply_add(mr_lookups[idx].pke);
			printf("For EID: %s\n",(char *)prefix2str(pf));
			udp_reply_add_record(rpk, pf, 15, 0, 0, 0, 1);
			udp_reply_terminate(rpk);
			//send map-negative-reply
			free(pf);
			free_lookups(idx);
			return NULL;
			break;
		case LISP_REFERRAL_NOT_AUTHORITATIVE:
			//clear cache
			free(pf);
			free_lookups(idx);
			return NULL;
			break;			
		}
		rec = (union map_referral_record_generic *)CO(rec, rlen);
	}
	free(pf);
	send_mr_ddt(idx);
	return NULL;
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

	void *
mr_event_loop(void *context)
{
	thr_pool_t *mrworker;
	mrworker = thr_pool_create(min_thread,max_thread,linger_thread, NULL);
	int *enid;
	
	for (;;) {
        int e, i, j, l = -1,ipv4;
		int poll_timeout = timeout*1000;
        
		//int poll_timeout = INFTIM; 
		/* poll() timeout in milliseconds. We initialize
                                   to INFTIM = -1 (infinity). If there are no
                                   active lookups, we wait in poll() until a
                                   mapping socket event is received. */
        struct timespec now, deadline, delta, to, tmp;
	
        to.tv_sec  = timeout;
        to.tv_nsec = 0;

        mr_nfds = 0;

        clock_gettime(CLOCK_REALTIME, &now);

        for (i = 0; i < MAX_LOOKUPS; i++) {
            if (!(mr_lookups[i].active)) continue;
			if (mr_lookups[i].count > MR_MAX_LOOKUP) {
				free_lookups(i);
				continue;
			}
			
            deadline.tv_sec = mr_lookups[i].start.tv_sec + mr_lookups[i].count * timeout; 
            deadline.tv_nsec = mr_lookups[i].start.tv_nsec;
		
            timespec_subtract(&delta, &deadline, &now);
			if (delta.tv_sec < 0) {
				delta.tv_sec = timeout/2 ;
				delta.tv_nsec = 0;
			}
			
            mr_fds[mr_nfds].fd     = mr_lookups[i].rx;
            mr_fds[mr_nfds].events = POLLIN;
			mr_fds_idx[mr_nfds]    = i;
			mr_nfds++;
			mr_fds6[mr_nfds].fd     = mr_lookups[i].rx6;
            mr_fds[mr_nfds].events = POLLIN;
            mr_fds_idx[mr_nfds]    = i;
            mr_nfds++;
            /* Find the minimum delta */
            if (timespec_subtract(&tmp, &delta, &to)) {
				to.tv_sec    = delta.tv_sec;
                to.tv_nsec   = delta.tv_nsec;
                poll_timeout = to.tv_sec * 1000 + to.tv_nsec / 1000000;
                l = i;
            }			
        } /* Finished iterating through all lookups */
		
		e = poll(mr_fds, mr_nfds, poll_timeout);		
        if (e < 0) continue;		
        if (e == 0)                             /* If timeout expires */
            if (l >= 0)                         /* and slot is defined */
				send_mr_ddt(l);                    /* retry Map-Request */
		for (j = mr_nfds - 1; j >= 0; j--) {
            if (mr_fds[j].revents == POLLIN) {
				ipv4 = (j % 2 == 0)?1:0;
				enid = calloc(1,sizeof(int));
				/*enid: encoding of idx and ipv4 */
				*enid = mr_fds_idx[j]*2+ipv4;
                //thr_pool_queue(mrworker, read_mr_ddt, (void *)enid);
				read_mr_ddt((void *)enid);
            }
        }
    }
}
