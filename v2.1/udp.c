
#include "lib.h"
#include "udp.h"

uint32_t _request(uint32_t request_id);
uint32_t _register(uint32_t request_id);
uint32_t _referral(uint32_t  request_id);
uint32_t _forward(uint32_t  request_id);

size_t _process_register_record(const union map_reply_record_generic * rec);
size_t _process_referral_record(const union map_referral_record_generic * rec, union afi_address_generic * best_rloc, struct db_node ** node);                                                                                   
int  _ms_validate_register(struct lisp_db * db, const void * packet, void ** site_ptr);
void _ms_clean_site_mapping(struct list_entry_t * site);
size_t _ms_process_register_record(struct lisp_db * db, struct list_entry_t * site, 
									const union map_reply_record_generic * rec,uint8_t proxy_map_repl );

void * general_register_process(void * data);


/*------------helper function-------------------  */

/* Make new nonce base on random function
   future need new method */
   
	void 
_make_nonce(uint64_t * nonce)
{
    uint32_t * nonce0;
    uint32_t * nonce1;
	nonce0  = (uint32_t *)nonce;
	nonce1  = (uint32_t *)(nonce0+1);
	*nonce0 = random()^random();
    *nonce1 = random()^time(NULL);
}

/* Get free place in pool with number of places < max 
	future need function to process with zombie package if exist*/

	uint32_t
_get_pool_place(void * pool[], int max)
{
	int i = 1;
	while( (i < max) && (pool[i] != NULL) )
		i++;
		
	if(i == max){
		return -1;
	}
	return i;
}

/* a very basic function to remove a request package from queue */

	void 
_rm_req(void * entry)
{
	free( ((struct pk_req_entry *)entry)->buf);
}

	void 
_rm_rpl(void * entry)
{
	free( ((struct pk_rpl_entry *)entry)->buf);
}

	uint32_t
_free_pool_place(void * pool[], uint32_t id, void (* fnc)(void *))
{
	if(!pool[id])
		return -1;
	fnc((void *)pool[id]);	
	free(pool[id]);
	pool[id] = NULL;	
	return 0;
}

/*
 * Determine the LISP AFI type of an <AFI, address> tuple on the wire
 */
	inline static uint16_t
_get_address_type(const union afi_address_generic * addr)
{
	return (ntohs(addr->ip.afi));
}


/* Determine the actual size of an <AFI, address> tuple on the wire (only IPv4
 * and IPv6 supported)
 */
	inline size_t 
_get_address_size(const union afi_address_generic * addr)
{
	switch(_get_address_type(addr)){
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
_get_record_size(const union map_request_record_generic * rec)
{
	switch(ntohs(rec->record.eid_prefix_afi)){
		case LISP_AFI_IP:
			return (sizeof(struct map_request_record));
		case LISP_AFI_IPV6:
			return (sizeof(struct map_request_record6));
		default:
			fprintf(OUTPUT_STREAM,"AF not support\n");
			//assert(FALSE);
			return (0);
	}
}

/* 
 * Determine the actual size of a Map-Reply record tuple on the wire (only
 * IPv4 and IPv6 supported)
 */
	inline size_t
_get_reply_record_size(const union map_reply_record_generic * rec)
{

	switch(ntohs(rec->record.eid_prefix_afi)){
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
_get_referral_record_size(const union map_referral_record_generic * rec)
{

	switch(ntohs(rec->record.eid_prefix_afi)){
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
_afi_address_str(const union afi_address_generic * addr, char * buf, size_t len)
{
	int ret = TRUE;
	bzero(buf, len);
	switch(_get_address_type(addr)){
		case LISP_AFI_IP:
			inet_ntop(AF_INET, (void *)&addr->ip.address, buf, len);
			break;
		case LISP_AFI_IPV6:
			inet_ntop(AF_INET6, (void *)&addr->ip6.address, buf, len);
			break;
		default:
			snprintf(buf, len, "address not present");
			ret = FALSE;
			break;
	}
	return ret;
}

/* convert union sockunio to afi_address */

	int 
_sockunion_to_afi_address(const union sockunion * su, union afi_address_generic * afi_address)
{
	bzero(afi_address, sizeof(union afi_address_generic));
	switch(su->sa.sa_family){
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
			fprintf(OUTPUT_STREAM, "AFI not supported union sockunion to afi_address\n");
			return (FALSE);
	}
	return (TRUE);
}

/*------------Main functions: Reply------------- */

	
	uint32_t 
udp_new_reply_entry(uint32_t request_id)
{
	uint32_t reply_id;
	
	reply_id = _get_pool_place((void *)_pk_rpl_pool,PK_POOL_MAX);
	if(reply_id < 0)
		return -1;
	_pk_rpl_pool[reply_id] = calloc(1, sizeof(struct pk_rpl_entry));
	_pk_rpl_pool[reply_id]->buf = calloc(PKMSIZE,sizeof(char));
	_pk_rpl_pool[reply_id]->curs = _pk_rpl_pool[reply_id]->buf;
	_pk_rpl_pool[reply_id]->buf_len = 0;
	_pk_rpl_pool[reply_id]->request_id = request_id;
	
	return reply_id;
}

/* ========================================================== */
/* Map-register handing code */

	uint32_t
udp_register_add(uint32_t request_id)
{
	struct map_register_hdr * hdr;
	uint32_t reply_id;
	//uint32_t * nonce_trick;
	//uint64_t nonce;
	
	if( (reply_id = udp_new_reply_entry(request_id)) < 0)
	{
		return -1;
	}
	bzero(_pk_rpl_pool[reply_id]->buf,PKMSIZE);
	hdr = (struct map_register_hdr *)_pk_rpl_pool[reply_id]->buf;
	
	/* write the 64-bit nonce in two 32-bit fields
	 * need this trick because of the LITTLE_ENDIAN
	 */
	
	//_make_nonce(&nonce);
	//nonce_trick = (uint32_t *)&nonce;
	hdr->lisp_type = LISP_TYPE_MAP_REGISTER;
	//hdr->lisp_nonce0 = htonl((*nonce_trick));
	//hdr->lisp_nonce1 = htonl((*(nonce_trick + 1)));

	/* ================================= */
	//fprintf(OUTPUT_STREAM, "Map-Register ");
	//fprintf(OUTPUT_STREAM, " <");
	//fprintf(OUTPUT_STREAM, "nonce=0x%x - 0x%x", ntohl(hdr->lisp_nonce0), ntohl(hdr->lisp_nonce1));
	//fprintf(OUTPUT_STREAM, ">\n");
	/* ================================= */
	_pk_rpl_pool[reply_id]->curs = CO(hdr,sizeof(struct map_register_hdr)+20);
	_pk_rpl_pool[reply_id]->buf_len = (char *)_pk_rpl_pool[reply_id]->curs - (char *)_pk_rpl_pool[reply_id]->buf;
	return reply_id;
}

/* send map-register
	udp_register_add_record == udp_reply_add_record
	udp_register_add_locator == udp_reply_add_locator
 */
	int 
udp_register_add_record(uint32_t register_id, struct prefix * p, 
					uint32_t ttl, uint8_t lcount, uint32_t version, uint8_t A, uint8_t act)
{
	return udp_reply_add_record(register_id, p, ttl, lcount, version, A, act);			
}

	int 
udp_register_add_locator(uint32_t register_id, struct map_entry * e)
{
	return udp_reply_add_locator(register_id, e);
}

/* send map-register to ms */

	uint32_t
udp_register_terminate(uint32_t id, union sockunion * ds)
{
	int skt;
	socklen_t slen = 0;
		
	fprintf(OUTPUT_STREAM, "send Map-Register ");
	fprintf(OUTPUT_STREAM, "to %s:%d\n", 
			sk_get_ip(ds, ip), sk_get_port(ds) );
	fprintf(OUTPUT_STREAM, "Sending packet... ");
	
	skt = 0;
	if( (ds->sa).sa_family == AF_INET){
		if ((skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
			perror("socket");
			exit(0);
		}
		//skt = skfd;
		slen = sizeof(struct sockaddr_in);
	}else if((ds->sa).sa_family == AF_INET6){
		//skt = skfd6;
		if( (skt = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1){
			perror("socket");
			exit(0);
		}
		slen = sizeof(struct sockaddr_in6);
	}
	else{
		fprintf(OUTPUT_STREAM,"Map-server not correct::AF_NOT_SUPPORT\n");
		exit(0);
	}
	
	if(sendto(skt, (char *)_pk_rpl_pool[id]->buf, _pk_rpl_pool[id]->buf_len, 0, (struct sockaddr *)&(ds->sa), slen) == -1){
		fprintf(OUTPUT_STREAM, "failed\n");
		perror("sendto( )");
		close(skt);
		return (FALSE);
	}
	close(skt);
	fprintf(OUTPUT_STREAM, "done\n");
	return (TRUE);
}

	uint32_t
udp_register_error(uint32_t register_id)
{
	fprintf(OUTPUT_STREAM,"Error processing\n");
	return -1;
}

/* ========================================================== */
/* Map-Reply handling code */

/* make new map-reply header */

	int 
udp_reply_add(uint32_t request_id)
{
	struct map_reply_hdr * hdr;
	uint32_t reply_id;
	uint32_t * nonce_trick;
	uint64_t nonce;
	
	if( (reply_id = udp_new_reply_entry(request_id)) < 0)
	{
		_free_pool_place((void *)_pk_req_pool, request_id, _rm_req);
		return -1;
	}
	
	hdr = (struct map_reply_hdr *)_pk_rpl_pool[reply_id]->buf;
	
	/* write the 64-bit nonce in two 32-bit fields
	 * need this trick because of the LITTLE_ENDIAN
	*/
	 
	udp_request_get_nonce(request_id, &nonce);
	nonce_trick = (uint32_t *)&nonce;
	hdr->lisp_type = LISP_TYPE_MAP_REPLY;
	hdr->lisp_nonce0 = htonl(*nonce_trick);
	hdr->lisp_nonce1 = htonl(*(nonce_trick + 1));

	/* ================================= */
	fprintf(OUTPUT_STREAM, "Map-Reply ");
	fprintf(OUTPUT_STREAM, " <");
	fprintf(OUTPUT_STREAM, "nonce=0x%x - 0x%x", ntohl(hdr->lisp_nonce0), ntohl(hdr->lisp_nonce1));
	fprintf(OUTPUT_STREAM, ">\n");
	/* ================================= */
	_pk_rpl_pool[reply_id]->curs = CO(hdr,sizeof(struct map_reply_hdr));
	_pk_rpl_pool[reply_id]->buf_len = (char *)_pk_rpl_pool[reply_id]->curs - (char *)_pk_rpl_pool[reply_id]->buf;
	return reply_id;
}

/* add new record to message */
					
	int 
udp_reply_add_record(uint32_t reply_id, struct prefix * p, 
					uint32_t ttl, uint8_t lcount, uint32_t version, uint8_t A, uint8_t act)
{
	union map_reply_record_generic * rec;
	struct map_reply_hdr * hdr;
	
	hdr = (struct map_reply_hdr *)_pk_rpl_pool[reply_id]->buf;
	hdr->record_count++;
	
	rec = (union map_reply_record_generic *)_pk_rpl_pool[reply_id]->curs;

	rec->record.ttl = htonl(ttl);
	rec->record.locator_count = lcount;
	rec->record.eid_mask_len = p->prefixlen;
	
	/* Negative Map-Reply */
	if(0 == lcount){
		rec->record.act = act;
	}
	rec->record.a = A;
	rec->record.version = htonl(version);

	switch(p->family){
		case AF_INET:
			rec->record.eid_prefix_afi = htons(LISP_AFI_IP);
			memcpy(&rec->record.eid_prefix, &p->u.prefix4, sizeof(struct in_addr));
			_pk_rpl_pool[reply_id]->curs = CO(rec, sizeof(struct map_reply_record));
			break;
		case AF_INET6:
			rec->record6.eid_prefix_afi = htons(LISP_AFI_IPV6);
			memcpy(&rec->record6.eid_prefix, &p->u.prefix6, sizeof(struct in6_addr));
			_pk_rpl_pool[reply_id]->curs = CO(rec, sizeof(struct map_reply_record6));
			break;
		default:
			assert(FALSE);
			break;
	}
	_pk_rpl_pool[reply_id]->buf_len = (char *)_pk_rpl_pool[reply_id]->curs - (char *)_pk_rpl_pool[reply_id]->buf;
	
	/* ==================================================== */
	char buf[BSIZE];

	bzero(buf, BSIZE);
	inet_ntop(p->family, (void *)&p->u.prefix, buf, BSIZE);
	fprintf(OUTPUT_STREAM, "EID %s/%d: ", buf, p->prefixlen);

	fprintf(OUTPUT_STREAM, "<");
	fprintf(OUTPUT_STREAM, "Lcount=%u", lcount);
	
	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "TTL=%u", ttl);

	if(lcount == 0){
		fprintf(OUTPUT_STREAM, ", ");
		fprintf(OUTPUT_STREAM, "ACT=%d", act);
	}

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "version=%u", version);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "A=%u", A);

	fprintf(OUTPUT_STREAM, ">\n");
	
	if(lcount == 0){
		fprintf(OUTPUT_STREAM, "\tNegative reply\n");
	}
	/* ====================================================== */
	
	return (TRUE);
}

/* add more locator to message */

	int 
udp_reply_add_locator(uint32_t id, struct map_entry * e)
{
	union map_reply_locator_generic * loc;
	
	loc = (union map_reply_locator_generic *)_pk_rpl_pool[id]->curs;

	loc->rloc.priority = e->priority;
	loc->rloc.weight = e->weight;
	loc->rloc.m_priority = e->m_priority;
	loc->rloc.m_weight = e->m_weight;
	loc->rloc.L = e->L;
	loc->rloc.p = e->p;
	loc->rloc.R = e->r;

	switch(e->rloc.sa.sa_family){
		case AF_INET:
			loc->rloc.rloc_afi = htons(LISP_AFI_IP);
			memcpy(&loc->rloc.rloc, &e->rloc.sin.sin_addr, sizeof(struct in_addr));
			_pk_rpl_pool[id]->curs = CO(loc, sizeof(struct map_reply_locator));
			break;
		case AF_INET6:
			loc->rloc6.rloc_afi = htons(LISP_AFI_IPV6);
			memcpy(&loc->rloc6.rloc, &e->rloc.sin6.sin6_addr, sizeof(struct in6_addr));
			_pk_rpl_pool[id]->curs = CO(loc, sizeof(struct map_reply_locator6));
			break;
		default:
			assert(FALSE);
	}
	_pk_rpl_pool[id]->buf_len = (char *)_pk_rpl_pool[id]->curs - (char *)_pk_rpl_pool[id]->buf;

	/* ================================================= */
	char buf[BSIZE];
	bzero(buf, BSIZE);
	switch(e->rloc.sa.sa_family){
		case AF_INET:
			inet_ntop(AF_INET, (void *)&e->rloc.sin.sin_addr, buf, BSIZE);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, (void *)&e->rloc.sin6.sin6_addr, buf, BSIZE);
			break;
		default:
			fprintf(OUTPUT_STREAM, "unsuported family\n");
			return (FALSE);
	}
	fprintf(OUTPUT_STREAM, "\t[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d, L=%d, p=%d]\n", \
			buf, \
			e->priority, \
			e->weight, \
			e->m_priority, \
			e->m_weight, \
			e->r, \
			e->L, \
			e->p);
	/* ================================================= */

	return (TRUE);
}


/* send map-reply */
	int 
udp_reply_terminate(uint32_t id)
{
	union sockunion local;
	int socket;
	socklen_t slen;
	uint32_t request_id;
	union sockunion itr;
	struct pk_req_entry * p;
	
	fprintf(OUTPUT_STREAM, "send Map-Reply ");
	request_id = _pk_rpl_pool[id]->request_id;
	p = _pk_req_pool[request_id];
	
	if(!p->emc){
		memcpy(&local, &p->si, sizeof(local));
	}else {
		/* choose one ITR */
		if( udp_request_get_itr(request_id,&itr,0) <= 0)
			return -1;
		
		local.sin.sin_family = itr.sin.sin_family;
		if(itr.sin.sin_family == AF_INET){	
			memcpy(&local.sin.sin_addr, &itr.sin.sin_addr, SIN_LEN(AF_INET));
			local.sin.sin_port = p->ih_si.sin.sin_port;
		}
		else{
			memcpy(&local.sin6.sin6_addr, &itr.sin6.sin6_addr, SIN_LEN(AF_INET6));
			local.sin6.sin6_port = p->ih_si.sin6.sin6_port;
		}	
	}
	
	fprintf(OUTPUT_STREAM, "to %s:%d\n", 
			sk_get_ip(&local, ip), sk_get_port(&local) );
	fprintf(OUTPUT_STREAM, "Sending packet... ");
	
	socket = 0;
	if ( (local.sa).sa_family == AF_INET){
		socket = skfd;
		slen = sizeof(struct sockaddr_in);
	}
	else if( (local.sa).sa_family == AF_INET6){
		socket = skfd6;
		slen = sizeof(struct sockaddr_in6);
	}
	
	if(socket){
		if(sendto(socket, (char *)_pk_rpl_pool[id]->buf, _pk_rpl_pool[id]->buf_len, 0, (struct sockaddr *)&(local.sa), slen) == -1){
			fprintf(OUTPUT_STREAM, "failed\n");
			perror("sendto( )");
			_free_pool_place((void *)_pk_rpl_pool, id, _rm_rpl);
			return (FALSE);
		}
	}	
	else{
		fprintf(OUTPUT_STREAM, "failed\n");
		perror("select_socket");
		_free_pool_place((void *)_pk_rpl_pool, id, _rm_rpl);
		return (FALSE);
	}
	fprintf(OUTPUT_STREAM, "done\n");
	_free_pool_place((void *)_pk_rpl_pool, id, _rm_rpl);

	return (TRUE);
}

/* error when process */
	int 
udp_reply_error(uint32_t id)
{
	fprintf(OUTPUT_STREAM, "Unknown error (%u)\n", id);
	return (TRUE);
}

/* ========================================================== */
/*  Map-Referral handling code */

/* make new map-referral message */
	
	int 
udp_referral_add(uint32_t request_id)
{
	struct map_referral_hdr * hdr;
	uint32_t * nonce_trick;
	uint64_t nonce;
	uint32_t reply_id;
	
	reply_id = _get_pool_place((void *)_pk_rpl_pool,PK_POOL_MAX);
	
	_pk_rpl_pool[reply_id] = calloc(1, sizeof(struct pk_rpl_entry));
	_pk_rpl_pool[reply_id]->buf = calloc(PKMSIZE,sizeof(char));
	_pk_rpl_pool[reply_id]->curs = _pk_rpl_pool[reply_id]->buf;
	_pk_rpl_pool[reply_id]->buf_len = 0;
	_pk_rpl_pool[reply_id]->request_id = request_id;
	
	
	hdr = (struct map_referral_hdr *)_pk_rpl_pool[reply_id]->buf;

	/* write the 64-bit nonce in two 32-bit fields
	*  need this trick because of the LITTLE_ENDIAN
	*/
	
	udp_request_get_nonce(request_id, &nonce);
	nonce_trick = (uint32_t *)(&nonce);
	hdr->lisp_type = LISP_TYPE_MAP_REFERRAL;
	hdr->lisp_nonce0 = htonl(*nonce_trick);
	hdr->lisp_nonce1 = htonl(*(nonce_trick + 1));

	/* ================================= */
	fprintf(OUTPUT_STREAM, "Map-Referral ");
	fprintf(OUTPUT_STREAM, " <");
	fprintf(OUTPUT_STREAM, "nonce=0x%x - 0x%x", ntohl(hdr->lisp_nonce0), ntohl(hdr->lisp_nonce1));
	fprintf(OUTPUT_STREAM, ">\n");
	/* ================================= */

	_pk_rpl_pool[reply_id]->curs = (void *)CO(hdr, sizeof(struct map_referral_hdr));
	_pk_rpl_pool[reply_id]->buf_len = (char *)_pk_rpl_pool[reply_id]->curs - (char *)_pk_rpl_pool[reply_id]->buf;
	return reply_id;
}

/* add new record to map-referral */
	int 
udp_referral_add_record(uint32_t id, uint32_t iid, struct prefix * p, uint32_t ttl, uint8_t lcount, 
						uint32_t version, uint8_t A, uint8_t act, uint8_t i, uint8_t sigcnt)
{
	union map_referral_record_generic * rec;
	struct map_referral_hdr * hdr;
	
	hdr = (struct map_referral_hdr *)_pk_rpl_pool[id]->buf;
	hdr->record_count++;
	
	rec = (union map_referral_record_generic *)_pk_rpl_pool[id]->curs;

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
	
	
	switch(p->family){
		case AF_INET:
			rec->record.eid_prefix_afi = htons(LISP_AFI_IP);
			memcpy(&rec->record.eid_prefix, &p->u.prefix4, sizeof(struct in_addr));
			_pk_rpl_pool[id]->curs = CO(rec, sizeof(struct map_referral_record));
			rec->record.lcaf.length = 4+2+sizeof(struct in_addr);
			break;
		case AF_INET6:
			rec->record6.eid_prefix_afi = htons(LISP_AFI_IPV6);
			memcpy(&rec->record6.eid_prefix, &p->u.prefix6, sizeof(struct in6_addr));
			_pk_rpl_pool[id]->curs = CO(rec, sizeof(struct map_referral_record6));
			rec->record.lcaf.length = 4+2+sizeof(struct in6_addr);
			break;
		default:
			assert(FALSE);
			break;
	}
	
	_pk_rpl_pool[id]->buf_len = (char *)_pk_rpl_pool[id]->curs - (char *)_pk_rpl_pool[id]->buf;
	/* ==================================================== */
	char buf[BSIZE];

	bzero(buf, BSIZE);
	inet_ntop(p->family, (void *)&p->u.prefix, buf, BSIZE);
	fprintf(OUTPUT_STREAM, "EID %s/%d: ", buf, p->prefixlen);

	fprintf(OUTPUT_STREAM, "<");
	fprintf(OUTPUT_STREAM, "ref_count=%u", lcount);
	
	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "TTL=%u", ttl);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "ACT=%d", act);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "version=%u", version);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "A=%u", A);

	fprintf(OUTPUT_STREAM, ">\n");
	
	if(lcount == 0){
		fprintf(OUTPUT_STREAM, "\tNegative referral\n");
	}
	/* ====================================================== */
	return (TRUE);
}

/* add new locator  to map-referral-record */

	int 
udp_referral_add_locator(uint32_t id, struct map_entry * e)
{
	union map_referral_locator_generic * loc;

	loc = (union map_referral_locator_generic *)_pk_rpl_pool[id]->curs;

	loc->rloc.priority = e->priority;
	loc->rloc.weight = e->weight;
	loc->rloc.m_priority = e->m_priority;
	loc->rloc.m_weight = e->m_weight;
	loc->rloc.R = e->r;

	switch(e->rloc.sa.sa_family){
		case AF_INET:
			loc->rloc.rloc_afi = htons(LISP_AFI_IP);
			memcpy(&loc->rloc.rloc, &e->rloc.sin.sin_addr, sizeof(struct in_addr));
			_pk_rpl_pool[id]->curs = CO(loc, sizeof(struct map_referral_locator));
			break;
		case AF_INET6:
			loc->rloc6.rloc_afi = htons(LISP_AFI_IPV6);
			memcpy(&loc->rloc6.rloc, &e->rloc.sin6.sin6_addr, sizeof(struct in6_addr));
			_pk_rpl_pool[id]->curs = CO(loc, sizeof(struct map_referral_locator6));
			break;
		default:
			assert(FALSE);
	}
	_pk_rpl_pool[id]->buf_len = (char *)_pk_rpl_pool[id]->curs - (char *)_pk_rpl_pool[id]->buf;
	/* ================================================= */
	char buf[BSIZE];
	bzero(buf, BSIZE);
	switch(e->rloc.sa.sa_family){
		case AF_INET:
			inet_ntop(AF_INET, (void *)&e->rloc.sin.sin_addr, buf, BSIZE);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, (void *)&e->rloc.sin6.sin6_addr, buf, BSIZE);
			break;
		default:
			fprintf(OUTPUT_STREAM, "unsuported family\n");
			return (FALSE);
	}
	fprintf(OUTPUT_STREAM, "\t[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d]\n", \
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
udp_referral_error(uint32_t id)
{
	printf("referral_error\n");
	return (TRUE);
	
}

/* send map-referral */

	int 
udp_referral_terminate(uint32_t id)
{
	
	union sockunion local;
	int socket;
	uint32_t request_id;
	socklen_t slen;
	
	fprintf(OUTPUT_STREAM, "send Map-Referral ");
	request_id = _pk_rpl_pool[id]->request_id;
	memcpy(&local, &_pk_req_pool[request_id]->si, sizeof(local));
	sk_set_port(&local,LISP_CP_PORT);
	
	fprintf(OUTPUT_STREAM, "to %s:%d\n", 
			sk_get_ip(&local, ip), sk_get_port(&local) );
	fprintf(OUTPUT_STREAM, "Sending packet... ");
	
	socket = 0;
	if ( (local.sa).sa_family == AF_INET){
		socket = skfd;
		slen = sizeof(struct sockaddr_in);
	}
	else if( (local.sa).sa_family == AF_INET6){
		socket = skfd6;
		slen = sizeof(struct sockaddr_in6);
	}
	
	if(socket){
		if(sendto(socket, _pk_rpl_pool[id]->buf, _pk_rpl_pool[id]->buf_len, 0, (struct sockaddr *)&(local.sa), slen) == -1){
			fprintf(OUTPUT_STREAM, "failed\n");
			perror("sendto( )");
			_free_pool_place((void *)_pk_rpl_pool, id, _rm_rpl);
			return (FALSE);
		}
	}
	else{
		fprintf(OUTPUT_STREAM, "failed\n");
		perror("select_socket");
		_free_pool_place((void *)_pk_rpl_pool, id, _rm_rpl);
		
		return (FALSE);
	}
	fprintf(OUTPUT_STREAM, "done\n");
	_free_pool_place((void *)_pk_rpl_pool, id, _rm_rpl);
	
	return (TRUE);	
}

/* ========================================================== */
/*  Map-Request handling code */

/* support function */

/* free map-request from queue */
	int 
udp_request_terminate(uint32_t id)
{
	_free_pool_place((void *)_pk_req_pool, id, _rm_req);
	return (TRUE);
}

/* get first eid in map-request */
/* future need support many eid(s) in map-request */

	int 
udp_request_get_eid(uint32_t id, struct prefix * pr)
{
	/* at this vesion, get the first eid in list */
	struct list_t * ll;
	struct list_entry_t * l;
	struct pk_req_entry * p;
	
	p = _pk_req_pool[id];
	
	if(!p->eid)
		return -1;
	
	ll = (struct list_t *)p->eid;	
	
	if(ll->count <=0)
		return -1;
	
	l = ll->head.next;
	memcpy(pr, l->data, sizeof(struct prefix));
	return (TRUE);
}

/* get nonce from map-request */
	int 
udp_request_get_nonce(uint32_t id, uint64_t * nonce)
{
	uint32_t * nonce_trick;
	nonce_trick = (uint32_t *)nonce;
	*nonce_trick = _pk_req_pool[id]->nonce0;
	*(nonce_trick+1) = _pk_req_pool[id]->nonce1;
	
	return (TRUE);
}

/* check if map-request is ddt bit set or not */
	int 
udp_request_is_ddt(uint32_t id, int * is_ddt)
{
	*is_ddt = _pk_req_pool[id]->ddt;
	return (TRUE);
}
	
/* get itr suit with afi, if afi = 0, choose the first in list */	
	int 
udp_request_get_itr(uint32_t id, union sockunion * itr, int afi)
{
	struct pk_req_entry * p;
	struct list_t	* ll;
	struct list_entry_t * l;
	union afi_address_generic * afi_address;
	int i = 0;
	
	p = _pk_req_pool[id];
	
	if(!p->itr)
		return -1;
	
	ll = (struct list_t *)p->itr;	
	if(ll->count <=0)
		return -1;
		
	l = p->itr->head.next;
	/* run over itr list to choose the first itr match with afi */
	while(l != &p->itr->tail){
		afi_address = (union afi_address_generic *)l->data;
		/* afi ==0 --> get the first itr */
		if(afi == ntohs(afi_address->ip.afi) || afi == 0){
			i++;
			switch(ntohs(afi_address->ip.afi)){
				case AF_INET:
					memcpy(&itr->sin.sin_addr,&afi_address->ip.address,sizeof(struct in_addr));
					itr->sin.sin_family = AF_INET;
					break;
				case AF_INET6:
					memcpy(&itr->sin6.sin6_addr,&afi_address->ip6.address,sizeof(struct in6_addr));
					itr->sin6.sin6_family = AF_INET6;
					break;
				default:
					fprintf(OUTPUT_STREAM,"AF not support\n");
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
udp_request_get_port(uint32_t id, uint16_t * port)
{
	union sockunion * si_other;
	if(_pk_req_pool[id]->emc)
		si_other = &(_pk_req_pool[id]->ih_si);
	else
		si_other = &(_pk_req_pool[id]->si);
	if( (si_other->sa).sa_family == AF_INET)
		*port = ntohs( (si_other->sin).sin_port);
	else
		*port = ntohs( (si_other->sin6).sin6_port);	
	return (TRUE);
}

/* generate checksum of message */
	ushort 
ip_checksum (unsigned short *buf, int nwords)
{
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/* make a new map-request message -	EMC package */
	int 
udp_request_add(uint32_t id, uint8_t security, uint8_t ddt,\
		uint8_t A, uint8_t M, uint8_t P, uint8_t S,\
		uint8_t p, uint8_t s,\
		uint32_t nonce0, uint32_t nonce1,\
		const union sockunion * src,\
		const union sockunion * dst,\
		uint16_t source_port,\
		const struct prefix * eid)
{
	size_t itr_size;
	size_t ip_len;

	/* the different parts of the packet */
	/* type 8 encapsulation part */
	struct lisp_control_hdr * lh;
	struct ip * ih;	/*set source and destination IPs */
	struct ip6_hdr *ih6;
	struct udphdr * udp /* dst port 4342 */;
	/* map request part */
	/* type 1 */
	struct map_request_hdr * lcm;
	union afi_address_generic * itr_rloc;
	union map_request_record_generic * rec;
	union afi_address_generic afi_addr_src, afi_addr_dst;
	uint32_t reply_id;
	
	reply_id = _get_pool_place((void *)_pk_rpl_pool,PK_POOL_MAX);
	_pk_rpl_pool[reply_id] = calloc(1, sizeof(struct pk_rpl_entry));
	_pk_rpl_pool[reply_id]->buf = calloc(PKMSIZE,sizeof(char));
	_pk_rpl_pool[reply_id]->curs = _pk_rpl_pool[reply_id]->buf;
	_pk_rpl_pool[reply_id]->buf_len = 0;
	_pk_rpl_pool[reply_id]->request_id = id;
	
	
	_sockunion_to_afi_address(src, &afi_addr_src);
	_sockunion_to_afi_address(dst, &afi_addr_dst);
		
	/* point to the correct place in the packet */
	lh = (struct lisp_control_hdr *)_pk_rpl_pool[reply_id]->buf;
	ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
	ih6 = (struct ip6_hdr *)CO(lh, sizeof(struct lisp_control_hdr));
	
	switch (eid->family){
		case AF_INET: 
			udp = (struct udphdr *)CO(ih, sizeof(struct ip));
			break;
		case AF_INET6:
			udp = (struct udphdr *)CO(ih, sizeof(struct ip6_hdr));
			break;
		default:
			fprintf(OUTPUT_STREAM, "AF not support, ignore \n");
			return -1;
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
	struct list_t * ll;
	struct list_entry_t * l;
	
	ll = _pk_req_pool[id]->itr;
	if(!ll)
		return -1;
	l = ll->head.next;
	while(l != &ll->tail){			
		memcpy(itr_rloc, l->data,sizeof(union afi_address_generic));
		if(ntohs(itr_rloc->ip.afi) == AF_INET)
			itr_rloc->ip.afi = htons(LISP_AFI_IP);
		else
			itr_rloc->ip6.afi = htons(LISP_AFI_IPV6)	;
		itr_size = _get_address_size(itr_rloc);
		itr_rloc = (union afi_address_generic *)CO(itr_rloc,itr_size);
		l = l->next;
	}
	rec = (union map_request_record_generic *)itr_rloc;
	
	/* assign correctly the EID prefix */
	switch(eid->family){
		case AF_INET:
			rec->record.eid_mask_len = eid->prefixlen;
			rec->record.eid_prefix_afi = htons(LISP_AFI_IP);
            memcpy(&rec->record.eid_prefix, &eid->u.prefix4, sizeof(struct in_addr));

			/* EID prefix is an IPv4 so 32 bits (4 bytes) */
			_pk_rpl_pool[reply_id]->curs = (void *)CO(rec, 4 + 4);
			break;
		case AF_INET6:
			rec->record6.eid_mask_len = eid->prefixlen;
			rec->record.eid_prefix_afi = htons(LISP_AFI_IPV6);
            memcpy(&rec->record6.eid_prefix, &eid->u.prefix6, sizeof(struct in6_addr));

			/* EID prefix is an IPv6 so 128 bits (16 bytes) */ 
			_pk_rpl_pool[reply_id]->curs = (void *)CO(rec, 4 + 16);
			break;
		default:
			printf("not supported\n");
			return (FALSE);
	}

	/* set the UDP parameters */
#ifdef BSD
	udp->uh_sport = htons(source_port);
	udp->uh_dport = htons(LISP_CP_PORT);
	udp->uh_ulen = htons((uint8_t *)_pk_rpl_pool[reply_id]->curs - (uint8_t *) udp);
	udp->uh_sum = 0;
#else
	udp->source = htons(source_port);
	udp->dest = htons(LISP_CP_PORT);
	udp->len = htons((uint8_t *) _pk_rpl_pool[reply_id]->curs - (uint8_t *) udp );
	udp->check = 0;
#endif

	/* setup the IP parameters */
	switch (eid->family){
		case AF_INET: 
			ip_len = (uint8_t *)_pk_rpl_pool[reply_id]->curs - (uint8_t *) ih;
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
			ih->ip_sum 		  = ip_checksum((unsigned short *)ih, ip_len);
			break;
		case AF_INET6:
			ip_len = (uint8_t *)_pk_rpl_pool[reply_id]->curs - (uint8_t *) udp;
			ih6->ip6_vfc	  = 0x6E; //version
			ih6->ip6_plen	  = htons(ip_len); //payload length
			ih6->ip6_nxt      = IPPROTO_UDP;//nex header
			ih6->ip6_hlim     = 64; //hop limit      
			memcpy(&ih6->ip6_src, &afi_addr_src.ip6.address, sizeof(struct in6_addr));
			memcpy(&ih6->ip6_dst, &afi_addr_dst.ip6.address, sizeof(struct in6_addr));
			break;
		default:
			fprintf(OUTPUT_STREAM, "AF not support, ignore \n");
			return -1;
	}	
		
	_pk_rpl_pool[reply_id]->buf_len = (char *)_pk_rpl_pool[reply_id]->curs - (char *)_pk_rpl_pool[reply_id]->buf;
	/* ================================= */
	fprintf(OUTPUT_STREAM, "Map-Request-Referral ");
	fprintf(OUTPUT_STREAM, " <");
	fprintf(OUTPUT_STREAM, "nonce=0x%x - 0x%x", nonce0, nonce1);
	fprintf(OUTPUT_STREAM, ">\n");
	/* ================================= */
	return reply_id;
}

	int 
udp_request_ddt_terminate(uint32_t id, const union sockunion * server, char terminal)
{
	union sockunion servaddr;
	int skt;
	socklen_t slen;
	
	bzero(&servaddr,sizeof(servaddr));
	memcpy(&servaddr,server, sizeof(servaddr));
	
	if( (server->sa).sa_family == AF_INET){
		(servaddr.sin).sin_port=ntohs(LISP_CP_PORT);
		if ((skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
			perror("socket");
			exit(0);
		}
		slen = sizeof(struct sockaddr_in);
	}else if((server->sa).sa_family == AF_INET6){
		(servaddr.sin6).sin6_port=ntohs(LISP_CP_PORT);
		if( (skt = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1){
			perror("socket");
			exit(0);
		}
		slen = sizeof(struct sockaddr_in6);
	}
	else
		return 0;
	/*=============================*/
	fprintf(OUTPUT_STREAM, "send Map-Request-Referral ");
	fprintf(OUTPUT_STREAM, "to %s:%d\n", 
			sk_get_ip(&servaddr, ip), sk_get_port(&servaddr) );
	fprintf(OUTPUT_STREAM, "Sending packet... ");
	/*=============================*/
	if(sendto(skt, _pk_rpl_pool[id]->buf, _pk_rpl_pool[id]->buf_len, 0, (struct sockaddr *)&(servaddr.sa),slen) < 0){
			fprintf(OUTPUT_STREAM, "failed\n");
			perror("sendto( )");
			_free_pool_place((void *)_pk_rpl_pool, id, _rm_rpl);
			close(skt);
			return (FALSE);
	}
	
	fprintf(OUTPUT_STREAM, "done\n");
	close(skt);
	if(terminal){
		_free_pool_place((void *)_pk_req_pool, _pk_rpl_pool[id]->request_id, _rm_req);
	}
	_free_pool_place((void *)_pk_rpl_pool, id, _rm_rpl);
	
	return (TRUE);		
}

/* ========================================================== */
/* forwarding package to outside network*/
	uint32_t 
_forward(uint32_t request_id)
{
	/*
	 * XXX dsa: DANGER RISK OF BUG
	 * => code duplication with uint32_t _request(const void *)
	 */
	struct lisp_control_hdr * lh;
	struct ip * ih;
	struct ip6_hdr *ih6;
	struct udphdr * udp;
	struct map_request_hdr * lcm;
	union sockunion sin;
	int one;
	int s;
	void * packet = _pk_req_pool[request_id]->buf;	
	union sockunion * si_other = &_pk_req_pool[request_id]->si;
	
	printf("Forwardig.....\n");
	lh = (struct lisp_control_hdr *)CO(packet, 0);
	/* Encapsulated Control Message Format => decap first */
	if(lh->type != LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE){
		fprintf(OUTPUT_STREAM, "Forwarding works only on Encapsulated Control Message mode\n");
		return (FALSE);
	}
	
	ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
	if (ih->ip_v == 4){
		ih = (struct ip *)CO(lh, sizeof(struct lisp_control_hdr));
		ih6	= NULL;
		udp = (struct udphdr *)CO(ih, sizeof(struct ip));
	}
	else {
		if (ih->ip_v == 6){
			ih		= NULL;
			ih6	= (struct ip6_hdr *) CO(lh, sizeof(struct lisp_control_hdr));
			udp	= (struct udphdr *) CO(ih6,  sizeof(struct ip6_hdr));
		}
		else{
			fprintf(OUTPUT_STREAM, "IP version not correct: Only support IPv4 and IPv6\n");
			return (0);
		}
	}	
	udp = (struct udphdr *)CO(ih, sizeof(struct ip));
	lcm = (struct map_request_hdr *)CO(udp, sizeof(struct udphdr));

	if(lcm->lisp_type != LISP_TYPE_MAP_REQUEST){
		fprintf(OUTPUT_STREAM, "Forwarding works only with Map-Request\n");
		return (FALSE);
	}

	bzero(&sin, sizeof(sin));
	if( (si_other->sa).sa_family == AF_INET){
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

	
	fprintf(OUTPUT_STREAM, "Sending packet...");                                                                                                                      
	if((s = socket (PF_INET, SOCK_RAW, IPPROTO_IP)) < 0){
		perror("socket");
		return (FALSE);
	}

	one = 1;
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0){
		perror("setsockopt");
		close(s);
		return (FALSE);
	}
	if(sendto(s,(void *)ih, (ih->ip_len), 0, (struct sockaddr *)&sin, sizeof (struct sockaddr)) < 0){
		perror("sendto");
		close(s);
		return (FALSE);
	}
	printf("done\n");
	close(s);


	return (TRUE);
}

/* forwarding to ETR */

	uint32_t 
_forward_to_etr(uint32_t request_id, struct db_node * rn)
{
	/*
	 * XXX dsa: DANGER RISK OF BUG
	 * => code duplication with uint32_t _request(const void *)
	 */
	struct lisp_control_hdr * lh;
	union sockunion sin;
	int skt = 0;
	int sin_len = 0;
	struct list_t * l = NULL;
	struct list_entry_t * _iter;
	struct map_entry * e = NULL;
	char ip[INET6_ADDRSTRLEN];
	void * packet = _pk_req_pool[request_id]->buf;	
	int pkt_len = _pk_req_pool[request_id]->buf_len;
	
	lh = (struct lisp_control_hdr *)CO(packet, 0);
	/* Encapsulated Control Message Format => decap first */
	if(lh->type != LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE){
		fprintf(OUTPUT_STREAM, "Forwarding works only on Encapsulated Control Message mode\n");
		return (FALSE);
	}
	lh->ddt_originated = 0;
	
	/*get first reachable ETR's rloc*/
	assert(rn);
	//show_eid_info((void *)rn);
	l = (struct list_t *)db_node_get_info(rn);
	assert(l);
	_iter = l->head.next;
	if(!_iter || _iter == &l->tail)
		return (0);
	
	while(_iter != &l->tail){
		e = (struct map_entry*)_iter->data;
		if(e->r)
			break;
		_iter = _iter->next;
	}

	if(_iter == &l->tail)
		return (0);
	
	switch(e->rloc.sa.sa_family){
		case AF_INET:
			sin.sin.sin_family = AF_INET;
			sin.sin.sin_port = ntohs(LISP_CP_PORT);
			memcpy(&(sin.sin.sin_addr), &(e->rloc.sin.sin_addr), sizeof(struct in_addr));
			inet_ntop(AF_INET, (void *)&(e->rloc.sin.sin_addr), ip, INET_ADDRSTRLEN);
			if ((skt = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
				perror("socket");
				exit(0);
			}
			//skt = skfd;
			sin_len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			sin.sin6.sin6_family = AF_INET6;
			sin.sin6.sin6_port = ntohs(LISP_CP_PORT);
			memcpy(&(sin.sin6.sin6_addr), &(e->rloc.sin6.sin6_addr), sizeof(struct in6_addr));
			inet_ntop(AF_INET6, (void *)&e->rloc.sin.sin_addr, ip, INET6_ADDRSTRLEN);
	
			//skt = skfd6;
			if( (skt = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1){
				perror("socket");
				exit(0);
			}
			
			sin_len = sizeof(struct sockaddr_in6);
			break;
		default:
			assert(FALSE);
	}	
	printf("Forwarding to %s\n",ip);
	if(sendto(skt,(void *)packet, pkt_len, 0, (struct sockaddr *)&sin.sa, sin_len) < 0){
		perror("sendto");
		close(skt);
		return (-1);
	}
	close(skt);
	printf("done\n");
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
	
	sprintf(_str_port, "%d", LISP_CP_PORT);
	
	//socket for bind ipv6
	if ((skfd6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1){
			perror("socket6");
			exit(0);
	}
		
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET6;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = IPPROTO_UDP;
	
	if ((e = getaddrinfo(listening_address[1], _str_port, &hints, &res)) != 0) {
			fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
			exit(0);
	}
		
	if (bind(skfd6, res->ai_addr, res->ai_addrlen) == -1){
			perror("bind");
			exit(0);
	}
	
	if( listening_address[1])	
		free(listening_address[1]);
	listening_address[1] = calloc(1,sizeof(struct in6_addr));
	memcpy(listening_address[1], &((struct sockaddr_in6 *)(res->ai_addr))->sin6_addr, sizeof(struct in6_addr));

	//socket for bind ipv4
	if ((skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
		perror("socket");
		exit(0);
	}
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = IPPROTO_UDP;
	
	if ((e = getaddrinfo(listening_address[0], _str_port, &hints, &res)) != 0) {
		fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(0);
	}
	
	if (bind(skfd, res->ai_addr, res->ai_addrlen) == -1){
		perror("bind");
		close(skfd);
		exit(0);
	}
	
	if( listening_address[0])	
		free(listening_address[0]);
	listening_address[0] = calloc(1,sizeof(struct in_addr));
	memcpy(listening_address[0], &((struct sockaddr_in *)(res->ai_addr))->sin_addr, sizeof(struct in_addr));
	
	return 1;
}

/* get message and push to queue */

	uint32_t 
udp_get_pk(int sockfd, socklen_t slen)
{
	
	int pk_len = 0;
	char buf[BUFLEN];
	union sockunion ssk; //source
	struct lisp_control_hdr * lh;
	struct map_request_hdr * lcm;
	struct ip * ih;
	struct ip6_hdr *ih6;
	struct udphdr * udph;
	uint32_t request_id;
	uint32_t hdr_len = 0;
	union sockunion * ih_si;
	struct pk_req_entry * p;
	
	/* wait for incoming packet */
	bzero(buf, BUFLEN);	
	if ( (pk_len = recvfrom(sockfd, buf, BUFLEN, 0, (struct sockaddr *)&(ssk.sa), &slen)) < 0){
		perror("recvfrom");
		return -1;
	}
	fprintf(OUTPUT_STREAM, "Received packet from  %s:%d\n", sk_get_ip(&ssk, ip) , sk_get_port(&ssk));	
	//get a free entry in pool
	
	if( (request_id = _get_pool_place( (void *)_pk_req_pool,PK_POOL_MAX) ) < 0)
		return -1;
		
	printf("request_id::%d\n",	request_id);
	p = _pk_req_pool[request_id] = calloc(1,sizeof(struct pk_req_entry));
	p->ttl = 0;
	p->hop = 0;
	p->itr = p->eid = NULL;	
	p->buf = calloc(pk_len+12,sizeof(char));
	bzero(p->buf,pk_len+12);
	memcpy((char *)p->buf, (char *)buf, pk_len);
	p->buf_len = pk_len;
	memcpy((char *)&p->si, (char *)&ssk, sizeof(ssk));
	
	//push package to pool
	lh = (struct lisp_control_hdr *)CO(p->buf, 0);
	if(lh->type == LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE){
		p->lh = lh;
		p->emc = 1;
		p->ddt = lh->ddt_originated;
		lh = (struct lisp_control_hdr *)CO(lh, sizeof(struct lisp_control_hdr));
		hdr_len += sizeof(struct lisp_control_hdr);
		
				//by pass UDP IH
		p->ih = ih = (struct ip *)lh;
		ih6 = (struct ip6_hdr *)lh;
		ih_si = (union sockunion *)&(p->ih_si);
		switch (ih->ip_v){
			case 4:
				p->udp = udph = (struct udphdr *)CO(lh,sizeof(struct ip));
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
				p->udp = udph = (struct udphdr *)CO(lh,sizeof(struct ip6_hdr));
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
				fprintf(OUTPUT_STREAM, "IP version not correct: Only support IPv4 and IPv6\n");
				return -1;
		}
			
		lh = (struct lisp_control_hdr *)CO(udph,sizeof(struct udphdr));			
	}
		
	switch (lh->type){
		case LISP_TYPE_MAP_REQUEST:
		case LISP_TYPE_MAP_REPLY:
		case LISP_TYPE_MAP_REGISTER:
		case LISP_TYPE_MAP_NOTIFY:
		case LISP_TYPE_MAP_REFERRAL:
			p->lcm = lcm = (struct map_request_hdr *)lh;
			p->type = lh->type;
			p->nonce_0 = &lcm->lisp_nonce0;
			p->nonce_0 = &lcm->lisp_nonce0;
			p->nonce0 = ntohl(lcm->lisp_nonce0);
			p->nonce1 = ntohl(lcm->lisp_nonce1);
			break;	
		default:
			fprintf(OUTPUT_STREAM, "unsupported LISP type\n");
			return -1;
	}
	
	return request_id;
}

/* fork a new thread to process with new message in queue */
	void *
_lisp_process(void *data)
{
	void * buf;
	int register_id;
	struct lisp_control_hdr * lh;
	union sockunion * si_other;
	int rt = 0;
	int pk_id = *(int *)data;	
	
	si_other = &_pk_req_pool[pk_id]->si;
	buf = _pk_req_pool[pk_id]->buf;
	
	lh = (struct lisp_control_hdr *)CO(buf, 0);
		
	/* action depends on the LISP type */				
	switch(lh->type){
		/* Map-Request or DDT Map-Request */
		case LISP_TYPE_MAP_NOTIFY:
			_free_pool_place((void *)_pk_req_pool, pk_id, _rm_req);
			//_xtr_notify(request_id);				
			break;
		case LISP_TYPE_MAP_REQUEST:
		case LISP_TYPE_ENCAPSULATED_CONTROL_MESSAGE:
			rt = _request(pk_id);
			if(rt <= 0){
				fprintf(OUTPUT_STREAM, "Not a map-request!\n");
				_free_pool_place((void *)_pk_req_pool, pk_id, _rm_req);
				break;
			}
			
			if(_fncs & _FNC_XTR)
				if(xtr_generic_process_request(pk_id, &udp_fct))
					break;
			
			if(!generic_process_request(pk_id, &udp_fct)){
				fprintf(OUTPUT_STREAM, "Forwarding mode\n");
				_forward(pk_id);
			}
			break;
		/* Map-Register */
		case LISP_TYPE_MAP_REGISTER:
			if(_fncs & _FNC_MS)
				register_id = _register(pk_id);
			else
				_free_pool_place((void *)_pk_req_pool, pk_id, _rm_req);
			break;
		/* Map-Referral */
		case LISP_TYPE_MAP_REFERRAL:
			if(_fncs & _FNC_NODE || _fncs & _FNC_MR)		
				rt = _referral(pk_id);
				//printf("rt = %d\n",rt);
				if(rt && _pk_req_pool[rt])
					generic_process_request(rt, &udp_fct);
				else
					_free_pool_place((void *)_pk_req_pool, pk_id, _rm_req);	
			break;
		/* Map-Reply */
		case LISP_TYPE_MAP_REPLY:
			_free_pool_place((void *)_pk_req_pool, pk_id, _rm_req);
		/* unsupported */
		default:
			_free_pool_place((void *)_pk_req_pool, pk_id, _rm_req);
			fprintf(OUTPUT_STREAM, "unsupported LISP type\n");			
	}
	pthread_exit(NULL); 
}
	

/* start control center */
	void * 
udp_start_communication(void * context)
{
	int nready;
	int sockfd = 0;
	uint32_t pk_id;
	socklen_t slen = 0;
	pthread_t _thr_map_register_process;
	int i;
	
	if(!udp_init_socket())
		exit(0);
	for(i = 0; i < PK_POOL_MAX; i++){
		_pk_req_pool[i] = NULL;
		_pk_rpl_pool[i] = NULL;
	}		
	/* infinite loop to listen packets comming */
	_sk[0].fd = skfd;
	_sk[1].fd = skfd6;
	_sk[0].events = POLLRDNORM;
	_sk[1].events = POLLRDNORM;
	
	/*map-register process thread*/
	if( _fncs & _FNC_XTR){
		pthread_create(&_thr_map_register_process, NULL, general_register_process, NULL);
	}	
	
	for (;;) {
		/* reset buffers */
		nready = poll(_sk, 2, INFTIM);
		if(nready <=0)
			continue;
		//check socket ready to read
		if( _sk[0].revents & POLLRDNORM){
			sockfd = _sk[0].fd;
			slen = sizeof(struct sockaddr_in);
		}else if( _sk[1].revents & POLLRDNORM){
			sockfd = _sk[1].fd;
			slen = sizeof(struct sockaddr_in6);
		}
		
		if( (pk_id = udp_get_pk(sockfd,slen)) < 0){
			fprintf(OUTPUT_STREAM, "can not get package\n");
			continue;
		}
		pthread_t _thr_lisp_process;
		pthread_create(&_thr_lisp_process, NULL, _lisp_process, (void *)&pk_id);		
	}
	pthread_join(_thr_map_register_process, NULL);
	return NULL;
}

/* stop control center */
	void * 
udp_stop_communication(void * context)
{
	fprintf(OUTPUT_STREAM, "bye\n");
	return (NULL);	
}


/*
 * Process Map-Request
 * @param Map-Request LISP Control Message 
 */
	uint32_t 
_request(uint32_t request_id)
{
	struct lisp_control_hdr * lh;
	struct map_request_hdr * lcm;
	union afi_address_generic * eid_source;
	union afi_address_generic * itr_rloc;		/* current ITR-RLOC */
	union map_request_record_generic * rec;		/* current record */
	int ret;
	struct prefix * eid_prefix;
	union afi_address_generic * itr_address;
	struct pk_req_entry * p;
	size_t eid_size;
	uint8_t icount;
	uint8_t rcount;
	char buf[512];
	
	p = _pk_req_pool[request_id];
	lh = (struct lisp_control_hdr *)p->lh;
	fprintf(OUTPUT_STREAM, "LH: <type=%u>\n", lh->type);
	
	/* Encapsulated Control Message Format => decap first */
	lcm = (struct map_request_hdr *)p->lcm;
	
	if(p->emc){
		fprintf(OUTPUT_STREAM, "Encapsulated Control Message mode <S=%u, D=%u>\n", lh->security_bit, lh->ddt_originated);
	}
	
	if(lcm->lisp_type != LISP_TYPE_MAP_REQUEST){
		fprintf(OUTPUT_STREAM, "only Map-Requests are supported\n");
		return (0);
	}
	
	/* parse LCM */
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
	fprintf(OUTPUT_STREAM, "Source EID: %s\n", buf);

	/* jump to the ITR address list */
	itr_rloc = (union afi_address_generic *)CO(eid_source, eid_size);
	p->itr = list_init();
	
	/* XXX dsa: DANGER RISK OF BUG 
	 * ==> ACTUAL NUMBER OF ITR-RLOCs is ( IRC + 1 )
	 */
	icount = lcm->irc + 1;
	/* Browse all the ITR-RLOC
	 * XXX dsa: at the end of the loop, itr_rloc point at the END of the last ITR-RLOC 
	 * 	    "INV": itr_rloc points to the rloc to process
	 */
	//get all ITR-RLOC
	while(icount--){
		itr_address = calloc(1,sizeof(union afi_address_generic));
		
		switch(_get_address_type(itr_rloc)){
			case LISP_AFI_IP:
				memcpy(&itr_address->ip.address, &itr_rloc->ip.address, sizeof(struct in_addr));
				itr_address->ip.afi = htons(AF_INET);
				break;
			case LISP_AFI_IPV6:
				memcpy(&itr_address->ip6.address, &itr_rloc->ip6.address, sizeof(struct in6_addr));
				itr_address->ip6.afi = htons(AF_INET6);
				break;
			default:
				printf("not supported (only IPv4 and IPv6)\n");
				return (-1);	
		}
		list_insert(p->itr,itr_address, NULL);
		_afi_address_str(itr_rloc, buf, 512);	
		fprintf(OUTPUT_STREAM, "ITR-RLOC: %s\n", buf);
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
	p->eid = list_init();	
	while(rcount--){
		bzero(buf, 512);
		eid_prefix = calloc(1,sizeof(struct prefix));

		switch(ntohs(rec->record.eid_prefix_afi)){
			case LISP_AFI_IP:
				eid_prefix->family = AF_INET;
				eid_prefix->u.prefix4 = rec->record.eid_prefix;

				inet_ntop(AF_INET, (void *)&rec->record.eid_prefix, buf, 512);
				break;
			case LISP_AFI_IPV6:
				eid_prefix->family = AF_INET6;
				eid_prefix->u.prefix6 = rec->record6.eid_prefix;

				inet_ntop(AF_INET6, (void *)&rec->record6.eid_prefix, buf, 512);
				break;
			default:
				return -1;				
		}
		eid_prefix->prefixlen = rec->record.eid_mask_len;

		fprintf(OUTPUT_STREAM, "EID prefix: %s/%u\n", buf, rec->record.eid_mask_len);
		list_insert(p->eid,eid_prefix, NULL);
		rec = (union map_request_record_generic *)CO(rec, _get_record_size(rec));
	}
	return (1);
}


/* Proces Map-referral */

	uint32_t 
_referral(uint32_t request_id)
{
	struct map_referral_hdr * lcm;
	union map_referral_record_generic * rec;		/* current record */
	size_t lcm_len;
	uint8_t rcount;
	size_t packet_len;
	size_t rlen = 0;
	union afi_address_generic best_rloc;
	void * packet = _pk_req_pool[request_id]->buf;
	struct prefix * pf;
	
	lcm = (struct map_referral_hdr *)CO(packet, 0);

	rcount = lcm->record_count;
	fprintf(OUTPUT_STREAM, "LCM: <type=%u, rcount=%u nonce=0x%x - 0x%x\n", \
			lcm->lisp_type, \
			rcount, \
			ntohl(lcm->lisp_nonce0), \
			ntohl(lcm->lisp_nonce1));

	lcm_len = sizeof(struct map_referral_hdr);
	packet_len = lcm_len;

	if(rcount == 0){
		fprintf(OUTPUT_STREAM, "NO RECORD\n");
		return (0);
	}
	
	uint64_t nonce;
	uint32_t * nonce0;
	uint32_t * nonce1;
	udp_request_get_nonce(request_id, &nonce);
	nonce0 = (uint32_t *)&nonce;
	nonce1 = (uint32_t *)(nonce0+1);
	int i = 1;
	
	/* lookup map-request match with map-referral */
	while( i < PK_POOL_MAX){
		if (i == request_id ||  !_pk_req_pool[i]){
			i++;
			continue;
		}
		
		if( (*nonce0 == _pk_req_pool[i]->nonce0) &&  (*nonce1 == _pk_req_pool[i]->nonce1)){
			break;
		} 
		i++;
	}
	
	/* if exist -> recur map-request */
	if( (i < PK_POOL_MAX) && (i != request_id) && _pk_req_pool[i]){
		
		/* check eid in map-refarral to avoid loop */
		
		rec = (union map_referral_record_generic *)CO(lcm, lcm_len);
		pf = calloc(1,sizeof(struct prefix));
		pf->family = rec->record.eid_prefix_afi;
		pf->prefixlen = rec->record.eid_mask_len;
		memcpy(&pf->u.prefix4,&rec->record.eid_prefix, SIN_LEN(pf->family));
		
		if(!_pk_req_prefix[i]){
			_pk_req_prefix[i] = pf;			
		}else{
			/* if loop, free map-request, return */
			if(!prefix_match(_pk_req_prefix[i],pf)){
				fprintf(OUTPUT_STREAM,"Error: Map-referral loop by compare EID\n");
				_free_pool_place((void *)_pk_req_pool, request_id, _rm_req);
				return 0;
			}
		}
				
		/* go to the first record */
		rec = (union map_referral_record_generic *)CO(lcm, lcm_len);
		/* ==================== RECORDs ========================= */
		rlen = 0;
		struct db_node *node;
		
		while(rcount--){
			bzero(&best_rloc, sizeof(union afi_address_generic));
			rlen = _process_referral_record(rec, &best_rloc, (struct db_node **)&node);
			//get MS-ACK
			if(rlen == 0){
				//printf("Receive MS_ACK\n");
				_free_pool_place((void *)_pk_req_pool, request_id, _rm_req);				
				return 0;
			}
			packet_len += rlen;
			rec = (union map_referral_record_generic *)CO(rec, rlen);
		}
			
		//This will be used for automatic iteration
		if(_get_address_type(&best_rloc) == LISP_AFI_IP){
			char buf[BSIZE];
			inet_ntop(AF_INET, (void *)&best_rloc.ip.address, buf, BSIZE);                             
			//printf("BEST RLOC %s\n", buf);
		}
	}
	else{
		i = 0;		
	}
	_free_pool_place((void *)_pk_req_pool, request_id, _rm_req);	
	return i;
}

size_t 
_process_referral_record(const union map_referral_record_generic * rec, union afi_address_generic * best_rloc, struct db_node ** node)
{
	size_t rlen;
	union map_referral_locator_generic * loc;
	char buf[BSIZE];
	size_t len;
	struct map_entry * entry;
	uint8_t lcount;
	struct prefix eid;
	struct mapping_flags mflags;
	void * mapping;
	uint8_t best_priority;

	rlen = 0;
	bzero(buf, BSIZE);
	*node  = mapping = NULL;
	/* this version only support lcaf type=2 */
	if(ntohs(rec->record.lcaf.afi) == LCAF_AFI){
		if(rec->record.lcaf.type !=2){
			fprintf(OUTPUT_STREAM,"Only support lcaf with type is 2\n");
			return 0;
		}
	}
	
	bzero(&eid, sizeof(struct prefix));
	//printf("afi::%d\n",ntohs(rec->record.eid_prefix_afi));
	switch(ntohs(rec->record.eid_prefix_afi)){
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
			fprintf(OUTPUT_STREAM, "unsuported family\n");
			return (-1);
	}
	eid.prefixlen = rec->record.eid_mask_len;

	lcount = rec->record.referral_count;
	bzero(&mflags, sizeof(struct mapping_flags));
	mflags.act = rec->record.act;
	mflags.A = rec->record.a;
	mflags.version = rec->record.version;
	mflags.incomplete = rec->record.i;
	mflags.ttl = ntohl(rec->record.ttl);
	mflags.referral = rec->record.act+1;
	mflags.iid = rec->record.lcaf.iid;

	if(rec->record.sig_cnt > 0){
		fprintf(OUTPUT_STREAM, "Signature not implemented\n");
	}

	/* to mapping table */
	/* add the locator to the table only incomplete is 0*/
	if(!mflags.incomplete){ 
	//switch(rec->record.act){
	//	case LISP_REFERRAL_NODE_REFERRAL:
	//	case LISP_REFERRAL_MS_REFERRAL:
			*node = mapping = generic_mapping_new(&eid);
			generic_mapping_set_flags(mapping, &mflags);
			ms_node_update_type(mapping,_MAPP);
	//		break;
	//	default:
	//		*node = mapping = NULL;
	}

	/* ====================================================== */
	fprintf(OUTPUT_STREAM, "EID %s/%d: ", buf, eid.prefixlen);

	fprintf(OUTPUT_STREAM, "<");
	fprintf(OUTPUT_STREAM, "ref_count=%u", lcount);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "TTL=%u", mflags.ttl);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "ACT=%d", mflags.act);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "version=%u", mflags.version);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "A=%u", mflags.A);

	fprintf(OUTPUT_STREAM, ", ");
	fprintf(OUTPUT_STREAM, "i=%u", mflags.incomplete);

	fprintf(OUTPUT_STREAM, ">\n");

	if(lcount == 0){
		fprintf(OUTPUT_STREAM, "\tNegative referral\n");
	}
	/* ====================================================== */

	size_t rhdr_len = _get_referral_record_size(rec);
	rlen += rhdr_len;
	loc = (union map_referral_locator_generic *)CO(rec, rhdr_len);

	/* ==================== RLOCs ========================= */
	best_priority = 0xff;
	while(lcount--){
		char buf[BSIZE];
		bzero(buf, BSIZE);

		entry = (struct map_entry *)calloc(1, sizeof(struct map_entry));

		/* get locator parameters  and address */
		entry->priority = loc->rloc.priority;
		entry->weight = loc->rloc.weight;
		entry->m_priority = loc->rloc.m_priority;
		entry->m_weight = loc->rloc.m_weight;
		entry->r = loc->rloc.R;
		switch(ntohs(loc->rloc.rloc_afi)){
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
				fprintf(OUTPUT_STREAM, "unsuported family\n");
				free(entry);
				return (-1);
		}
		if(mapping){
			generic_mapping_add_rloc(mapping, entry);
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

		/* determine if it is the best locator */
		if(best_rloc != NULL && entry->priority < best_priority){
			best_priority = entry->priority;
			memcpy(best_rloc, &loc->rloc.rloc_afi, \
					(ntohs(loc->rloc.rloc_afi) == LISP_AFI_IP)?sizeof(struct afi_address):\
					(ntohs(loc->rloc.rloc_afi) == LISP_AFI_IPV6?sizeof(struct afi_address6):0));

		}

		loc = (union map_referral_locator_generic *)CO(loc, len);
		rlen += len;
		if(!mapping){
			free(entry);
		}
	}
	if(mflags.act == LISP_REFERRAL_MS_ACK)
		return 0;
		
	return (rlen);
}

/* Map-notify */
	int
_register_notify(uint32_t request_id)
{
	
	struct pk_req_entry * p;
	union sockunion ds;
	void * buf;
	size_t pklen;
	struct map_register_hdr * lcm;
	size_t slen;
	int skt;
	
	/* content of map-notify same as map-register */
	p = _pk_req_pool[request_id];
	buf = calloc(p->buf_len, sizeof(char));
	memcpy(buf,p->buf,p->buf_len);
	lcm = p->lcm;
	lcm->lisp_type = LISP_TYPE_MAP_NOTIFY;
	memcpy(&ds, &p->si, sizeof(union sockunion));
	sk_set_port(&ds,LISP_CP_PORT);
	pklen = p->buf_len;
	
	
	fprintf(OUTPUT_STREAM, "send Map-Notify ");
	fprintf(OUTPUT_STREAM, "to %s:%d\n", 
				sk_get_ip(&ds, ip), sk_get_port(&ds) );
	fprintf(OUTPUT_STREAM, "Sending packet... ");
	
	/* select socket for ds */
	
	switch( (ds.sa).sa_family ){
		case AF_INET:
			skt = skfd;
			slen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			skt = skfd6;
			slen = sizeof(struct sockaddr_in6);
			break;
		default:	
			fprintf(OUTPUT_STREAM,"ETR address not correct::AF_NOT_SUPPORT\n");
			return -1;
	}
		
	if(sendto(skt, (char *)buf, pklen, 0, (struct sockaddr *)&(ds.sa), slen) == -1){
			fprintf(OUTPUT_STREAM, "failed\n");
			perror("sendto( )");
			free(buf);
			return (-1);
		}
	fprintf(OUTPUT_STREAM, "done\n");
	return (TRUE);	
}


/* Process Map-Register */

	uint32_t 
_register(uint32_t request_id)
{
	struct map_register_hdr * lcm;
	union map_reply_record_generic * rec;		/* current record */
	size_t lcm_len;
	uint8_t rcount;
	size_t packet_len;
	struct list_entry_t * site;
	int proxy_flg;
	void * packet = _pk_req_pool[request_id]->buf;	
	int rt;
	
	lcm = (struct map_register_hdr *)CO(packet, 0);
	rcount = lcm->record_count;
	//list_db(table);
	fprintf(OUTPUT_STREAM, "LCM: <type=%u, P=%u, rcount=%u, nonce=0x%x - 0x%x, key id=%u, auth data length=%u\n", \
			lcm->lisp_type,
			lcm->proxy_map_reply, \
			rcount, \
			ntohl(lcm->lisp_nonce0), \
			ntohl(lcm->lisp_nonce1), \
			ntohs(lcm->key_id), \
			ntohs(lcm->auth_data_length));

	lcm_len = sizeof(struct map_register_hdr) + ntohs(lcm->auth_data_length);
	packet_len = lcm_len;
	
	if ( (rt = _ms_validate_register(ms_db, packet, (void *)&site)) >=0 )
	{
		/* update */
		if(rt){
			fprintf(OUTPUT_STREAM, "Map-register:: Valide - OK\n");
			
			//cleare mapping of site in database
			fprintf(OUTPUT_STREAM, "Map-register:: Preparing to update database\n");
			_ms_clean_site_mapping(site);
			
			//add new mapping to database
			rec = (union map_reply_record_generic *)CO(lcm, lcm_len);
			proxy_flg = lcm->proxy_map_reply;
			/* ==================== RECORDs ========================= */
			size_t rlen = 0;
			while(rcount--){
				rlen = _ms_process_register_record(ms_db, site, rec, proxy_flg);
				packet_len += rlen;
				rec = (union map_reply_record_generic *)CO(rec, rlen);
			}
			fprintf(OUTPUT_STREAM, "Map-register:: Update......Success\n");
			
			fprintf(OUTPUT_STREAM, "Map-register:: Finish update database\n");
		}		
		/* Send map-notify if required */
		if(lcm->want_map_notify)
			_register_notify(request_id);
		return 1;
	}
	return 0;
}

	size_t 
_process_register_record(const union map_reply_record_generic * rec)
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

	rlen = 0;
	bzero(buf, BSIZE);
	mapping = NULL;

	bzero(&eid, sizeof(struct prefix));
	switch(ntohs(rec->record.eid_prefix_afi)){
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
	mflags.referral = 0;

	/* add entry to mapping table */
	mapping = generic_mapping_new(&eid);
	generic_mapping_set_flags(mapping, &mflags);
	ms_node_update_type(mapping,_MAPP);
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

	if(lcount == 0){
		fprintf(OUTPUT_STREAM, "\tNegative reply\n");
	}
	/* ====================================================== */

	size_t rhdr_len = _get_reply_record_size(rec);
	rlen += rhdr_len;
	loc = (union map_reply_locator_generic *)CO(rec, rhdr_len);

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
		generic_mapping_add_rloc(mapping, entry);

		loc = (union map_reply_locator_generic *)CO(loc, len);
		rlen += len;
	}

	return (rlen);
}

/* Cal hashing of package */
	void * 
_ms_recal_hashing(const void *packet, int pk_len, void * key, void *rt, int no_nonce)
{
	
    void * packet2;
	struct map_register_hdr * map_register;
    HMAC_SHA1_CTX	ctx;
	unsigned char	buf[BUFLEN];    	  	    
	u_char auth_len;
	int i;
	
	//hexout(packet,pk_len);
	
	packet2 = calloc(pk_len,sizeof(char));
	memcpy(packet2, packet, pk_len);
	map_register = (struct map_register_hdr *)packet2;				
	auth_len = ntohs(map_register->auth_data_length);
	for (i = 0; i < auth_len; i++){
		map_register->auth_data[i]=0;
	}
	
	if(no_nonce){
		//ignore when hashing
		memset((char *)&map_register->lisp_nonce0,0,4);
		memset((char *)&map_register->lisp_nonce1,0,4);
		//map_register->lisp_nonce1 = 0;		
	}
	
	// Calculate Hash and fill in Authentication Data field
	HMAC_SHA1_Init(&ctx);
	HMAC_SHA1_UpdateKey(&ctx, key, strlen((char *)key) );
	HMAC_SHA1_EndKey(&ctx);
	HMAC_SHA1_StartMessage(&ctx);
	HMAC_SHA1_UpdateMessage(&ctx, packet2,pk_len);
	HMAC_SHA1_EndMessage(buf, &ctx);

	char hex_output[auth_len*2+1];
	for (i = 0; i < auth_len; i++){
		sprintf(hex_output + i * 2, "%02x", buf[i]);
		map_register->auth_data[i]=buf[i];
	}
	memcpy((char *)rt, (char *)map_register->auth_data, auth_len);	
	return (map_register->auth_data);
}


/* Check validate of one eid */

	struct list_entry_t *  
_ms_validate_eid(struct lisp_db *lisp_db, const union map_reply_record_generic * rec,  size_t * rlen)
{
	union map_reply_locator_generic * loc;
	size_t len;
	uint8_t lcount;
	struct prefix eid;
	struct db_table * db;
	struct db_node *node;
	struct list_entry_t *n_ex_info;
	
	//get EID-prefix
	*rlen = 0;	
	bzero(&eid, sizeof(struct prefix));
	switch(ntohs(rec->record.eid_prefix_afi)){
		case LISP_AFI_IP:
			eid.family = AF_INET;
			eid.u.prefix4 = rec->record.eid_prefix;
			break;
		case LISP_AFI_IPV6:
			eid.family = AF_INET6;
			eid.u.prefix6 = rec->record6.eid_prefix;
			break;
		default:			
			fprintf(OUTPUT_STREAM, "unsuported family\n");
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
	while(lcount--){
		switch(ntohs(loc->rloc.rloc_afi)){
			case LISP_AFI_IP:
				len = sizeof(struct map_reply_locator);
				break;
			case LISP_AFI_IPV6:
				len = sizeof(struct map_reply_locator6);
				break;
			default:
				fprintf(OUTPUT_STREAM, "unsuported family\n");
				return (0);
		}
		
		loc = (union map_reply_locator_generic *)CO(loc, len);
		*rlen += len;		
	}
	
	
	//Check EID-prefix, must: belong to one active site
	db = ms_get_db_table(lisp_db,&eid);
	node = db_node_match_prefix(db,&eid);
	
	if (node)
	{
		while(node != db->top)
		{
			if (ms_node_is_type(node,_EID))
				break;		
			node = node->parent;			
		}	
		
		//atleast eid match with root 0/0
		if (node == db->top)
		{
			fprintf(OUTPUT_STREAM, "EID::%s:: not in registed range\n",(char *)prefix2str(&eid) );
			return NULL;
		}
		else
		{
			n_ex_info = ((struct mapping_flags *)node->flags)->rsvd;
			show_site_info(n_ex_info->data);
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
_ms_validate_register(struct lisp_db * db, const void * packet, void **site_ptr)
{
	struct map_register_hdr * lcm;
	union map_reply_record_generic * rec;		/* current record */
	size_t lcm_len;
	uint8_t rcount;
	size_t packet_len, auth_len;
	void * pt;
	size_t rlen = 0;
	void * site = NULL;
	struct site_info * s_info;
	void * s_hashing;
	void * s_hmac;
	void * info_hashing;
	void * info_hmac;
	
	lcm = (struct map_register_hdr *)CO(packet, 0);
	rcount = lcm->record_count;
	auth_len = ntohs(lcm->auth_data_length);
	lcm_len = sizeof(struct map_register_hdr);
	
	fprintf(OUTPUT_STREAM, "Map-register: Validate processing....\n");
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
		
	while(rcount--){
		
		pt = _ms_validate_eid(db, rec, &rlen);
		if (pt == NULL){
			//fprintf(OUTPUT_STREAM, "Map-register: One of eid not in allowed range\n");
			return -1;			
		}
		
		if ( (site != NULL) && (site != pt) )
		{
			fprintf(OUTPUT_STREAM, "Map-register: All eid not belong to same site\n");
			return -1;			
		}
		site = pt;
		packet_len += rlen;
		rec = (union map_reply_record_generic *)CO(rec, rlen);		
	}
	
	fprintf(OUTPUT_STREAM, "Map-register: Compare with stored hashing..........\n");
	
	//printf("Checking stored hashing.......\n");
	/* ============================================= */
	//check if need update or not by compare stored hasing and package's hashing
	s_info = (struct site_info *)((struct list_entry_t *)site)->data;
	//show_site_info(s_info);
	info_hashing = s_info->hashing;
	s_hashing = calloc(auth_len, sizeof(char));
	_ms_recal_hashing( packet, packet_len, s_info->key, s_hashing, 1);
	
	//if(info_hashing)	
	//	hexout(info_hashing,auth_len);
	//hexout(s_hashing,auth_len);
	//hexout(packet,packet_len);
	
	if ( (info_hashing != NULL) && (strncmp((char *)info_hashing,(char *)s_hashing,auth_len) == 0) )
	{
		fprintf(OUTPUT_STREAM, "Map-register: Not need update\n");
		fprintf(OUTPUT_STREAM, "Map-register:: Finish update database\n");
			return 0;		
	}
	
	fprintf(OUTPUT_STREAM, "Map-register: Authenticate processing........\n");
	/* ============================================= */
	//check again hashing
	s_hmac = calloc(auth_len, sizeof(char));
	_ms_recal_hashing( packet, packet_len, s_info->key, s_hmac, 0);
	
	if ( strncmp((char *)info_hmac, (char *)s_hmac,auth_len) != 0)
	{
		fprintf(OUTPUT_STREAM, "Map-register: Authentication not success....., ignore package\n");
		return -1;
	}
	
	//update site information: hashing, TTL..
	free(info_hashing);
	info_hashing = s_info->hashing = calloc(auth_len, sizeof(char));
	memcpy((char *)info_hashing, (char *)s_hashing,auth_len );
	
	*site_ptr = site;
	return (1);
}

/* Delete an old mapping */

	void 
_ms_clean_eid_mapping(struct db_node * node)
{
	struct db_node * tmp_node;
	assert(node);
	node->parent = NULL;
	
	while (node)
	{
		if (node->l_left)
		{
			node = node->l_left;
			continue;
		}

		if (node->l_right)
		{
			node = node->l_right;
			continue;
		}

		tmp_node = node;
		node = node->parent;

		if (node != NULL)
		{
			if (node->l_left == tmp_node)
				node->l_left = NULL;
			else
				node->l_right = NULL;

			ms_free_node(tmp_node);
		}
		else
		{
			ms_free_node (tmp_node);
			break;
		}
	}

	
	
}

/* Delete mapping of site */

	void 
_ms_clean_site_mapping(struct list_entry_t * site)
{
	struct list_t * eid_l;
	struct list_entry_t *cur;
	struct db_node * node;
	uint8_t range;
	void * rsvd;
	
	assert(site);
	eid_l = ((struct site_info *)site->data)->eid;
	cur = eid_l->head.next;
	show_site_info((struct site_info *)site->data);
	while (cur != &(eid_l->tail))
	{
		node = (struct db_node *)cur->data;
		
		if(node->l_left){
			_ms_clean_eid_mapping(node->l_left);
			node->l_left = NULL;
		}
		if(node->l_right){
			_ms_clean_eid_mapping(node->l_right);	
			node->l_right = NULL;
		}
		db_node_set_info(node,NULL);
		if(node->flags){
			range = ((struct mapping_flags *)node->flags)->range;
			rsvd = ((struct mapping_flags *)node->flags)->rsvd;
			bzero(node->flags,sizeof(struct mapping_flags));
			if(range > _MAPP)
				range = range & ~_MAPP;
				
			((struct mapping_flags *)node->flags)->range = range;	
			((struct mapping_flags *)node->flags)->rsvd = rsvd;	
		}
		else
			node->flags = NULL;
		cur = cur->next;
	}
}

/* Create a new mapping */

	void * 
_ms_generic_mapping_new(struct db_table * tb, struct prefix * eid)
{
	struct db_node * rn;
	struct list_t * locs;
	
	rn = db_node_get(tb, eid);
	if(!rn){
		return (NULL);
	}
	
	ms_node_update_type(rn, _MAPP);
	locs = list_init();
	db_node_set_info(rn, locs);

	return ((void *)rn);
}

/* Update a mapping */

	size_t 
_ms_process_register_record(struct lisp_db * db, struct list_entry_t * site, 
									const union map_reply_record_generic * rec, uint8_t proxy_map_repl)
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
	struct db_table * tb;
	
	rlen = 0;
	bzero(buf, BSIZE);
	mapping = NULL;

	bzero(&eid, sizeof(struct prefix));
	switch(ntohs(rec->record.eid_prefix_afi)){
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
			fprintf(OUTPUT_STREAM, "unsuported family\n");
			return (0);
	}
	eid.prefixlen = rec->record.eid_mask_len;
	tb = ms_get_db_table(db,&eid);
	
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

	if(lcount == 0){
		fprintf(OUTPUT_STREAM, "\tNegative reply\n");
	}
	/* ====================================================== */

	size_t rhdr_len = _get_reply_record_size(rec);
	rlen += rhdr_len;
	loc = (union map_reply_locator_generic *)CO(rec, rhdr_len);

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
		generic_mapping_add_rloc(mapping, entry);

		loc = (union map_reply_locator_generic *)CO(loc, len);
		rlen += len;
	}

	return (rlen);
}

/* Map-register process thread */

	void * 
general_register_process(void * data)
{
	uint32_t register_id;
	struct list_entry_t * ptr;
	struct db_node * node;
	struct ms_entry * ms;
	struct mapping_flags *mflags;
	struct map_register_hdr * hr;
	int i;
	HMAC_SHA1_CTX	ctx;
	unsigned char	buf[BUFLEN];
	struct map_entry * e = NULL;
	struct list_entry_t * _iter;
	struct list_t * l = NULL;
	u_char pkbuf[PKMSIZE];
	uint64_t	nonce;
	uint32_t	* nonce_trick;
	struct list_t * wntfy;
	int count;
	wntfy = list_init();
	
	count = 0;
	for (; ;){
		
		while( (register_id = udp_register_add(0)) < 0){
			sleep(1);
			continue;
		}
				
		//add mapping to map-register package
		ptr = etr_db->head.next;
		while(ptr != &etr_db->tail){
			node = (struct db_node *)ptr->data;
			mflags = node->flags;			
			l = (struct list_t *)db_node_get_info(node);
			assert(l);
			_iter = l->head.next;
			
			if(!_iter){
				ptr = ptr->next;
				continue;				
			}
						
			udp_register_add_record(register_id, &node->p, mflags->ttl, l->count, mflags->version, mflags->A, mflags->act);
			if(_iter == &l->tail){
				ptr = ptr->next;
				continue;
			}

			while(_iter != &l->tail){
				e = (struct map_entry*)_iter->data;
				udp_register_add_locator(register_id, e);
				_iter = _iter->next;
			}
			ptr = ptr->next;
		}	
		
		//for each ms, make new nonce, cal authen data and send
		
		ptr = xtr_ms->head.next;
		hr = (struct map_register_hdr *)_pk_rpl_pool[register_id]->buf;
		hr->key_id = htons(01);
		hr->auth_data_length = htons(20);
		if(!(count %15)){
			hr->want_map_notify = 1;
			count = 0;
		}
		count++;
		
		ptr = xtr_ms->head.next;
		while(ptr != &xtr_ms->tail){
			ms = (struct ms_entry *)ptr->data;
			
			/*Calc auth data */
			for (i = 0; i < 20; i++)
				hr->auth_data[i]=0;
			
			_make_nonce(&nonce);
			nonce_trick = (uint32_t *)&nonce;
			hr->lisp_nonce0 = htonl((*nonce_trick));
			hr->lisp_nonce1 = htonl((*(nonce_trick + 1)));
			
			memcpy(pkbuf, _pk_rpl_pool[register_id]->buf,_pk_rpl_pool[register_id]->buf_len);
			HMAC_SHA1_Init(&ctx);
			HMAC_SHA1_UpdateKey(&ctx, (unsigned char *)ms->key, strlen((char *)ms->key));
			HMAC_SHA1_EndKey(&ctx);
			HMAC_SHA1_StartMessage(&ctx);
			HMAC_SHA1_UpdateMessage(&ctx, pkbuf,_pk_rpl_pool[register_id]->buf_len);
			HMAC_SHA1_EndMessage(buf, &ctx);
			for (i = 0; i < 20; i++){
				hr->auth_data[i]=buf[i];
			}
			
			/* ================================= */
			fprintf(OUTPUT_STREAM, "Map-Register ");
			fprintf(OUTPUT_STREAM, " <");
			fprintf(OUTPUT_STREAM, "nonce=0x%x - 0x%x", ntohl(hr->lisp_nonce0), ntohl(hr->lisp_nonce1));
			fprintf(OUTPUT_STREAM, ">\n");
			/* ================================= */
			
			/*Send */
			udp_register_terminate(register_id, (union sockunion *) ms);
			ptr = ptr->next;
		}
		
		//wake up each 1 minute to send map-register
		_free_pool_place((void *)_pk_rpl_pool, register_id, _rm_rpl);
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
sk_get_ip(union sockunion * sk, char * ip)
{
	int afi;
	
	afi = (sk->sa).sa_family;
	if( afi == AF_INET){
		inet_ntop( afi, &(sk->sin).sin_addr,ip,INET_ADDRSTRLEN);
	}
	else if (afi == AF_INET6){
		inet_ntop(afi, &(sk->sin6).sin6_addr,ip,INET6_ADDRSTRLEN);
	}else{
		printf("Type not support\n");
		return NULL;
	}
	return ip;
}

/* get ip of sockunion */
	int 
sk_get_port(union sockunion * sk)
{
	int afi;
	
	afi = (sk->sa).sa_family;
	if( afi == AF_INET){
		return ntohs((sk->sin).sin_port);
	}
	else if (afi == AF_INET6){
		return ntohs((sk->sin6).sin6_port);
	}else{
		printf("Type not support\n");
	}
	return 0;
}

/* set ip of sockunion */
	void 
sk_set_ip(union sockunion * sk, char * ip)
{
	
}

/* set port of sockunion */
	void 
sk_set_port(union sockunion * sk, int port){
	int afi;
	
	afi = (sk->sa).sa_family;
	if( afi == AF_INET){
		(sk->sin).sin_port = htons(port);
	}
	else if (afi == AF_INET6){
		(sk->sin6).sin6_port = htons(port);
	}else{
		printf("Type not support\n");
	}	
}

/* general free function */
	int 
_destroy_fct(void * data)
{
	free(data);
	return 1;
}
