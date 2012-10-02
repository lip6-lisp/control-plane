#include <stdio.h>

//
//Add a mapping to database of Openlisp
//


int add_eid(int s, void *params, int db){//db = 1:database, db=0:cache
	
	struct eid_rloc_db * data_ptr = params;
	struct openlisp_mapmsg m_mapmsg;
	struct rloc_mtx rloc_mtx;
	int pkt_len, rlen;
	char *ptr;
	struct addrinfo *res;
	struct rloc_db * rloc = data_ptr->rloc;
	int t_len;
	
	if (data_ptr == NULL) {
		return -1;	
	}
	memset(&m_mapmsg,0,8192+sizeof(struct map_msghdr));
	m_mapmsg.m_map.map_version = MAPM_VERSION;
	m_mapmsg.m_map.map_type =  MAPM_ADD;      
	m_mapmsg.m_map.map_flags = (db == 1? MAPF_DB: 0) | MAPF_STATIC | MAPF_UP; 
	m_mapmsg.m_map.map_addrs = MAPA_EID | ( (rloc != NULL)?MAPA_RLOC:0);
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
	int mask_max = (data_ptr->ed_ip.ss_family == AF_INET)?32:128;
	//Not include MAPA_EIDMASK if subnetmask is default, 32 for ipv4 and 128 for ipv6
	if( (data_ptr->eidlen > 0) && (mask_max > data_ptr->eidlen) ){
		mask2ip(data_ptr->eidlen, data_ptr->ed_ip.ss_family,&res); 
		memcpy(ptr, res->ai_addr, t_len);
		ptr = CO(ptr, t_len);
		pkt_len += t_len;
		m_mapmsg.m_map.map_addrs |= MAPA_EIDMASK;
	}
	m_mapmsg.m_map.map_rloc_count = 0;

	//include rloc 
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
	//send to openlisp database
	if ((rlen = write(s, (char *)&m_mapmsg, pkt_len)) < 0) {
		if (errno == EPERM)
			err(1, "writing to mapping socket");
		warn("writing to mapping socket");
		return -1;
	}
}

//
//Delete a mapping from Openlisp database
//

int del_eid2(int s, void *params, int db){//db: for future
	
	struct eid_rloc_db * data_ptr = params;
	struct openlisp_mapmsg m_mapmsg;

	char *ptr;
	struct addrinfo *res;
	int t_len,pkt_len, rlen;
	
	if (data_ptr == NULL) {
		return -1;
	}
	m_mapmsg.m_map.map_version = MAPM_VERSION;
	m_mapmsg.m_map.map_type =  MAPM_DELETE;
	m_mapmsg.m_map.map_addrs = MAPA_EID;
	m_mapmsg.m_map.map_pid = getpid();
	
	ptr = m_mapmsg.m_space;
	memset(ptr,0,8192);
	m_mapmsg.m_map.map_seq = ++seq;

	pkt_len = sizeof(struct	map_msghdr);
	t_len =  SA_LEN(data_ptr->ed_ip.ss_family);
		
	memcpy(ptr, &(data_ptr->ed_ip), t_len);
	ptr = CO(ptr, t_len);
	pkt_len += t_len;
	int mask_max = (data_ptr->ed_ip.ss_family == AF_INET)?32:128;
	//Not include MAPA_EIDMAKS if subnetmask = 32(ip4) or 128(ipv6)
	if( (data_ptr->eidlen > 0) && (mask_max > data_ptr->eidlen) ){
	mask2ip(data_ptr->eidlen, data_ptr->ed_ip.ss_family,&res); 
	memcpy(ptr, res->ai_addr, t_len);
	ptr = CO(ptr, t_len);
	pkt_len += t_len;
		m_mapmsg.m_map.map_addrs |= MAPA_EIDMASK;
	}

	m_mapmsg.m_map.map_rloc_count = 0;	
	m_mapmsg.m_map.map_msglen = pkt_len;	
	if ((rlen = write(s, (char *)&m_mapmsg, pkt_len)) < 0) {
		if (errno == EPERM)
			err(1, "writing to mapping socket");
		warn("writing to mapping socket");
		return -1;
	};
}

//
//Find a mapping from Openlisp database
//

int get_eid(int s, struct eid_rloc_db *params, struct  eid_rloc_db *rs){
	
	struct eid_rloc_db * data_ptr = params;
	struct openlisp_mapmsg m_mapmsg;
	struct rloc_db *rloc;
	int rn;

	void *ptr;
	struct addrinfo *res;
	int t_len,pkt_len, rlen;
	int cseq;
	int pid;
	int afi;
	int max_masklen;

	uint16_t  map_addrs;
	ptr = &m_mapmsg;
	memset(ptr,0,8192+sizeof(struct map_msghdr));
	
	if (data_ptr == NULL) {
		return -1;
	}
	//build map_msghdr
	m_mapmsg.m_map.map_version = MAPM_VERSION;
	m_mapmsg.m_map.map_type =  MAPM_GET;      
	m_mapmsg.m_map.map_addrs = MAPF_ALL | MAPA_EID;
	m_mapmsg.m_map.map_pid = pid = getpid();
	m_mapmsg.m_map.map_seq = cseq = ++seq;
	m_mapmsg.m_map.map_rloc_count = 0;
	
	ptr = m_mapmsg.m_space;
	pkt_len = sizeof(struct	map_msghdr);
	t_len =  SA_LEN(data_ptr->ed_ip.ss_family);

	data_ptr->ed_ip.ss_len = t_len;
	memcpy(ptr, &(data_ptr->ed_ip), t_len);
	ptr = CO(ptr, t_len);
	pkt_len += t_len;

	//Not include MAPA_EIDMASK if subnetmask is default (32 for ipv4 and 128 for ipv6)
	max_masklen = (data_ptr->ed_ip.ss_family == AF_INET)? 32:128;
	if ( (data_ptr->eidlen > 0) && (data_ptr->eidlen < max_masklen) ) {
		mask2ip(data_ptr->eidlen, data_ptr->ed_ip.ss_family,&res);
		((struct sockaddr_storage *)(res->ai_addr))->ss_len = t_len;
		memcpy(ptr, res->ai_addr, t_len);
		ptr = CO(ptr, t_len);
		pkt_len += t_len;
		m_mapmsg.m_map.map_addrs |= MAPA_EIDMASK;
	}
	
	m_mapmsg.m_map.map_msglen = pkt_len;
	
	//send to mapping socket
	hexout((char *)&m_mapmsg,pkt_len);

	if ((rlen = write(s, (char *)&m_mapmsg, pkt_len)) < 0) {
		if (errno == EPERM)
			err(1, "writing to mapping socket");
		warn("writing to mapping socket");
		return -1;
	};

	//wait for return from mapping soket
	do {
		rlen = read(s, (char *)&m_mapmsg, sizeof(m_mapmsg));
	} while (rlen > 0 && (m_mapmsg.m_map.map_seq != cseq || m_mapmsg.m_map.map_pid != pid));
	
	//get result
	if (rlen < 0){
		err("read from mapping socket");
		res = NULL;
		return -1;
	}

	data_ptr = rs;
	hexout((char *)&m_mapmsg,m_mapmsg.m_map.map_msglen);
	ptr = (char *)m_mapmsg.m_space;
	//EID exist or not
	if (m_mapmsg.m_map.map_flags & MAPF_DONE <=0) {
		return -1;
	}

	map_addrs = m_mapmsg.m_map.map_addrs;
	//get EID 
	if ( (map_addrs & MAPA_EID) > 0 ) {
		memcpy(&data_ptr->ed_ip, ptr, SA_LEN(((struct sockaddr_storage *)ptr)->ss_family));
		ptr = CO(ptr, ((struct sockaddr_storage *)ptr)->ss_len);
	}
	//get EID-masklen if exist
	if ( (map_addrs & MAPA_EIDMASK ) > 0) {
		if ( ((struct sockaddr_storage *)ptr)->ss_family == AF_INET)
			data_ptr->eidlen = net2mask(AF_INET,(char *)&(((struct sockaddr_in *)ptr)->sin_addr)); 			
		else
			data_ptr->eidlen = net2mask(AF_INET6,(char *)&(((struct sockaddr_in6 *)ptr)->sin6_addr)); 			
		
		ptr = CO(ptr,((struct sockaddr_storage *)ptr)->ss_len );
	}else
		data_ptr->eidlen = ( ((struct sockaddr_storage *)ptr)->ss_family == AF_INET)?32:128;

	//get Rloc if exist
	data_ptr->rloc = NULL;
	if ( (map_addrs & MAPA_RLOC ) > 0) {
		for (rn = 0; rn < m_mapmsg.m_map.map_rloc_count ; rn++) {
			if (rn == 0) {
				rloc = malloc(sizeof(struct rloc_db));
				data_ptr->rloc = rloc;
			}
			else{
				rloc->rl_next = malloc(sizeof(struct rloc_db));
				rloc = rloc->rl_next;
			}
			rloc->rl_next = NULL;
			memcpy(&rloc->rl_ip, ptr, ((struct sockaddr_storage *)ptr)->ss_len);
			ptr = CO(ptr,((struct sockaddr_storage *)ptr)->ss_len);
			rloc->priority = ((struct rloc_mtx *)ptr)->priority;
			rloc->weight = ((struct rloc_mtx *)ptr)->weight;
			rloc->local = ((struct rloc_mtx *)ptr)->flags;
			ptr = CO(ptr,sizeof(struct rloc_mtx)); 
		}
	}
}

//
//update db
//
int update_eid2(int s, struct eid_rloc_db *params){
	
	del_eid2(s,params,0);
	add_eid2(s,params,0);
}

//
//process map-request with smr bit set
//
int smr_process(void *mr, struct sockaddr_storage *sender {
		
	struct map_request_pkt mr_pkt;
	struct	map_request_eid *mr_eid;
	struct eid_rloc_db eid_db;
	struct eid_rloc_db rs;
	struct rloc_db *rloc;

	void *ptr;
	void *ad_ptr;
	int afi;
	void *sr_ip, *rloc_ip;
	int i;
	int s;

	mr_pkt = (struct map_request_pkt *) mr;

	//if not exist any EID in package, ignore package
	if (mr_pkt->record_count == 0) {
		return 0;
	}
				
	//Pass EID AFI
	if (ntohs(mr_pkt->source_eid_afi) == LISP_AFI_IP ) {
		ptr = CO(ptr, sizeof(struct in_addr));
	}
	else if (ntohs(mr_pkt->source_eid_afi) == LISP_AFI_IPV6) {
		ptr = CO(ptr, sizeof(struct in6_addr));
	}
	
	//Pass all ITR AFI,must there is at lease 1 ITR AFI
	for (i = 0; i<=mr_pkt->irc; i++ ) {
		if (ntohs(*((ushort*)ptr)) == LISP_AFI_IP ) {
			ptr = CO(ptr, sizeof(struct in_addr)+2);
		}
		else if (ntohs(*((ushort*)ptr)) == LISP_AFI_IPV6 ) {
			ptr = CO(ptr, sizeof(struct in6_addr)+2);
		}
	}

	//Get one of EID prefix (In future draft must support multi EID prefix)
	mr_eid = (struct map_request_eid *) ptr;
	eid_db.eidlen = mr_eid->eid_mask_len;
	eid_db.record_ttl = 0;
	eid_db.locator=0;
	eid_db.flag = 0;
	eid_db.rloc = NULL;
	eid_db.ed_next = NULL;
	if (mr_eid->eid_prefix_afi == LISP_AFI_IP) {
		eid_db.ed_ip.ss_family = AF_INET;
		ad_ptr = (struct sockaddr_in *)&(eid_db.ed_ip);
		ad_ptr->sin_port = 0;
		memcpy(&(ad_ptr->sin_addr), mr_eid->eid_prefix,sizeof(struct in_addr));
	}else if (mr_eid->eid_prefix_afi == LISP_AFI_IP6) {
		eid_db.ed_ip.ss_family = AF_INET6;
		ad_ptr = (struct sockaddr_in6 *)&(eid_db.ed_ip);
		memcpy(&(ad_ptr->sin6_addr), mr_eid->eid_prefix,sizeof(struct in6_addr));
	}
	
	//check if EID in database, if not, ignore map-request message
	s = socket(PF_MAP, SOCK_RAW, 0);
	if (get_eid(s, eid_db, &rs) < 0){
		close(s);
		return 0;
	}
	close(s);

	//check if source location in rloc-list
	rloc = rs.rloc;
	afi = sender->ss_family;
	if (afi == AF_INET) {
		sr_ip = &((struct sockaddr_in *)sender->sin_addr);
	}
	else if (afi == AF_INET6){
		sr_ip = &((struct sockaddr_in6 *)sender->sin6_addr);
	}
	else 
		return -1;
	i = (afi == AF_INET)?32:128;
	while (rloc != NULL) {		
		ad_ptr = &(rloc_ip->rl_ip);
		if (ad_ptr->ss_family != afi) {
			rloc = rloc->rl_next;
			continue;
		}
		
		if (ad_ptr->ss_family == AF_INET) {
			rloc_ip = &( (struct sockaddr_in *)ad_ptr->sin_addr);
		}
		else if (ad_ptr->ss_family == AF_INET6) {
			rloc_ip = &( (struct sockaddr_in6 *)ad_ptr->sin6_addr);
		}
		
		if ( bcp(sr_ip, rloc_ip, i) == i) {
			break;
		}
		rloc = rloc->rl_next;
	}
	
	//if source location not in rloc-list, send map-request to map-server
	if ( rloc == NULL) {
		//send to map-server
		return 0;
	}
	
	//if exist only one rloc, send to map-server
	if (rs.locator <=1) {
		//send_ms();
		return 0;
	}
	
	//send to rloc
	
	return 0;
}

int send4smr(sender,eid)
	struct sockaddr_storage *sender;
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