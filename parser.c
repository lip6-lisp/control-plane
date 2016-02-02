
#include <expat.h>
#include <sys/stat.h>

#include "lib.h"

#ifdef XML_LARGE_SIZE
	#if defined(XML_USE_MSC_EXTENSIONS) && _MSC_VER < 1400
		#define XML_FMT_INT_MOD "I64"
	#else
		#define XML_FMT_INT_MOD "ll"
	#endif
#else
	#define XML_FMT_INT_MOD "l"
#endif

static XML_Parser parser;
static const char *_xml_name;
static char *_prefix;
static struct mapping_flags _mflags;
static int _fam = AF_INET;
static void *_mapping;
u_char _fncs;
u_char lisp_te=0;
u_char srcport_rand = 1;
char *config_file[6];
	
/* compare priority bw 2 entry */
	int 
_insert_prio_ordered(void *data, void *entry)
{
	uint8_t _a;
	uint8_t _b;
	
	_a = ((struct map_entry *)data)->priority;
	_b = ((struct map_entry *)entry)->priority;

	return (_a - _b);
}

/* compare ip of two map_entry 
	ipv6 > ipv4
	return 1 when new_entry's ip > exist_entry's ip
	else return 0
*/
	int
_insert_ip_ordered(void *data, void *entry)
{
	union sockunion *ins_s, *exis_s;
	int mmask = 0;
	uint8_t *ins_ip, *exis_ip;
	
	ins_ip = exis_ip = NULL;
	ins_s = &((struct map_entry *)data)->rloc;
	exis_s = &((struct map_entry *)entry)->	rloc;
	
	if (ins_s->sa.sa_family !=  exis_s->sa.sa_family) {
		if (ins_s->sa.sa_family == AF_INET)
			/* ins_s (ipv4) < exis_s (ipv6) */
			return -1;
		else
			/* ins_s (ipv6) > exis_s (ipv4) */
			return 1;
	}
	
	/* same afi */
	switch (ins_s->sa.sa_family) {
	case AF_INET:
		mmask = 4;
		ins_ip = (uint8_t *)&ins_s->sin.sin_addr;
		exis_ip = (uint8_t *)&exis_s->sin.sin_addr;
		break;	
	case AF_INET6:
		mmask = 16;
		ins_ip = (uint8_t *)&ins_s->sin.sin_addr;
		exis_ip = (uint8_t *)&exis_s->sin.sin_addr;		
	}
	
	while (ins_ip && exis_ip && mmask > 0 && (*ins_ip == *exis_ip) ) {
		ins_ip++;
		exis_ip++;
		mmask--;
	}
	if (mmask == 0)
		return 0;
	if (*ins_ip > *exis_ip)
		return 1;
	else
		return -1;		
}

	int
get_my_addr(int afi, union sockunion *sk)
{
	struct ifaddrs *ifap, *ifa;
	char buf[NI_MAXHOST];
	
	if (getifaddrs(&ifap) == -1) 	
		return -1;	
    
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		/* ignore: */
			/* interface with not ip */
		if (ifa->ifa_addr == NULL)
			continue;
			/* interface with not same afi */	
		if (ifa->ifa_addr->sa_family != afi)
			continue;
			/* look back interface */	
		if (getnameinfo(ifa->ifa_addr,SA_LEN(ifa->ifa_addr->sa_family),
		    buf,NI_MAXHOST,NULL,0,NI_NUMERICHOST) != 0) {
			continue;
	    }
		if (!(strcmp(LOOPBACK,buf) && strcmp(LOOPBACK6,buf) &&  strncmp(LINK_LOCAL,buf,LINK_LOCAL_LEN)))
			continue;
		
		/* compare addr */
		switch (afi) {
		case AF_INET:
			memcpy((void *)&sk->sin.sin_addr, (void *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, 
					sizeof(struct in_addr));
			goto exit_fnc;				
		case AF_INET6:
			memcpy((void *)&sk->sin6.sin6_addr, (void *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
					sizeof(struct in6_addr));
			goto exit_fnc;						
		}		
	}
	return -1;

exit_fnc:	
	freeifaddrs(ifap);
	return 0;
}	

	void 
_err_config(char *err_msg) {
	printf("Error Configure file: %s, at line %" XML_FMT_INT_MOD "u\n",err_msg,XML_GetCurrentLineNumber(parser));
	cp_log(LLOG, "Error Configure file: %s, at line %" XML_FMT_INT_MOD "u\n",err_msg,XML_GetCurrentLineNumber(parser));
}

/* validate if an eid-prefix is overlap or not
	xTR EID must belong to root
	GEID, GREID must only belong to root and not overlap
	EID must belong to GEID and overlap each other
	EID-referral must belong to GREID and overlap each other
*/
	int
_valid_prefix(struct prefix *p, int type)
{
	struct db_node *rn = NULL;
	struct db_table *table;
	
	table = ms_get_db_table(ms_db,p);
	rn = db_node_match_prefix(table, p);
	/* database seem empty */
	if (!rn)
		return 1;
	
	/* duplicate EID */
	if (rn && rn->p.prefixlen == p->prefixlen)
		return 2;
		
	switch (type) {
	case _MAPP_XTR:
	/* EID-prefix of xTR must have target is root but can not overlap*/
		while (rn != table->top && !rn->flags)
			rn = rn->parent;
		return (rn == table->top || ((struct mapping_flags *)rn->flags)->range == _MAPP_XTR);
		break;
	case _GEID:
	case _GREID:
	/* _GEID prefix must have target is root and not overlap */	
		while (rn != table->top && !rn->flags)
			rn = rn->parent;
		return (rn == table->top);
		break;
	case _EID:
	/* _EID prefix must have target is one of _GEID*/	
		while (rn != table->top && !rn->flags)
			rn = rn->parent;
			
		return (rn == table->top || ((struct mapping_flags *)rn->flags)->range & (_GEID | _EID));
		break;	
	case _REID:	
		/* _EID prefix must have target is one of _GREID*/	
		while (rn != table->top && !rn->flags)
			rn = rn->parent;
		return (rn == table->top || ((struct mapping_flags *)rn->flags)->range == _GREID);	
		break;					
	}
	return 0;	
}

/* calc sum of weight of rloc chain for a priority */
	int
sw_rloc(struct list_t *rlc, uint8_t priority)
{
	int sw = 0;
	struct list_entry_t *iter;
	struct map_entry *me;
	
	if (!rlc)
		return -1;
	iter = rlc->head.next;
	while (iter != &rlc->tail) {
		if (!(me = (struct map_entry *)iter->data))
			return -1;
		if (me->priority == priority)
			sw += me->weight;
		iter = iter->next;
	}
	return sw;
}	

/* calc sum of weight of elp chain for a priority */
	int
sw_elp(struct list_t *elp, uint8_t priority)
{
	int sw = 0;
	struct list_entry_t *iter;
	struct pe_entry *pe;
	
	if (!elp)
		return -1;
	iter = elp->head.next;
	while (iter != &elp->tail) {
		if (!(pe = (struct pe_entry *)iter->data))
			return -1;
		if (pe->priority == priority)
			sw += pe->weight;
		iter = iter->next;
	}
	return sw;
}	

	int
_get_file_size(const char *filename)
{
	struct stat sb;
    
	if (stat(filename, &sb) == 0)
		return sb.st_size;
	else
		return -1;
}
	
	int 
xml_configure(const char *filename,
	void (*startElement)(void *, const char *, const char **),
	void (*endElement)(void *, const char *),
	void (*getElementValue)(void *, const XML_Char *, int)
)
{
	int done;
	int bsize;
	char *buf;
	FILE *config;
	
	if ((bsize = _get_file_size(filename)) == -1) {
		cp_log(LLOG, "Error configure file: can not open file %s\n",filename);
		exit(1);
	}
	buf = (char *)malloc(bsize+1);
	bzero(buf, bsize+1);

	parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, NULL);

	XML_SetStartElementHandler(parser, startElement);
	XML_SetEndElementHandler(parser, endElement);

	XML_SetCharacterDataHandler(parser, getElementValue);

	config = fopen(filename, "r");

	do {
		unsigned int len = (int)fread(buf, 1, bsize, config);
		done = len < sizeof(buf);
		if (XML_Parse(parser, buf, len, done) == XML_STATUS_ERROR) {
			cp_log(LLOG, "Error Configure file: %s at line %" XML_FMT_INT_MOD "u\n",\
					XML_ErrorString(XML_GetErrorCode(parser)),\
					XML_GetCurrentLineNumber(parser));
			fclose(config);
			exit(1);
		}
	} while (!done);
	
	XML_ParserFree(parser);
	
	fclose(config);
	return 0;
}


/* ====================================================================
 * Parse for xTR configure 
 */
struct ms_entry *xtr_ms_entry;
struct mr_entry *xtr_mr_entry;
struct pe_entry *pe;
struct hop_entry *hop;

	static int
ms_match_id(void *id, void *ms_entry)
{
	struct ms_entry *ms;
	uint8_t *i;
	
	ms = (struct ms_entry *)ms_entry;
	i = (uint8_t *)id;	
	if (ms->id == *i)
		return 0;
	
	return 1;	
}
	
	static void XMLCALL
xtr_startElement(void *userData, const char *name, const char **atts)
{
	int len;
	struct map_entry *entry;
	char *msids;
	
	if ((0 == strcasecmp(name, "eid_prefix")) || 
	    (0 == strcasecmp(name, "eid"))) {
		msids = NULL;
		while (*atts) {
			/* EID prefix */
			if (0 == strcasecmp(*atts, "ms_ids")) {
				atts++;
				msids = (char *)*atts;
			}
			
			if (0 == strcasecmp(*atts, "prefix")) {
				/*get eid-prefix */
				struct prefix p1;
				atts++;
				len = strlen(*atts);
				printf("processing prefix \n");
				_prefix = (char *)calloc(1, len+1);
				memcpy(_prefix, *atts, len);
				*(_prefix + len) = '\0';
				if (str2prefix (_prefix, &p1) <=0) {
					_err_config("invalid prefix");
					exit(1);				
				}				
				apply_mask(&p1);				
				/* append to db */
				if (!_valid_prefix(&p1, _MAPP_XTR) || !(_mapping = generic_mapping_new(&p1)) ) {
					_err_config("invalid prefix");
					exit(1);
				}
				bzero(&_mflags, sizeof(struct mapping_flags));
				_mflags.range = _MAPP_XTR;
				_mflags.act = 0;
				_mflags.A = 1; /* I'm ETR so I owns the EID-prefix */				
				list_insert(etr_db, _mapping, NULL);
				struct list_entry_t *p;
				struct ms_entry *ms;
				
				if ((msids != NULL) && (0 != strcasecmp(msids, "all")) && (0 != strcasecmp(msids, "none"))) {						
					char data[50][255];
					char *tk;
					char *ptr;
					char *sep_t =  "; ";
					int	i = 0, j; /*counter */					
					uint8_t	m;
					
					i = 0;
					/*ms_id="ms1; ms2; ...; msn" */
					for (tk = strtok_r(msids, sep_t, &ptr); tk ; tk = strtok_r(NULL, sep_t, &ptr))
						strcpy(data[i++], tk);
					
					for (j = 0; j < i ; j++) {
						/* assign EID to Map-server */
						m = atoi(data[j]);
						if (xtr_ms && ((p = list_search(xtr_ms,(void *)&m,ms_match_id)) != NULL)) {
							ms = (struct ms_entry *)p->data;
							list_insert(ms->eids, _mapping, NULL);
						}
						else{
							printf("Error Configure file: MS ID %d invalid, at line %" XML_FMT_INT_MOD "u\n",m, XML_GetCurrentLineNumber(parser));
							exit(1);
						};					
					}					
				}else{/* assign EID to all MS */
					if ((msids == NULL) || (msids && (0 != strcasecmp(msids, "none")) )) {
						if (xtr_ms) {
							p = xtr_ms->head.next;
							while (p != &xtr_ms->tail) {
								ms = (struct ms_entry *)p->data;
								list_insert(ms->eids, _mapping, NULL);
								p = p->next;
							}
						}
					}
				};
				
			}
			
			/* ACT bits */
			if (0 == strcasecmp(*atts, "act")) {
				atts++;
				_mflags.act = atoi(*atts);
			}
			/* Echo-noncable */
			if (0 == strcasecmp(*atts, "a")) {
				atts++;
				_mflags.A = (strcasecmp(*atts, "true")==0);
			}
			/* Version */
			if (0 == strcasecmp(*atts, "version")) {
				atts++;
				_mflags.version = atoi(*atts);	
			}
			/* TTL */
			if (0 == strcasecmp(*atts, "ttl")) {
				atts++;
				_mflags.ttl = atoi(*atts);
				printf("processing ttl ");
			}
			/* y5er */
			if (0 == strcasecmp(*atts, "peer")){
				struct prefix peer_prefix;
				/* getting peer eid from buf string*/
				// NOTICE: we reuse the len and _prefix
				atts++;
				len = strlen(*atts);
				_prefix = (char *)calloc(1, len+1);
				memcpy(_prefix, *atts, len);
				*(_prefix + len) = '\0';
				printf("processing peer prefix ");
				if (str2prefix(_prefix,&peer_prefix) <= 0){
					_err_config("invalid prefix");
					exit(1);
				}
				apply_mask(&peer_prefix);
				/* adding peer's eid*/
				if ( !generic_mapping_set_peer(_mapping,&peer_prefix) ){
					_err_config("unable to set peer");
					exit(1);
				}

			}
			/* y5er */

			/**/
			atts++;
		}
	} else {
		if (0 == strcasecmp(name, "address") ||
			0 == strcasecmp(name, "ms") ||
			0 == strcasecmp(name, "mr") ||
			0 == strcasecmp(name, "petr") ||
			0 == strcasecmp(name, "elp")||
			0 == strcasecmp(name, "hop")){
			
			if (0 == strcasecmp(name, "ms")) {
				xtr_ms_entry = calloc(1, sizeof(struct ms_entry));
				xtr_ms_entry->id = -1;
				xtr_ms_entry->proxy = 0;				
				xtr_ms_entry->eids = list_init();
				list_insert(xtr_ms, xtr_ms_entry, NULL);		
			}
			if (0 == strcasecmp(name, "elp")) {
				pe = calloc(1,sizeof(struct pe_entry));				
			}
			
			if (0 == strcasecmp(name, "address") )
				_fam = AF_INET;
			
			if (0 == strcasecmp(name, "hop")) {
				_fam = AF_INET;
				hop = calloc(1, sizeof(struct hop_entry));				
			}
			
			while (*atts) {
				
				if (0 == strcasecmp(*atts, "family")) {
					atts++;
					_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
				}
				
				if (0 == strcasecmp(*atts, "id")) {
					struct list_entry_t *pr;
					atts++;
					xtr_ms_entry->id = atoi(*atts);	
					if (xtr_ms && (pr = list_search(xtr_ms,(void *)&(xtr_ms_entry->id),ms_match_id)) && (pr->data != xtr_ms_entry) )	{
						_err_config("duplicate Map server id");
						pr = xtr_ms->head.next;						
						exit(1);
					}					
				}
				
				if (0 == strcasecmp(*atts, "key")) {
					atts++;
					len = strlen(*atts);
					xtr_ms_entry->key = (char *)calloc(1, len+1);
					memcpy(xtr_ms_entry->key, *atts, len);
					xtr_ms_entry->key[len] = '\0';	
				}
				if (0 == strcasecmp(*atts, "proxy")) {
					atts++;
					xtr_ms_entry->proxy = (strncasecmp(*atts,"yes",3) == 0)? _ACTIVE: _NOACTIVE;						
				}
				if (pe) {
					if (0 == strcasecmp(*atts, "priority")) {
						atts++;
						pe->priority = atoi(*atts);
					}
					if (0 == strcasecmp(*atts, "m_priority")) {
						atts++;
						pe->m_priority = atoi(*atts);
					}
					if (0 == strcasecmp(*atts, "weight")) {
						atts++;
						pe->weight = atoi(*atts);
					}
					if (0 == strcasecmp(*atts, "m_weight")) {
						atts++;
						pe->m_weight = atoi(*atts);
					}
				}
				
				atts++;
			}
		}else{
			if (0 == strcasecmp(name, "rloc")) {
				if (userData || !_mapping) { 
					_err_config("Mismatch tag");	
					exit(1);
				}
				entry = calloc(1, sizeof(struct map_entry));
				XML_SetUserData(parser, entry);
			}
			
		}
	}

	_xml_name = name;
}

	static void XMLCALL
xtr_endElement(void *userData, const char *name)
{
	struct map_entry *entry;
	
	entry = (struct map_entry*)userData;
	if (0 == strcasecmp(name, "rloc")) {		
		if (!entry) { 
			_err_config("Mismatch tag");
			exit(1);
		}
		XML_SetUserData(parser, NULL);
		if (entry->priority > 0 && entry->weight > 0 && 
			(entry->weight + sw_rloc(((struct db_node *)_mapping)->info,entry->priority)) <= 100 ) {		
			generic_mapping_add_rloc(_mapping, entry);
		}else{
			_err_config("Incorrect priority or weight (sum weight must <=100 for each priority)");
			exit(1);
		}
		entry = NULL;
	}else{
		if (0 == strcasecmp(name, "eid_prefix") || 0 == strcasecmp(name, "eid")) {			
			generic_mapping_set_flags(_mapping, &_mflags);			
			bzero(&_mflags, sizeof(struct mapping_flags));
			free(_prefix);
			_prefix = NULL;
			_mapping = NULL;
		}
		
		/* if (0 == strcasecmp(name, "db") || 
			0 == strcasecmp(name, "mapserver") ||
			0 == strcasecmp(name, "mapresolver")) {			
		} */
		
		if (0 == strcasecmp(name, "ms")) {
			xtr_ms_entry = NULL;
		}
		
		if (0 == strcasecmp(name, "mr")) {
			xtr_mr_entry = NULL;
		}
		
		if (0 == strcasecmp(name, "elp")) {
			if (entry && !entry->pe)
				entry->pe = list_init();
			cp_log(LLOG, "pe->weight:%d,pe->priority:%d\n",pe->weight,pe->priority);
			if (entry && entry->pe && (pe->weight + sw_elp(entry->pe,pe->priority) <=100))
				list_insert(entry->pe, pe,NULL);
			else{
				_err_config("Incorrect priority or weight (sum weight must <=100 for each priority)");
				exit(1);
			}
			pe = NULL;
		}	
	}	
}

	static void XMLCALL
xtr_getElementValue(void *userData, const XML_Char *s, int len)
{
	struct map_entry *entry;
	void *ptr;
	
	char buf[len+1];

	buf[len] = '\0';
	memcpy(buf, s, len);

	entry = (struct map_entry *)userData;
	if (entry) {
		if (0 == strcasecmp(_xml_name, "priority")) {
			entry->priority = atoi(buf);
		}else if (0 == strcasecmp(_xml_name, "m_priority")) {
			entry->m_priority = atoi(buf);
		}else if (0 == strcasecmp(_xml_name, "weight")) {
			entry->weight = atoi(buf);
		}else if (0 == strcasecmp(_xml_name, "m_weight")) {
			entry->m_weight = atoi(buf);
		}else if (0 == strcasecmp(_xml_name, "reachable")) {
			entry->r = (strcasecmp(buf, "true")==0);
		}else if (0 == strcasecmp(_xml_name, "local")) {
			entry->L = (strcasecmp(buf, "true")==0);
		}else if (0 == strcasecmp(_xml_name, "rloc-probing")) {
			entry->p = (strcasecmp(buf, "true")==0);
		/*y5er*/
		}else if (0 == strcasecmp(_xml_name, "ingress_cost")) {
					entry->i_cost = atoi(buf);
		}else if (0 == strcasecmp(_xml_name, "egress_cost")) {
					entry->e_cost = atoi(buf);
		/*y5er*/
		}else if (0 == strcasecmp(_xml_name, "hop")) {
			hop->addr.sa.sa_family = _fam;
			switch (_fam) {
				case AF_INET:
					ptr = &hop->addr.sin.sin_addr;
					break;
				case AF_INET6:
					ptr = &hop->addr.sin6.sin6_addr;
					break;
				default:
					_fam = AF_INET;
					ptr = &hop->addr.sa.sa_data;
					break;
			}
			if (inet_pton(_fam, buf, ptr) <=0) {
				_err_config("invalid address");
				exit(1);
			}
			if (pe && !pe->hop)
				pe->hop = list_init();
			if (pe)	
				list_insert(pe->hop, hop,NULL);
			else{
				_err_config("missing elp");
				exit(1);
			}			
			hop = NULL;
			_fam = AF_INET;
		}else if (0 == strcasecmp(_xml_name, "address")) {
			entry->rloc.sa.sa_family = _fam;
			switch (_fam) {
				case AF_INET:
					ptr = &entry->rloc.sin.sin_addr;
					break;
				case AF_INET6:
					ptr = &entry->rloc.sin6.sin6_addr;
					break;
				default:
					_fam = AF_INET;
					ptr = &entry->rloc.sa.sa_data;
					break;
			}
			if (inet_pton(_fam, buf, ptr) <=0) {
				_err_config("invalid address");
				exit(1);
			}
			_fam = AF_INET;
		}
	}
	
	if (0 == strcasecmp(_xml_name, "ms")) {
		switch (_fam) {
		case AF_INET:
			xtr_ms_entry->addr.sin.sin_family = _fam;
			xtr_ms_entry->addr.sin.sin_port = htons(LISP_CP_PORT);
			ptr = &xtr_ms_entry->addr.sin.sin_addr;
		break;
		case AF_INET6:
			xtr_ms_entry->addr.sin6.sin6_family = _fam;
			xtr_ms_entry->addr.sin6.sin6_port = htons(LISP_CP_PORT);
			ptr = &xtr_ms_entry->addr.sin6.sin6_addr;
		break;
		default:
			xtr_ms_entry->addr.sa.sa_family = AF_INET;
			xtr_ms_entry->addr.sin.sin_port = htons(LISP_CP_PORT);
			ptr = &xtr_ms_entry->addr.sa.sa_data;
			break;
		}
		if (inet_pton(_fam, buf, ptr) <=0) {
				_err_config("invalid address");
				exit(1);
		}
		
		_fam = AF_INET;
	}else{
		if (0 == strcasecmp(_xml_name, "mr")) {
			xtr_mr_entry = calloc(1, sizeof(struct mr_entry));
			union sockunion *mr = &xtr_mr_entry->addr;
			switch (_fam) {
			case AF_INET:
				mr->sin.sin_family = _fam;
				mr->sin.sin_port = htons(LISP_CP_PORT);
				ptr = &mr->sin.sin_addr;
			break;
			case AF_INET6:
				mr->sin6.sin6_family = _fam;
				mr->sin6.sin6_port = htons(LISP_CP_PORT);
				ptr = &mr->sin6.sin6_addr;
			break;
			default:
				mr->sa.sa_family = AF_INET;
				mr->sin.sin_port = htons(LISP_CP_PORT);
				ptr = &mr->sa.sa_data;
				break;
			}
			if (inet_pton(_fam, buf, ptr) <=0) {
				_err_config("invalid address");
				exit(1);
			}
			list_insert(xtr_mr,xtr_mr_entry, NULL);
			_fam = AF_INET;					
		}
	}
	if (0 == strcasecmp(_xml_name, "petr")) {
		struct petr_entry *petr;
		petr = calloc(1, sizeof(struct petr_entry));
		switch (_fam) {
		case AF_INET:
			petr->addr.sin.sin_family = _fam;					
			ptr = &petr->addr.sin.sin_addr;
		break;
		case AF_INET6:
			petr->addr.sin6.sin6_family = _fam;					
			ptr = &petr->addr.sin6.sin6_addr;
		break;
		default:
			petr->addr.sa.sa_family = AF_INET;					
			ptr = &petr->addr.sa.sa_data;
			break;
		}		
		petr->addr.sin.sin_port = htons(LISP_DP_PORT);
		if (inet_pton(_fam, buf, ptr) <=0) {
			_err_config("invalid address");
			exit(1);
		}
		list_insert(xtr_petr,petr, NULL);
		_fam = AF_INET;	
	}
	/* y5er */
	/*
	if ( 0 == strcasecmp(_xml_name,"peer")) {
		struct prefix peer_prefix;

		if (str2prefix(buf,&peer_prefix) <= 0){
			_err_config("invalid prefix");
			exit(1);
		}

		apply_mask(&peer_prefix);
		if ( !generic_mapping_set_peer(_mapping,&peer_prefix) ){
			_err_config("unable to set peer");
			exit(1);
		}
	}
	*/
	/* y5er */
	_xml_name = "DUMMY";
}

/*====================================================================
 * Parse for map-resolve configure 
 */

	static void XMLCALL
mr_startElement(void *userData, const char *name, const char **atts)
{
	int len;
	struct map_entry *entry;
	if ((0 == strcasecmp(name, "eid_prefix")) ||
	   (0 == strcasecmp(name, "eid")) ) {
		_mflags.iid = 0;
		while (*atts) {
			/* EID prefix */
			if (0 == strcasecmp(*atts, "prefix")) {
				struct prefix p1;
				atts++;
				len = strlen(*atts);
				_prefix = (char *)calloc(1, len+1);
				memcpy(_prefix, *atts, len);
				*(_prefix + len) = '\0';
				if (str2prefix (_prefix, &p1) <=0) {
					_err_config("invalid prefix");
					exit(1);				
				}				
				apply_mask(&p1);
				if (!_valid_prefix(&p1, _REID) || !(_mapping = generic_mapping_new(&p1))) {	
					_err_config("invalid prefix - overlap");
					exit(0);
				}
				bzero(&_mflags, sizeof(struct mapping_flags));
				_mflags.range = _MAPP;				
			}
			_mflags.A = 0;
			_mflags.referral = LISP_REFERRAL_NODE_REFERRAL+1;
			
			/* ACT bits */
			if (0 == strcasecmp(*atts, "act")) {
				atts++;
				_mflags.act = atoi(*atts);
			}
			if (0 == strcasecmp(*atts, "iid")) {
				atts++;
				_mflags.iid = atoi(*atts);
			}
			/* Echo-noncable */
			if (0 == strcasecmp(*atts, "a")) {
				atts++;
				_mflags.A = (strcasecmp(*atts, "true")==0);
			}
			/* Version */
			if (0 == strcasecmp(*atts, "version")) {
				atts++;
				_mflags.version = atoi(*atts);	
			}
			/* TTL */
			if (0 == strcasecmp(*atts, "ttl")) {
				atts++;
				_mflags.ttl = atoi(*atts);  
			}
			/* Referral */
			if (0 == strcasecmp(*atts, "referral")) {
				atts++;
				//in case can not detect type of referral, set to NODE_REFERRAL;
				_mflags.referral = LISP_REFERRAL_NODE_REFERRAL+1;
				if (strcasecmp(*atts, "true")==0 || strcasecmp(*atts, "node")==0)
					_mflags.referral = LISP_REFERRAL_NODE_REFERRAL+1;
				if (strcasecmp(*atts, "ms")==0)
					_mflags.referral = LISP_REFERRAL_MS_REFERRAL+1;					
			}
			/* Incomplete Referral */
			if (0 == strcasecmp(*atts, "incomplete")) {
				atts++;
				_mflags.incomplete = (strcasecmp(*atts, "true")==0);
			}

			/**/
			atts++;
		}
	} else if (0 == strcasecmp(name, "address")) {
		_fam = AF_INET;
		while (*atts) {
			if (0 == strcasecmp(*atts, "family")) {
				atts++;
				_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
			}
			else
				_fam = AF_INET;
			atts++;
		}		
	}
	if (!userData) {
		entry = calloc(1, sizeof(struct map_entry));
		XML_SetUserData(parser, entry);
	}
	_xml_name = name;
}

	static void XMLCALL
mr_endElement(void *userData, const char *name)
{
	struct map_entry *entry;
	
	if ((0 == strcasecmp(name, "ddt_node")) ||
	   (0 == strcasecmp(name, "rloc"))) {
		entry = (struct map_entry*)userData;
		XML_SetUserData(parser, NULL);
		generic_mapping_add_rloc(_mapping, entry);
	}else if ((0 == strcasecmp(name, "eid_prefix")) ||
	          (0 == strcasecmp(name, "eid"))) {
		generic_mapping_set_flags(_mapping, &_mflags);
		bzero(&_mflags, sizeof(struct mapping_flags));		
		free(_prefix);
		_prefix = NULL;
	}
}

	static void XMLCALL
mr_getElementValue(void *userData, const XML_Char *s, int len)
{
	struct map_entry *entry;
	char buf[len+1];

	buf[len] = '\0';
	memcpy(buf, s, len);
	entry = (struct map_entry *)userData;

	if (0 == strcasecmp(_xml_name, "priority")) {
		entry->priority = atoi(buf);
	}else if (0 == strcasecmp(_xml_name, "weight")) {
		entry->weight = atoi(buf);
	}else if (0 == strcasecmp(_xml_name, "reachable")) {
		entry->r = (strcasecmp(buf, "true")==0);
	}else if (0 == strcasecmp(_xml_name, "address")) {
		void *ptr;
		entry->rloc.sa.sa_family = _fam;
		switch (_fam) {
		case AF_INET:
			ptr = &entry->rloc.sin.sin_addr;
			break;
		case AF_INET6:
			ptr = &entry->rloc.sin6.sin6_addr;
			break;
		default:
			ptr = &entry->rloc.sa.sa_data;
			break;
		}
		if (inet_pton(_fam, buf, ptr) <=0) {
				_err_config("invalid address");
				exit(1);
		}

		_fam = AF_INET;
	}

	_xml_name = "DUMMY";
}

/*====================================================================
 * Parse for node configure 
 */

	static void XMLCALL
node_startElement(void *userData, const char *name, const char **atts)
{
	int len;
	struct map_entry *entry;
	if (0 == strcasecmp(name, "delegated_eid_prefix") ) {
		_mflags.iid = 0;
		while (*atts) {
			/* EID prefix */
			if (0 == strcasecmp(*atts, "prefix")) {
				struct prefix p1;
				atts++;
				len = strlen(*atts);
				_prefix = (char *)calloc(1, len+1);
				memcpy(_prefix, *atts, len);
				*(_prefix + len) = '\0';
				if (str2prefix (_prefix, &p1) <=0) {
					_err_config("invalid prefix");
					exit(1);				
				}				
				apply_mask(&p1);
				if (!_valid_prefix(&p1, _REID) || !(_mapping = generic_mapping_new(&p1))) {	
					_err_config("invalid prefix - overlap");
					exit(0);
				}
				bzero(&_mflags, sizeof(struct mapping_flags));
				_mflags.range = _MAPP;				
			}
			/* set default value of flags, override by user */
			_mflags.A = 1;
			_mflags.ttl = 60;
			_mflags.referral = LISP_REFERRAL_NODE_REFERRAL+1;
			_mflags.incomplete = 0;
			
			/* ACT bits */
			if (0 == strcasecmp(*atts, "act")) {
				atts++;
				_mflags.act = atoi(*atts);
			}
			if (0 == strcasecmp(*atts, "iid")) {
				atts++;
				_mflags.iid = atoi(*atts);
			}
			/* Echo-noncable */
			if (0 == strcasecmp(*atts, "a")) {
				atts++;
				_mflags.A = (strcasecmp(*atts, "true")==0);
			}
			/* Version */
			if (0 == strcasecmp(*atts, "version")) {
				atts++;
				_mflags.version = atoi(*atts);	
			}
			/* TTL */
			if (0 == strcasecmp(*atts, "ttl")) {
				atts++;
				_mflags.ttl = atoi(*atts);  
			}
			/* Referral */
			if (0 == strcasecmp(*atts, "referral")) {
				atts++;
				//in case can not detect type of referral, set to NODE_REFERRAL;
				_mflags.referral = LISP_REFERRAL_NODE_REFERRAL+1;
				if (strcasecmp(*atts, "true")==0 || strcasecmp(*atts, "node")==0  )
					_mflags.referral = LISP_REFERRAL_NODE_REFERRAL+1;
				if (strcasecmp(*atts, "ms")==0)
					_mflags.referral = LISP_REFERRAL_MS_REFERRAL+1;					
			}
			/* Incomplete Referral */
			if (0 == strcasecmp(*atts, "incomplete")) {
				atts++;
				_mflags.incomplete = (strcasecmp(*atts, "true")==0);
			}

			/**/
			atts++;
		}
	} else if (0 == strcasecmp(name, "address")) {
		_fam = AF_INET;
		while (*atts) {
			if (0 == strcasecmp(*atts, "family")) {
				atts++;
				_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
			}
			else
				_fam = AF_INET;
			atts++;
		}		
	}
	if (!userData) {
		entry = calloc(1, sizeof(struct map_entry));
		XML_SetUserData(parser, entry);
	}
	_xml_name = name;
}

	static void XMLCALL
node_endElement(void *userData, const char *name)
{
	struct map_entry *entry;
	
	if (0 == strcasecmp(name, "ddt_node")) {
		entry = (struct map_entry*)userData;
		XML_SetUserData(parser, NULL);
		generic_mapping_add_rloc(_mapping, entry);
	}else if (0 == strcasecmp(name, "delegated_eid_prefix")) {
		generic_mapping_set_flags(_mapping, &_mflags);
		bzero(&_mflags, sizeof(struct mapping_flags));		
		free(_prefix);
		_prefix = NULL;
	}
}

	static void XMLCALL
node_getElementValue(void *userData, const XML_Char *s, int len)
{
	struct map_entry *entry;
	struct db_table *db;
	struct db_node *dn;
	struct prefix  pf;	
	char buf[len+1];

	buf[len] = '\0';
	memcpy(buf, s, len);
	entry = (struct map_entry *)userData;

	if (0 == strcasecmp(_xml_name, "priority")) {
		entry->priority = atoi(buf);
	}else if (0 == strcasecmp(_xml_name, "weight")) {
		entry->weight = atoi(buf);
	}else if (0 == strcasecmp(_xml_name, "reachable")) {
		entry->r = (strcasecmp(buf, "true")==0);
	}else if (0 == strcasecmp(_xml_name, "address")) {
		void *ptr;
		entry->rloc.sa.sa_family = _fam;
		switch (_fam) {
			case AF_INET:
				ptr = &entry->rloc.sin.sin_addr;
				break;
			case AF_INET6:
				ptr = &entry->rloc.sin6.sin6_addr;
				break;
			default:
				ptr = &entry->rloc.sa.sa_data;
				break;
		}
		if (inet_pton(_fam, buf, ptr) <=0) {
				_err_config("invalid address");
				exit(1);
		}

		_fam = AF_INET;
	}else if (0 == strcasecmp(_xml_name, "eid_prefix")) {
		if (str2prefix(buf, &pf)) {
			apply_mask(&pf);
			if (_valid_prefix(&pf, _GREID) && (db= ms_get_db_table(ms_db, &pf)) ) {
				dn = db_node_get(db, &pf);
				ms_node_update_type(dn,_GREID);				
			}
		}else{				
				_err_config("invalid address");
				exit(1);							
		}
	}

	_xml_name = "DUMMY";
}

/*====================================================================
 *Parse for map-server configure
 */ 
static struct list_entry_t *site_entry;
static struct db_node *eid_node;

	static void XMLCALL
ms_startElement(void *userData, const char *name, const char **atts)
{
	if (0 == strcasecmp(name, "site")) {
		if (site_entry != NULL) {
			_err_config("mismatch tag");
			exit(0);
		}
		site_entry = ms_new_site(site_db);		
	} else if ((0 == strcasecmp(name, "delegated_eid_prefix")) || 
	          (0 == strcasecmp(name, "eid"))) {
		if ((site_entry == NULL) || eid_node != NULL) {
			_err_config("mismatch tag");
			exit(0);
		}
		bzero(&_mflags,sizeof(struct mapping_flags));
		_mflags.range = _EID;
		_mflags.rsvd = site_entry;		
	}else if (0 == strcasecmp(name, "eid_prefix") || 0 == strcasecmp(name, "addr") || 0 == strcasecmp(name, "arrange")) {
		_fam = AF_INET;
		while (*atts) {
			if (0 == strcasecmp(*atts, "family")) {
				atts++;
				_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
			}
			else
				_fam = AF_INET;
			atts++;
		}
	}
	
	_xml_name = name;
}

	static void XMLCALL
ms_endElement(void *userData, const char *name)
{
	if (0 == strcasecmp(name, "site")) {
		site_entry = NULL;		
	}else if (0 == strcasecmp(name, "delegated_eid_prefix")) {	
		generic_mapping_set_flags(eid_node,&_mflags);		
		bzero(&_mflags,sizeof(struct mapping_flags));
		eid_node = NULL;
	}
}

	static void XMLCALL
ms_getElementValue(void *userData, const XML_Char *s, int len)
{
	
	char buf[len+1];
	struct prefix pf;
	struct db_table *db;
	struct site_info *s_data;
	struct db_node *dn;
	
	buf[len] = '\0';
	
	if (!s)
		return ;
		
	memcpy(buf, s, len);	
	s_data = NULL;
	if (site_entry && site_entry->data) {
		s_data = (struct site_info *)site_entry->data;
		if (0 == strcasecmp(_xml_name, "name")) {
			s_data->name = calloc(len+1,sizeof(char));
			memcpy(s_data->name, buf,len+1);		
		}
		else if (0 == strcasecmp(_xml_name, "key")) {
			s_data->key = calloc(len+1,sizeof(char));
			memcpy(s_data->key, buf,len+1);				
		}else if (0 == strcasecmp(_xml_name, "contact")) {
			s_data->contact = calloc(len+1,sizeof(char));
			memcpy(s_data->contact, buf,len+1);				
		}else if (0 == strcasecmp(_xml_name, "active")) {
			if (!_mflags.range) {
				s_data->active = (strncasecmp(buf,"yes",3) == 0)? _ACTIVE: _NOACTIVE;
			}
		}
	}
	if (site_entry) {
		if (0 == strcasecmp(_xml_name, "delegated_eid_prefix")) {
			if (str2prefix(buf, &pf) == 1) {
				apply_mask(&pf);
				if (_valid_prefix(&pf, _EID) && (db = ms_get_db_table(ms_db, &pf) ) && (eid_node = db_node_get(db, &pf)) ) {
					list_insert(s_data->eid, eid_node,NULL);				
				}else{
					_err_config("invalid address");
					exit(1);
				}
			}
		}
	}
	if (site_entry && eid_node) {
		if (0 == strcasecmp(_xml_name, "active"))
			if (_mflags.range) {
				_mflags.active = (strncasecmp(buf,"yes",3) == 0)? _ACTIVE: _NOACTIVE;
			}				
	}		
	
	if (0 == strcasecmp(_xml_name, "eid_prefix")) {
		if (str2prefix(buf, &pf)) {
			apply_mask(&pf);
			if (_valid_prefix(&pf, _GEID) && (db= ms_get_db_table(ms_db, &pf)) ) {
				dn = db_node_get(db, &pf);
				ms_node_update_type(dn,_GEID);				
			}
		}else{
				_err_config("invalid address");
				exit(1);							
		}
	}

	_xml_name = "DUMMY";
}

/*====================================================================
 * Parse for map-resolve configure 
 */
struct list_t *rloc_list;
struct map_entry *rtr_entry;

	static void XMLCALL
rtr_startElement(void *userData, const char *name, const char **atts)
{
	int len;
	
	if (0 == strcasecmp(name, "eid")) {
		_fam = AF_INET;
		while (*atts) {
			/* EID prefix */
			if (0 == strcasecmp(*atts, "family")) {
				atts++;
				_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
			}			
			if (0 == strcasecmp(*atts, "prefix")) {
				/*get eid-prefix */
				struct prefix p1;
				atts++;
				len = strlen(*atts);
				_prefix = (char *)calloc(1, len+1);
				memcpy(_prefix, *atts, len);
				*(_prefix + len) = '\0';
				if (str2prefix (_prefix, &p1) <=0) {
					_err_config("invalid prefix");
					exit(1);				
				}				
				apply_mask(&p1);				
				/* append to db */
				if (!_valid_prefix(&p1, _MAPP_XTR) || !(_mapping = generic_mapping_new(&p1)) ) {
					_err_config("invalid prefix");
					exit(1);
				}
				bzero(&_mflags, sizeof(struct mapping_flags));
				_mflags.range = _MAPP_XTR;
				list_insert(etr_db, _mapping, NULL);
				struct list_entry_t *lptr;
				lptr = rloc_list->head.next;
				while (lptr != &rloc_list->tail) {
					rtr_entry = (struct map_entry *)lptr->data;
					generic_mapping_add_rloc(_mapping, rtr_entry);
					lptr = lptr->next;
				}	
			}
			/* ACT bits */
			if (0 == strcasecmp(*atts, "act")) {
				atts++;
				_mflags.act = atoi(*atts);
			}
			/* Echo-noncable */
			if (0 == strcasecmp(*atts, "a")) {
				atts++;
				_mflags.A = (strcasecmp(*atts, "true")==0);
			}
			/* Version */
			if (0 == strcasecmp(*atts, "version")) {
				atts++;
				_mflags.version = atoi(*atts);	
			}
			/* TTL */
			if (0 == strcasecmp(*atts, "ttl")) {
				atts++;
				_mflags.ttl = atoi(*atts);  
			}
			/**/
			atts++;
		}
		generic_mapping_set_flags(_mapping, &_mflags);			
		bzero(&_mflags, sizeof(struct mapping_flags));
		free(_prefix);
		_prefix = NULL;
		_mapping = NULL;
	} 
	if (0 == strcasecmp(name, "mr")) {
		_fam = AF_INET;
		while (*atts) {
			if (0 == strcasecmp(*atts, "family")) {
				atts++;
				_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
			}
		}
	}
	_xml_name = name;
}

	static void XMLCALL
rtr_endElement(void *userData, const char *name)
{
	struct map_entry *entry;
	
	entry = (struct map_entry*)userData;
	if (0 == strcasecmp(name, "mr")) {
		xtr_mr_entry = NULL;
	}
		
}

	static void XMLCALL
rtr_getElementValue(void *userData, const XML_Char *s, int len)
{
	struct map_entry *entry;
	void *ptr;
	
	char buf[len+1];

	buf[len] = '\0';
	memcpy(buf, s, len);

	entry = (struct map_entry *)userData;
		
	if (0 == strcasecmp(_xml_name, "mr")) {
		xtr_mr_entry = calloc(1, sizeof(struct mr_entry));
		union sockunion *mr = &xtr_mr_entry->addr;
		switch (_fam) {
		case AF_INET:
			mr->sin.sin_family = _fam;
			mr->sin.sin_port = LISP_CP_PORT;
			ptr = &mr->sin.sin_addr;
		break;
		case AF_INET6:
			mr->sin6.sin6_family = _fam;
			mr->sin6.sin6_port = LISP_CP_PORT;
			ptr = &mr->sin6.sin6_addr;
		break;
		default:
			mr->sa.sa_family = AF_INET;
			mr->sin.sin_port = LISP_CP_PORT;
			ptr = &mr->sa.sa_data;
			break;
		}
		if (inet_pton(_fam, buf, ptr) <=0) {
			_err_config("invalid address");
			exit(1);
		}
		list_insert(xtr_mr,xtr_mr_entry, NULL);
		_fam = AF_INET;					
	}
	
	_xml_name = "DUMMY";
}

/*====================================================================
 * parse configuration file
 */
	int 
xtr_parser_config(const char *filename)
{	
	xtr_ms = list_init();
	xtr_mr = list_init();
	xtr_petr = list_init();
	xml_configure(filename, xtr_startElement, xtr_endElement, xtr_getElementValue);
	_petr = NULL;
	if (xtr_petr->count > 0) {
		_petr = calloc(1, sizeof(struct db_node));
		_petr->info = list_init();
		struct map_entry *petr;
		struct list_entry_t *pt;
		pt = xtr_petr->head.next;
		while (pt != &xtr_petr->tail) {
			petr = calloc(1, sizeof(struct map_entry));
			petr->priority = 1;
			petr->weight = 100;
			petr->m_priority = 0;
			petr->m_weight = 0;
			petr->r = 1;
			petr->rloc = ((struct petr_entry *)(pt->data))->addr;
			generic_mapping_add_rloc(_petr, petr);
			pt = pt->next;
		}
	}
	return 0;
}	

	int 
ms_parser_config(const char *filename)
{
	xml_configure(filename, ms_startElement, ms_endElement, ms_getElementValue);
	return 0;
}	

	int 
mr_parser_config(const char *filename)
{	
	xml_configure(filename, mr_startElement, mr_endElement, mr_getElementValue);
	return 0;
}

	int 
node_parser_config(const char *filename)
{	
	xml_configure(filename, node_startElement, node_endElement, node_getElementValue);
	return 0;
}	
	int
rtr_parser_config(const char *filename)
{	
	xtr_mr = list_init();
	rloc_list = list_init();
	if (src_addr[0]) {
		rtr_entry = calloc(1, sizeof(struct map_entry));
		rtr_entry->rloc.sa.sa_family= AF_INET;
		memcpy(&rtr_entry->rloc.sin.sin_addr,src_addr[0],sizeof(struct in_addr));
		rtr_entry->priority= 1;
		rtr_entry->weight= 100;
		rtr_entry->m_priority= 0;
		rtr_entry->m_weight= 0;
		rtr_entry->L= 1;
		rtr_entry->p= 0;
		rtr_entry->r= 1;
		list_insert(rloc_list, rtr_entry, NULL);
	}
	
	if (src_addr[1]) {
		rtr_entry = calloc(1, sizeof(struct map_entry));
		rtr_entry->rloc.sa.sa_family= AF_INET;
		memcpy(&rtr_entry->rloc.sin.sin_addr,src_addr[1],sizeof(struct in_addr));
		rtr_entry->priority= 1;
		rtr_entry->weight= 100;
		rtr_entry->m_priority= 0;
		rtr_entry->m_weight= 0;
		rtr_entry->L= 1;
		rtr_entry->p= 0;
		rtr_entry->r= 1;
		list_insert(rloc_list, rtr_entry, NULL);
	}	
	
	xml_configure(filename, rtr_startElement, rtr_endElement, rtr_getElementValue);
	return 0;
}

/* parse the main configuration file and load extern config */
	int
_parser_config(const char *filename)
{
	char buf[BUFSIZ];
	FILE *config, *sconfig;
	int ln = 0;
	struct addrinfo	    hints;
    struct addrinfo	    *res;
	int e, sk;
	char _str_port[NI_MAXSERV];
	union sockunion my_ip;
	
	if ((config = fopen(filename, "r")) == NULL) {
		printf("Error Configure file: Can not open main configuration file %s\n",filename);
		cp_log(LLOG, "Error Configure file: Can not open main configuration file %s\n",filename);
		exit(1);
	}
	
	config_file[1] = config_file[2] = config_file[3] = config_file[4] = config_file[5] = NULL;
	src_addr[0] =  NULL;
	src_addr6[0] = NULL;
	min_thread = max_thread = PK_POOL_MAX = linger_thread = 0;
	
	while (fgets(buf, sizeof(buf), config) != NULL )
	{
		char data[50][255];
		char *token = buf;			
		char *tk;
		char *ptr;
		char *sep_t =  "\t ";
		int	i = 0; /*counter */
		ln++;
		
		if ((token[1] == '\0') || (token[0] == '#'))
			continue;	/*skip empty and comment line */
		
		i = 0;
		/*configure line: key  =  value */
		for (tk = strtok_r(buf, sep_t, &ptr); tk ; tk = strtok_r(NULL, sep_t, &ptr))
			strcpy(data[i++], tk);
				
		if (i < 3 || (i > 1 && strcasecmp(data[1],"=")!= 0 ) ) {
			printf("Error configure file : syntax error, at line: %d\n", ln);
			cp_log(LLOG, "Error configure file : syntax error, at line: %d\n", ln);
			exit(1);
		}
		
		/* skip \n in the end of last token */
		data[i-1][strlen(data[i-1])-1]='\0';
		
		if (0 == strcasecmp(data[0], "debug_level")) {
			if (strcasecmp(data[2], "default") !=0) {
				_debug = atoi(data[2]);
			}
			else{
				_debug = 1;
			}
		}
		
		if (0 == strcasecmp(data[0], "functions")) {
			while (--i > 1) {
				if (0 == strncasecmp(data[i],"xtr",3))
					_fncs = _fncs | _FNC_XTR;
									
				if (0 == strncasecmp(data[i],"ms",2))
					_fncs = _fncs |  _FNC_MS;
					
				if (0 == strncasecmp(data[i],"mr",2))
					_fncs = _fncs | _FNC_MR;
				
				if ((0 == strncasecmp(data[i],"ddt",3)) || (0 == strncasecmp(data[i],"node",4)))
					_fncs = _fncs | _FNC_NODE;

				if ((0 == strncasecmp(data[i],"rtr",3)) )
					_fncs = _fncs | _FNC_RTR;
					
			}
			if ((_fncs % 2 && _fncs > 1) || (_fncs > 16)) {
				printf("Error Configure file: xTR and RTR can not run as MS or MR or DDT_NODE, at line: %d\n", ln);
				cp_log(LLOG, "Error Configure file: xTR and RTR can not run as MS or MR or DDT_NODE, at line: %d\n", ln);
				exit(1);
			}
		}
		
		if (0 == strcasecmp(data[0], "source_ipv4") ) {
			if (strcasecmp(data[2], "auto") !=0) {
				sprintf(_str_port, "%d", LISP_CP_PORT);
				
				if ((sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
					perror("socket");
					exit(0);
				}
				
				memset(&hints, 0, sizeof(struct addrinfo));
				hints.ai_family    = AF_INET;	/* Bind on AF based on AF of Map-Server */
				hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
				hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
				hints.ai_protocol  = IPPROTO_UDP;
				if ((e = getaddrinfo((char *)data[2], _str_port, &hints, &res)) != 0) {
					fprintf(stderr, "Source IP address version 4 not correct: %s\n", gai_strerror(e));
					cp_log(LLOG,  "Source IP address version 4 not correct: %s\n", gai_strerror(e));
					exit(0);
				}
				src_addr[0] = calloc(1,sizeof(struct in_addr));
				memcpy(src_addr[0], &((struct sockaddr_in *)(res->ai_addr))->sin_addr, sizeof(struct in_addr));				
				close(sk);
			}
			else{
				if (get_my_addr(AF_INET,&my_ip) == 0) {
					src_addr[0] = calloc(1,sizeof(struct in_addr));
					memcpy(src_addr[0], &my_ip.sin.sin_addr, sizeof(struct in_addr));								
				}	
			}
		}	
		
		if (0 == strcasecmp(data[0], "source_ipv6")) {
			if (strcasecmp(data[2], "auto") !=0) {
				sprintf(_str_port, "%d", LISP_CP_PORT);
				
				if ((sk = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
					perror("socket6");
					exit(0);
				}
				
				memset(&hints, 0, sizeof(struct addrinfo));
				hints.ai_family    = AF_INET6;	/* Bind on AF based on AF of Map-Server */
				hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
				hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
				hints.ai_protocol  = IPPROTO_UDP;
				
				if ((e = getaddrinfo((char *)data[2], _str_port, &hints, &res)) != 0) {
					fprintf(stderr, "Source IP address version 6 not correct: %s\n", gai_strerror(e));
					cp_log(LLOG, "Source IP address version 6 not correct: %s\n", gai_strerror(e));
					exit(0);
				}
				src_addr6[0] = calloc(1,sizeof(struct in6_addr));
				memcpy(src_addr6[0], &((struct sockaddr_in6 *)(res->ai_addr))->sin6_addr, sizeof(struct in6_addr));	
			}
			else{
				if (get_my_addr(AF_INET6,&my_ip) == 0) {
					src_addr6[0] = calloc(1,sizeof(struct in6_addr));
					memcpy(src_addr6[0], &my_ip.sin6.sin6_addr, sizeof(struct in6_addr));		
				}
			}
		}
		
		if (0 == strcasecmp(data[0], "srcport_rand")) {
			if (strncasecmp(data[2], "yes",3) ==0)
				srcport_rand = 1;			
			else
				srcport_rand = 0;
		}
		
		if (0 == strcasecmp(data[0], "lisp_te")) {
			if (strncasecmp(data[2], "yes",3) ==0) {
				lisp_te = 1;
			}
		}
		if ((0 == strcasecmp(data[0], "queue_size"))) {
			if (strcasecmp(data[2], "default") !=0) {
				PK_POOL_MAX = atoi(data[2]);
			}
			else{
				PK_POOL_MAX = 1000;
			}					
		}
		
		if ((0 == strcasecmp(data[0], "min_thread"))) {
			if (strcasecmp(data[2], "default") !=0) {
				min_thread = atoi(data[2]);
			}
			else{
				min_thread = 1;			
			}
		}
		
		if ((0 == strcasecmp(data[0], "max_thread"))) {
			if (strcasecmp(data[2], "default") !=0) {
				max_thread = atoi(data[2]);
			}
			else{
				max_thread = 2;			
			}
		}
		/* max_thread must greater min_thread */
		
		if (min_thread && max_thread && (max_thread < min_thread) ) {
			printf("Error configure file: max_thread must greater min_thread, at line: %d\n", ln);
			cp_log(LLOG, "Error configure file: max_thread must greater min_thread, at line: %d\n", ln);
			exit(1);
		}
		if ((0 == strcasecmp(data[0], "linger_thread"))) {
			if (strcasecmp(data[2], "default") !=0) {
				linger_thread = atoi(data[2]);
			}
			else{
				linger_thread = 10;			
			}
		}
		
		if ((_fncs & _FNC_XTR ) && (0 == strcasecmp(data[0], "xtr_configure")) ) {
			config_file[1] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[1], data[2],strlen(data[2]));
			config_file[1][strlen(data[2])]='\0';			
			if ((sconfig = fopen(config_file[1], "r")) == NULL) {
				printf("Error configure file: can not open XTR configuration file, at line: %d\n",ln);
				cp_log(LLOG, "Error configure file: can not open XTR configuration file, at line: %d\n",ln);
				exit(1);
			}
			else{
				fclose(sconfig);
			}
		}
		
		if ((_fncs & _FNC_MS) && (0 == strcasecmp(data[0], "ms_configure")) ) {
			config_file[2] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[2], data[2],strlen(data[2]));
			config_file[2][strlen(data[2])]='\0';			
			if ((sconfig = fopen(config_file[2], "r")) == NULL) {
				printf("Error configure file: can not open MS configuration file, at line: %d\n",ln);
				cp_log(LLOG, "Error configure file: can not open MS configuration file, at line: %d\n",ln);
				exit(1);
			}
			else{
				fclose(sconfig);
			}
		}
		
		if ((_fncs & _FNC_MR  ) && (0 == strcasecmp(data[0], "mr_configure")) ) {
			config_file[3] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[3], data[2],strlen(data[2]));
			config_file[3][strlen(data[2])]='\0';
			if ((sconfig = fopen(config_file[3], "r")) == NULL) {
				printf("Error configure file: can not open MR configuration file, at line: %d\n",ln);
				cp_log(LLOG, "Error configure file: can not open MR configuration file, at line: %d\n",ln);
				exit(1);
			}
			else{
				fclose(sconfig);
			}			
		}
		
		if ((_fncs & _FNC_RTR) && (0 == strcasecmp(data[0], "rtr_configure")) ) {
			config_file[4] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[4], data[2],strlen(data[2]));
			config_file[4][strlen(data[2])]='\0';			
			if ((sconfig = fopen(config_file[4], "r")) == NULL) {
				printf("Error configure file: can not open RTR configuration file, at line: %d\n",ln);
				cp_log(LLOG, "Error configure file: can not open RTR configuration file, at line: %d\n",ln);
				exit(1);
			}
			else{
				fclose(sconfig);
			}
		}
		if ((_fncs & _FNC_NODE  ) && (0 == strcasecmp(data[0], "node_configure")) ) {
			config_file[5] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[5], data[2],strlen(data[2]));
			config_file[5][strlen(data[2])]='\0';
			if ((sconfig = fopen(config_file[5], "r")) == NULL) {
				printf("Error configure file: can not open NODE configuration file, at line: %d\n",ln);
				cp_log(LLOG, "Error configure file: can not open NODE configuration file, at line: %d\n",ln);
				exit(1);
			}
			else{
				fclose(sconfig);
			}			
		}		
	}
			
	if ((_fncs & _FNC_XTR)  && config_file[1]) {
		cp_log(LLOG, "Parser file:%s\n",config_file[1]);
		xtr_parser_config(config_file[1]);
	}
	
	if ((_fncs & _FNC_MS) && config_file[2]) {
		cp_log(LLOG, "Parser file:%s\n",config_file[2]);
		ms_parser_config(config_file[2]);
	}
	
	if ((_fncs & _FNC_MR) && config_file[3]) {
		cp_log(LLOG, "Parser file:%s\n",config_file[3]);
		mr_parser_config(config_file[3]);		
	}
	
	if ((_fncs & _FNC_RTR) && config_file[4]) {
		cp_log(LLOG, "Parser file:%s\n",config_file[4]);
		rtr_parser_config(config_file[4]);		
	}
	if ((_fncs & _FNC_NODE) && config_file[5]) {
		cp_log(LLOG, "Parser file:%s\n",config_file[5]);
		node_parser_config(config_file[5]);		
	}
	fclose(config);
	return 0;
}
