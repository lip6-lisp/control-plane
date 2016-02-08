
#include <ctype.h>
#include <stdarg.h>

#include "lib.h"
#include "plumbing.h"

uint32_t _forward_to_etr(void *data,struct db_node *rn);
FILE *flog;
int _daemon;
/* support function */

/* create new mapping */

	void *
generic_mapping_new(struct prefix *eid)
{
	struct db_node *rn;
	struct list_t *locs;
	struct db_table *table;
	
	if (((table = ms_get_db_table(ms_db,eid)) == NULL) ||
		((rn = db_node_get(table, eid)) == NULL))
			return (NULL);
	
	locs = list_init();
	db_node_set_info(rn, locs);

	return ((void *)rn);
}

/* assign flags */
	int 
generic_mapping_set_flags(void *mapping, const struct mapping_flags *mflags)
{
	struct db_node *rn;
	uint8_t fns = 0;
	void *rsvd = NULL; 
	
	assert(mapping);
	rn = (struct db_node *)mapping;
		
	if (!(rn->flags)) {
		rn->flags = (struct mapping_flags *)calloc(1, sizeof(struct mapping_flags));
	}	
	else{
		fns = ((struct mapping_flags *)rn->flags)->range;
		rsvd = ((struct mapping_flags *)rn->flags)->rsvd;		
	}	
	
	memcpy(rn->flags, mflags, sizeof(struct mapping_flags));
		((struct mapping_flags *)rn->flags)->range = ((struct mapping_flags *)rn->flags)->range | fns;
	if (!mflags->rsvd)
		((struct mapping_flags *)rn->flags)->rsvd = rsvd;
	return (TRUE);
}

/* add rloc to mapping */
	int 
generic_mapping_add_rloc(void *mapping, struct map_entry *entry)
{
	struct db_node *rn;
	struct list_t *locs;

	assert(mapping);
	rn = (struct db_node *)mapping;
	locs = (struct list_t *)db_node_get_info(rn);

	assert(locs);

	list_insert(locs, entry, _insert_ip_ordered);

	return (TRUE);
}

/*y5er*/
/* assign peer prefix  */
	int
generic_mapping_set_peer(void *mapping, struct prefix *peer)
{
	struct db_node *rn;

	assert(mapping);
	rn = (struct db_node *)mapping;
	prefix_copy (&rn->peer, peer);

	return (TRUE);
}
/*y5er*/

	int 
_request_ddt(void *data, struct communication_fct *fct, \
			struct db_node *rn)
{
	struct prefix eid;		/* requested EID prefix */
	union sockunion *best_rloc = NULL;	/* best rloc */
	uint8_t best_priority = 0xff;	/* priority of the best RLOC*/
	uint64_t nonce;
	uint32_t *nonce_ptr;		/* pointer to nonce (cause network byte order) */
	struct list_entry_t *_iter;
	struct list_t *l = NULL;
	struct map_entry *e;
	union sockunion dst;		/* inner packet destination header */
	union sockunion itr;		/* ITR address*/
	uint16_t sport;			/* ITR source port */
	struct mapping_flags *mflags;
	struct pk_req_entry *pke = data;
	
	/* get the EID prefix to request */
	fct->request_get_eid(pke, &eid);
	/* consider the destination IP address of the inner packet to send as
	   the first EID in the requested EID prefix */
	bzero(&dst, sizeof(union sockunion));
	switch (eid.family) {
	case AF_INET:
		dst.sin.sin_family = AF_INET;
		memcpy(&dst.sin.sin_addr, &(eid.u.prefix4), sizeof(struct in_addr));
		break;
	case AF_INET6:
		dst.sin6.sin6_family = AF_INET6;
		memcpy(&dst.sin6.sin6_addr, &(eid.u.prefix6), sizeof(struct in6_addr));
		break;
	default:
		fct->referral_error(pke);
		return (FALSE);
	}

	/* determine the ITR address */
	memcpy(&itr,&pke->ih_si,sizeof(union sockunion));
	/* determine the ITR source port */
	fct->request_get_port(pke, &sport);

	/* determine the nonce used by the ITR */
	fct->request_get_nonce(pke, &nonce);
	nonce_ptr = (void *)&nonce;

	/* determine the RLOC of the DDT server to send a request to */
	/* get the RLOCs */
	l = (struct list_t *)db_node_get_info(rn);
	_iter = l->head.next;
	
	mflags = (struct mapping_flags *)rn->flags;
	
	if (!_iter) {
		fct->referral_error(pke);
		return (FALSE);
	}
	/* negative reply */
	if (_iter == &l->tail) {
		return (TRUE);
	}

	//int brloc = random() % l->count;
	int brloc = random() % 2;
	
	/* iterate over the rlocs */
	while (_iter != &l->tail) {
		e = (struct map_entry*)_iter->data;
		/* current read RLOC better than the others */
		/* choose by best priority */
		if (e->priority <= best_priority) {
			if (e->priority < best_priority || brloc) {
				best_priority = e->priority;
				best_rloc = &e->rloc;
			}				
		}
		
		/* choose by random */
		//if (i++ == brloc) {
		//	best_priority = e->priority;
		//	best_rloc = &e->rloc;
		//}
		_iter = _iter->next;
	}
	/* stop if no RLOC is available to send the request */
	if (best_priority == 0xff) {
		fct->referral_error(pke);
		return (FALSE);
	}

	/* create a DDT Map-Request */
	/* lcm flags: S=0, D=1
	 * Map-Request flags: A=1 M=0 P=0 S=0 p=0 s=0
	 * nonce
	 * inner packet src address: itr
	 * inner packet dst address: eid-prefix
	 * inner packet source port: sport
	 * EID prefix: eid
	 */
	 struct pk_rpl_entry *rpk;
	 
	if ((rpk = fct->request_add(pke, 0, 1, \
			1, 0, 0, 0, 0, 0,\
			*nonce_ptr, *(nonce_ptr + 1),\
			&itr ,  &dst, sport,\
			&eid)) == NULL ) {
		fct->referral_error(pke);
		return (FALSE);
	}
	
	if ((mflags->referral == LISP_REFERRAL_MS_REFERRAL+1) || \
	    (mflags->referral == LISP_REFERRAL_MS_ACK+1) || \
		(pke->hop++ > MTTL))
		fct->request_ddt_terminate(rpk, best_rloc, 1);
	else
		fct->request_ddt_terminate(rpk, best_rloc, 0);
	
	return (TRUE);
}

/* make a negative referral reply */
	int 
_request_referral_negative(void *data, struct communication_fct *fct, \
		struct db_node *rn, struct prefix *pf, uint32_t ttl, uint8_t A, uint8_t act,uint8_t version, uint8_t incomplete )
{		
	struct mapping_flags *mflags;
	uint32_t iid;
	struct pk_req_entry *pke = data;
	struct pk_rpl_entry *rpk;
	
	/* create the referral container  */
	rpk = fct->referral_add(pke);
	mflags = rn->flags;
	if (mflags)
		iid = mflags->iid;
	else
		iid = 0;
		
	fct->referral_add_record(rpk, iid, pf, ttl, 0, version, A, act, incomplete, 0);

	fct->referral_terminate(rpk);
	return (TRUE);	
}

/* make a map-referral reply */
	int 
_request_referral(void *data, struct communication_fct *fct, \
		struct db_node *rn)
{
	struct map_entry *e = NULL;
	struct list_entry_t *_iter;
	struct list_t *l = NULL;
	uint8_t act;
	struct mapping_flags *mflags = (struct mapping_flags *)rn->flags;
	struct pk_rpl_entry *rpk;
	struct pk_req_entry *pke = data;
	
	/* create the referral container  */
	rpk = fct->referral_add(pke);
	
	/* get the RLOCs and add each of them in the referral */
	l = (struct list_t *)db_node_get_info(rn);
	
	/* something bad happened */
	if (!(_iter = l->head.next)) {
		fct->referral_error(pke);
		return (FALSE);
	}

	/* Create one record container to put the locators */
	if (!mflags->referral && ms_node_is_type(rn,_MAPP)) {
		act = LISP_REFERRAL_MS_ACK;
	}
	else{
		act = mflags->referral-1;		
	}

	fct->referral_add_record(rpk, mflags->iid, &rn->p, mflags->ttl, 
								l->count, mflags->version, mflags->A, act, mflags->incomplete, 0);

	/* negative reply */
	if (_iter == &l->tail) {
		fct->referral_terminate(rpk);
		return TRUE;
	}

	/* add each locator into the record */
	while (_iter != &l->tail) {
		e = (struct map_entry*)_iter->data;

		fct->referral_add_locator(rpk, e);
		_iter = _iter->next;
	}

	fct->referral_terminate(rpk);

	return (TRUE);
}

/* make a negative map-reply */
	int 
_request_reply_negative(void *data, struct communication_fct *fct, \
		struct db_node *rn, struct prefix *pf, uint32_t ttl, uint8_t A, uint8_t act,	uint8_t version )
{	
	struct pk_req_entry *pke = data;
	struct pk_rpl_entry *rpk;
	
	cp_log(LDEBUG, "Send Map-Reply to ITR\n");
		
	rpk = fct->reply_add(pke);
	if (rn) {
		fct->reply_add_record(rpk, &rn->p, ttl, 0, version, A, act);
	}
	else if (pf) {
		fct->reply_add_record(rpk, pf, ttl, 0, version, A, act);
	}
	else {
		cp_log(LDEBUG, "Not process...ignore packet\n");		
		return (0);
	}
	
	fct->reply_terminate(rpk);
		
	return (TRUE);
}

/* make a map-reply */
	int 
_request_reply(void *data, struct communication_fct *fct, \
		struct db_node *rn)
{
	struct map_entry *e = NULL;
	struct list_entry_t *_iter;
	struct list_t *l = NULL;
	struct pk_rpl_entry *rpk;
	struct pk_req_entry *pke = data;
	struct list_t *overlap;
	struct list_entry_t *nptr;
	
	struct mapping_flags *mflags = (struct mapping_flags *)rn->flags;
	int pe=0;
	
	cp_log(LDEBUG, "Send Map-Reply to ITR\n");
	/* y5er */
	// check the source eid belonging to peer our not
	/*
    if (pke->seid)
    {
    	char buff[512];
    	bzero(buff,512);
    	inet_ntop(AF_INET,(void *)&pke->seid,buff,512);
    	cp_log(LDEBUG, " source eid of the request is %s \n",buff);
    }
	*/
	/* y5er */
	rpk = fct->reply_add(pke);
	
	/*PCD */
	overlap = list_init();
	ms_get_tree(rn,overlap,_MAPP|_MAPP_XTR);
	nptr = overlap->head.next;
	while (nptr != &overlap->tail) {
		rn = (struct db_node *)nptr->data;
		/* get the RLOCs */
		l = (struct list_t *)db_node_get_info(rn);
		assert(l);
		_iter = l->head.next;
		pe = 0;
		if ((_fncs & (_FNC_XTR | _FNC_MS)) && lisp_te) {
			while (_iter != &l->tail) {
				e = (struct map_entry*)_iter->data;
				if (e->pe)
					pe += e->pe->count; 
				else 
					pe++;
				_iter = _iter->next;
			}
			fct->reply_add_record(rpk, &rn->p, mflags->ttl, pe, mflags->version, mflags->A, mflags->act);
		}
		else
			fct->reply_add_record(rpk, &rn->p, mflags->ttl, l->count, mflags->version, mflags->A, mflags->act);
		
		_iter = l->head.next;
		while (_iter != &l->tail) {
			e = (struct map_entry*)_iter->data;

			fct->reply_add_locator(rpk, e);
			_iter = _iter->next;
		}
		nptr = nptr->next;
	}
	fct->reply_terminate(rpk);
	return TRUE;	
}

/* when request EID (REID) match an negative node (NEGA_NODE)
 * reply contain an EID which
 * less-specific than REID
 * more-specific than NEGA_NODE
 * not overlap any child of NEGA_NODE
 */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */
 
	int
get_hole_eid(struct prefix *rs, 
			 struct db_node *nega_node, struct prefix *pf)
{
	uint8_t *res_addr, *left_addr, *right_addr, *ptr;
	uint8_t start, end, c, offset, shift;
	u_char upbit[] = {0x1, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2};
	res_addr = &pf->u.prefix;
	left_addr = right_addr = NULL;
	
	/* debug */
	// inet_ntop(nega_node->p.family, &nega_node->p.u.prefix, ip, INET6_ADDRSTRLEN);
	// printf("main node:%s/%d\n",ip, nega_node->p.prefixlen);
	// if (nega_node->l_left) {
		// inet_ntop(nega_node->l_left->p.family, &nega_node->l_left->p.u.prefix, ip, INET6_ADDRSTRLEN);
		// printf("left node:%s/%d\n",ip, nega_node->l_left->p.prefixlen);
	// }
	// if (nega_node->l_right) {
		// inet_ntop(nega_node->l_right->p.family, &nega_node->l_right->p.u.prefix, ip, INET6_ADDRSTRLEN);
		// printf("right node:%s/%d\n",ip, nega_node->l_right->p.prefixlen);
	// }
	// inet_ntop(pf->family, &pf->u.prefix, ip, INET6_ADDRSTRLEN);
	// printf("search node:%s/%d\n",ip, pf->prefixlen);
	/* end debug */
	
	start = nega_node->p.prefixlen;
	end = pf->prefixlen;
	offset = start / PNBBY;
	shift = start % PNBBY;
	
	if (nega_node->l_left) {
		left_addr = &nega_node->l_left->p.u.prefix;
		left_addr = left_addr + offset;
		if (nega_node->l_left->p.prefixlen > end)
			end = nega_node->l_left->p.prefixlen;
	}
	
	if (nega_node->l_right) {
		right_addr = &nega_node->l_right->p.u.prefix;
		right_addr = right_addr + offset;
		if (nega_node->l_right->p.prefixlen > end)
			end = nega_node->l_right->p.prefixlen;			
	}	
		
	/* compare pf and pf of two children of nega_node from
	 * nega_node prefix until prefix of pf or not match any more
	 */
	if (left_addr || right_addr) {
		for (c = start+1; c <= end; c++) {
			if (left_addr && (upbit[c % PNBBY] & (*res_addr ^ *left_addr)))
				left_addr = NULL;
			
			if (right_addr && (upbit[c % PNBBY] & (*res_addr ^ *right_addr)))
					right_addr = NULL;	
			
			if (!left_addr && !right_addr)
					break;
			
			if (c > start+1 && (c % PNBBY == 0)) {
				res_addr = res_addr + 1;
				if (left_addr)
					left_addr = left_addr + 1;
				if (right_addr)
					right_addr = right_addr + 1;
			}
		}
	
		if (c <= end) {
			*rs = *pf;		
			ptr = &(rs->u.prefix) + (c / PNBBY);
			*ptr = *ptr & maskbit[c % PNBBY];
			offset = (rs->prefixlen -c) / PNBBY;
			if (offset)
				ptr = ptr+1;
			while (offset--) {
				*ptr = 0;
				ptr = ptr+1;
			}
			rs->prefixlen = c;
			return (0);
		}
	}else{
		*rs = nega_node->p;
		return (0);
	}	
	return 1;
}	

/* processing with map-request - only MS|NODE|MR function*/
	int 
generic_process_request(void *data, struct communication_fct *fct)
{
	struct db_table *table;
	struct db_node *rn = NULL;
	struct prefix p;
	int is_ddt;
	struct db_node *node = NULL;	
	int rt;
	struct pk_req_entry *pke = data;
		
	/* look for the eid */
	fct->request_get_eid(pke, &p);
	table = ms_get_db_table(ms_db,&p);
	rn = db_node_match_prefix(table, &p);
			
	fct->request_is_ddt(pke, &is_ddt);

	/* Received DDT request */
	if (is_ddt) {
		/*function of {map-register-with-DDT|DDT-node}*/
		if (!rn) {
			/* never happen: at least it must match with root node */				
			return (TRUE);
		}
		
		node = rn;
		/* for case eid overlap */
		if (!rn->flags || !((struct mapping_flags *)rn->flags)->range) {
			node = ms_get_target(rn);
		}
		
		 
		/* existing mapping for request */	
		if (ms_node_is_type(node, _MAPP)) {
			/* not referral node, it must belong to MS */			
			if (!ms_node_is_referral(node)) {
				/* do ms function: reply or foward to ETR */
				if (_fncs & _FNC_MS) {
					if (ms_node_is_proxy_reply(node)) {
						rt = _request_reply(pke, fct, node);
						
						return (TRUE);
					}
					
					cp_log(LDEBUG, "Forwarding to ETR\n");
						
					_request_referral(pke, fct, node);
					
					rt = _forward_to_etr(pke,node);	
						
					return (TRUE);
				}
				/*it not be here: it is not MS but is has normal mapping */
				return FALSE;
			}
			
			/* referral node, must belong to NODE or MR (caching referral)*/
			if (_fncs & _FNC_NODE) {
				/*Auth EID referral - return with map-referral*/				
				if (((struct mapping_flags *)node->flags)->A ) {					
					rt =  _request_referral(pke, fct, node);	
					return (TRUE);
				}else{
					/*If the requested XEID did not match either a configured delegation or
					 *	an authoritative XEID-prefix, then the request is dropped and a
					 * negative Map-Referral with action code NOT-AUTHORITATIVE is returned.
					 */
					get_hole_eid(&p, rn, &p); 
					rt =  _request_referral_negative(pke, fct, rn, &p, 0, 0, LISP_REFERRAL_NOT_AUTHORITATIVE, 0, 1);					
					return (TRUE);
				}				
			}
		}
		else{/* not exist mapping */
			if (_fncs & _FNC_MS || _fncs & _FNC_NODE) {
				/* node has type */
				while (node != table->top && 
						(!node->flags || 
						!(((struct mapping_flags *)node->flags)->range & (_EID | _GEID | _GREID)) ))
					node = node->parent;
				
				if (node == table->top) {
					get_hole_eid(&p, rn, &p); 
					if (node->flags && ms_node_is_type(node, _GEID | _GREID))
						rt = _request_referral_negative(pke, fct, rn, &p, 15, 0, LISP_REFERRAL_DELEGATION_HOLE,0, 1 );		
					else
						rt =  _request_referral_negative(pke, fct, rn, &p, 0, 0, LISP_REFERRAL_NOT_AUTHORITATIVE, 0, 1);
					return TRUE;
				}else{
					switch (((struct mapping_flags *)node->flags)->range) {
						case _EID: /* EID not is registered */
							if (_fncs & _FNC_MS) {
								get_hole_eid(&p, rn, &p); 
								rt =  _request_referral_negative(pke, fct, rn, &p, 1, 1, LISP_REFERRAL_MS_NOT_REGISTERED, 0, 1);	
								return TRUE;
							}
							break;
						case _GEID:/* EID not assign for any ETR */
							if (_fncs & _FNC_MS) {
								/* in ieft, this case is same as _EID, but I think TTL must longer*/
								get_hole_eid(&p, rn, &p); 
								rt =  _request_referral_negative(pke, fct, rn, &p, 15, 1, LISP_REFERRAL_DELEGATION_HOLE, 0, 1);	
								return TRUE;
							}	
							break;
						case _GREID:/* EID not delegated */
							if (_fncs & _FNC_NODE) {
								get_hole_eid(&p, rn, &p); 
								rt = _request_referral_negative(pke, fct, rn, &p, 15, 0, LISP_REFERRAL_DELEGATION_HOLE,0, 1 );		
								return TRUE;	
							}
							break;						
					}
					/*can not here or database has problem */
					return FALSE;
				}
			}
		}	
		cp_log(LDEBUG, "Not process...ignore packet\n");
		return FALSE;
	}
	/* Received non DDT request */
	else{
		/*function of {map-resolver |map-register-with-no-DDD-function} */
		node = rn;		
		if (!(rn->flags) || !((struct mapping_flags *)rn->flags)->range) {
			node = ms_get_target(rn);
		}
		
		if (ms_node_is_type(node, _MAPP)) {
			/* node is MAPP, must belong to MS */
			if (!ms_node_is_referral(node)) {
				if (_fncs & _FNC_MS) {
					if (ms_node_is_proxy_reply(node)) {
						rt = _request_reply(pke, fct, node);
																	
						return rt;
					}
					else{
						cp_log(LDEBUG, "Forwarding to ETR\n");
						
						rt = _forward_to_etr(pke,node);							
						return rt;	
					}				
				}
				return FALSE;
			}
			else{
				/* do MR function */
				if (_fncs & _FNC_MR) {
					pending_request(pke, fct, node);					
					return 2;
				}
			}
		}
		else{/*node is not mapping */
			while (node != table->top && 
						(!node->flags || 
						!(((struct mapping_flags *)node->flags)->range & (_EID | _GEID)) ))
				node = node->parent;
			if (_fncs & _FNC_MS) {
				if (node == table->top)
					return FALSE;
				get_hole_eid(&p, rn, &p); 	
				if (ms_node_is_type(node,_EID))
					rt = _request_reply_negative(pke, fct, node, &p, 60, 1, 1, 0);	
				else
					rt = _request_reply_negative(pke, fct, node, &p, 900, 1, 1, 0);	
				return TRUE;					
			}
			if (_fncs & _FNC_MR) {
				pending_request(pke, fct, node);					
				return 2;
			}
		}	
	}
	cp_log(LDEBUG, "Not process...ignore packet\n");
	return FALSE;			
}

/* processing with map-request for xTR */
	int 
xtr_generic_process_request(void *data, struct communication_fct *fct)
{
	struct db_table *table;
	struct db_node *rn = NULL;
	struct prefix p;
	struct db_node *node = NULL;
	int rt;
	struct pk_req_entry *pke = data;
	
	/* look for the eid */
	fct->request_get_eid(pke, &p);
	table = ms_get_db_table(ms_db,&p);
	rn = db_node_match_prefix(table, &p);
	
	if (pke->ecm) {
		/*ETR received this packet from MS */
		if (!rn) {
			/* this can not happen because ECM is forwared from MS to ETR
				it mean that MS has an old mapping of ETR
				drop packet and wait for MS timeout mapping or refesh
				with nex map-register from ETR
			*/
			return (FALSE);
		}
		node = rn;		
		if (!(rn->flags) || !((struct mapping_flags *)rn->flags)->range) {
			node = ms_get_target(rn);
		}
		/* y5er */
		cp_log(LLOG, "xtr generic process request \n");
		/* y5er */
		if (ms_node_is_type(node, _MAPP_XTR)) {
			rt = _request_reply(pke, fct, node);			
			return rt;
		}
		else{
			/* similar the case rn is NULL */			
			return (FALSE);
		}
	}else { /* ETR received packet from xTR or PxTR */
		/* process with SMR...?? */
		if (!rn) {
			/*ITR has cached an old mapping. 
			Drop request and ITR will timeout and send map-request to mapping system
			*/			
			return (FALSE);
		}

		node = rn;
		if (!(rn->flags) || !((struct mapping_flags *)rn->flags)->range) {
			node = ms_get_target(rn);
		}
			
		if (ms_node_is_type(node, _MAPP_XTR)) {
			rt = _request_reply(pke, fct, node);			
			return rt;
		}
		else{
			/* similar the case rn is NULL */	
			return(FALSE);
		}		
	}		
	return (FALSE);			
}

/* load configure file */

	void 
reconfigure()
{
	if (ms_db)
		ms_finish_db(ms_db);
	ms_db = ms_init_db();	
	printf("Init database ...\n\n");
	cp_log(LLOG, "Init database ...\n\n");
	site_db = list_init();	
	etr_db = list_init();
	printf("Parse main configuration file ...\n\n");
	cp_log(LLOG, "Parse main configuration file ...\n\n");
	_parser_config(config_file[0]);	
}


/* main function */
	void 
reopenlog()
{
	FILE *fd;

	fd = freopen("/var/log/opencp.log","a",flog);
	flog = fd;
}

	void 
cp_log(int level, char *format, ...)
{
	va_list args;
	
	if (_debug >= level) {
		va_start(args, format);
		if (flog != NULL) {
			vfprintf(flog, format, args);
			fflush(flog);
		}	
		else
			vfprintf(OUTPUT_STREAM, format, args);
		va_end(args);
	}	
}

	int 
main(int argc, char **argv)
{		
	config_file[0] = "opencp.conf";
	int c;
	opterr = 0;
	_daemon = 0;
	while ((c = getopt (argc, argv, "df:")) != -1) {
		switch (c) {
		case 'd':
			_daemon = 1;
			break;
		case 'f':
			config_file[0] = optarg;
			break;
		case '?':
			if (optopt == 'f')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
				fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
            return 1;
        default:
            abort ();
        }
	}
	
	if (_daemon) {
		pid_t pid;
 
		/* Clone child from ourselves */  
		pid = fork(); 
		
		if (pid < 0) {
			exit(EXIT_FAILURE);
		}
		
		/* pid > 0, we are the parent, exit */
		if (pid > 0) {
			exit(EXIT_SUCCESS);
		}
 		/* now I'm child */
		FILE *fpid;
		pid = getpid();
		printf("my pid is %d\n",pid);
		fpid = fopen("/var/run/opencp.pid", "w");
		
		fprintf(fpid,"%d",pid);
		fclose(fpid);
	}
	
	if (_daemon) {
		flog = fopen("/var/log/opencp.log","a");
		signal(SIGUSR1, reopenlog);
	}else{
		flog = NULL;
	}
	
	//signal(SIGHUP, reconfigure);
	reconfigure(SIGHUP);
	if (!udp_init_socket())
		exit(0);
	if (_daemon) {
		fflush(stdout);
		close(STDOUT_FILENO);
		close(STDIN_FILENO);
		close(STDERR_FILENO);
	}
	
	list_db(ms_db->lisp_db4);
	list_db(ms_db->lisp_db6);
	list_site(site_db);
	plumb(); 
	fclose(flog);
	exit(EXIT_SUCCESS);
}
