
#include "lib.h"
#include "plumbing.h"

uint32_t _forward_to_etr(void *data,struct db_node * rn);

/* support function */

/* create new mapping */

	void * 
generic_mapping_new(struct prefix * eid)
{
	struct db_node * rn;
	struct list_t * locs;
	struct db_table * table;
	
	table = ms_get_db_table(ms_db,eid);
	if(!table)
		return NULL;
		
	rn = db_node_get(table, eid);
	if(!rn){
		return (NULL);
	}

	locs = list_init();
	db_node_set_info(rn, locs);

	return ((void *)rn);
}

/* assign flags */
	int 
generic_mapping_set_flags(void * mapping, const struct mapping_flags * mflags)
{
	struct db_node * rn;
	uint8_t fns = 0;
	void * rsvd = NULL; 
	
	assert(mapping);
	rn = (struct db_node *)mapping;
		
	if(!(rn->flags))
		rn->flags = (struct mapping_flags *)calloc(1, sizeof(struct mapping_flags));
	else{
		fns = ((struct mapping_flags *)rn->flags)->range;
		rsvd = ((struct mapping_flags *)rn->flags)->rsvd;		
	}	
	
	memcpy(rn->flags, mflags, sizeof(struct mapping_flags));
	((struct mapping_flags *)rn->flags)->range = ((struct mapping_flags *)rn->flags)->range | fns;
	if(!mflags->rsvd)
		((struct mapping_flags *)rn->flags)->rsvd = rsvd;
	return (TRUE);
}

/* add rloc to mapping */
	int 
generic_mapping_add_rloc(void * mapping, struct map_entry * entry)
{
	struct db_node * rn;
	struct list_t * locs;

	assert(mapping);
	rn = (struct db_node *)mapping;
	locs = (struct list_t *)db_node_get_info(rn);

	assert(locs);

	list_insert(locs, entry, NULL);

	return (TRUE);
}

	int 
_request_ddt(void *data, struct communication_fct * fct, \
			struct db_node *rn)
{
	struct prefix eid;		/* requested EID prefix */
	union sockunion * best_rloc = NULL;	/* best rloc */
	uint8_t best_priority = 0xff;	/* priority of the best RLOC*/
	uint64_t nonce;
	uint32_t * nonce_ptr;		/* pointer to nonce ( cause network byte order) */
	struct list_entry_t * _iter;
	struct list_t * l = NULL;
	struct map_entry * e;
	union sockunion dst;		/* inner packet destination header */
	union sockunion itr;		/* ITR address*/
	uint16_t sport;			/* ITR source port */
	struct mapping_flags * mflags;
	int afi;
	struct pk_req_entry *pke = data;
	
	/* get the EID prefix to request */
	fct->request_get_eid(pke, &eid);
	/* consider the destination IP address of the inner packet to send as
	   the first EID in the requested EID prefix */
	bzero(&dst, sizeof(union sockunion));
	switch(eid.family){
		case AF_INET:
			dst.sin.sin_family = AF_INET;
			afi = AF_INET;
			memcpy(&dst.sin.sin_addr, &(eid.u.prefix4), sizeof(struct in_addr));
			break;
		case AF_INET6:
			dst.sin6.sin6_family = AF_INET6;
			afi = AF_INET6;
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
	nonce_ptr = (uint32_t *)&nonce;

	/* determine the RLOC of the DDT server to send a request to */
	/* get the RLOCs */
	l = (struct list_t *)db_node_get_info(rn);
	_iter = l->head.next;
	
	mflags = (struct mapping_flags *)rn->flags;
	
	if(!_iter){
		fct->referral_error(pke);
		return (FALSE);
	}
	/* negative reply */
	if(_iter == &l->tail){
		return (TRUE);
	}

	//int brloc = random() % l->count;
	int brloc = random() % 2;
	
	/* iterate over the rlocs */
	while(_iter != &l->tail){
		e = (struct map_entry*)_iter->data;
		/* current read RLOC better than the others */
		/* choose by best priority */
		if(e->priority <= best_priority){
			if(e->priority < best_priority || brloc){
				best_priority = e->priority;
				best_rloc = &e->rloc;
			}				
		}
		
		/* choose by random */
		//if(i++ == brloc){
		//	best_priority = e->priority;
		//	best_rloc = &e->rloc;
		//}
		_iter = _iter->next;
	}
	/* stop if no RLOC is available to send the request */
	if(best_priority == 0xff){
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
	 
	if( (rpk = fct->request_add(pke, 0, 1, \
			1, 0, 0, 0, 0, 0,\
			*nonce_ptr, *(nonce_ptr + 1),\
			&itr ,  &dst, sport,\
			&eid)) < 0 ){
		fct->referral_error(pke);
		return (FALSE);
	}
	
	if( (mflags->referral == LISP_REFERRAL_MS_REFERRAL+1) || \
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
		struct db_node * rn, struct prefix *pf, uint32_t ttl, uint8_t A, uint8_t act,uint8_t version, uint8_t incomplete ){
		
	struct mapping_flags * mflags;
	uint32_t iid;
	struct pk_req_entry *pke = data;
	struct pk_rpl_entry *rpk;
	
	/* create the referral container  */
	rpk = fct->referral_add(pke);
	mflags = rn->flags;
	if(mflags)
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
		struct db_node * rn){
	struct map_entry * e = NULL;
	struct list_entry_t * _iter;
	struct list_t * l = NULL;
	uint8_t act;
	struct mapping_flags * mflags = (struct mapping_flags *)rn->flags;
	struct pk_rpl_entry *rpk;
	struct pk_req_entry *pke = data;
	
	/* create the referral container  */
	rpk = fct->referral_add(pke);
	
	/* get the RLOCs and add each of them in the referral */
	l = (struct list_t *)db_node_get_info(rn);
	
	/* something bad happened */
	if(!(_iter = l->head.next)){
		fct->referral_error(pke);
		return (FALSE);
	}

	/* Create one record container to put the locators */
	if(!mflags->referral && ms_node_is_type(rn,_MAPP)){
		act = LISP_REFERRAL_MS_ACK;
	}
	else{
		act = mflags->referral-1;		
	}

	fct->referral_add_record(rpk, mflags->iid, &rn->p, mflags->ttl, 
								l->count, mflags->version, mflags->A, act, mflags->incomplete, 0);

	/* negative reply */
	if(_iter == &l->tail){
		fct->referral_terminate(rpk);
		return TRUE;
	}

	/* add each locator into the record */
	while(_iter != &l->tail){
		e = (struct map_entry*)_iter->data;

		fct->referral_add_locator(rpk, e);
		_iter = _iter->next;
	}

	fct->referral_terminate(rpk);

	return (TRUE);
}

/* make a negative map-reply */
	int 
_request_reply_negative(void *data, struct communication_fct * fct, \
		struct db_node * rn, struct prefix * pf, uint32_t ttl, uint8_t A, uint8_t act,	uint8_t version ){
	
	struct pk_req_entry *pke = data;
	struct pk_rpl_entry *rpk;
	
	if(_debug == LDEBUG){
		printf("Send Map-Reply to ITR\n");
	}	
	rpk = fct->reply_add(pke);
	if (rn){
		fct->reply_add_record(rpk, &rn->p, ttl, 0, version, A, act);
	}
	else if(pf) {
		fct->reply_add_record(rpk, pf, ttl, 0, version, A, act);
	}
	else {
		if(_debug == LDEBUG)	
			printf("Not process...ignore packet\n");		
		return (0);
	}
	
	fct->reply_terminate(rpk);
		
	return (TRUE);
}

/* make a map-reply */
	int 
_request_reply(void *data, struct communication_fct * fct, \
		struct db_node * rn, struct prefix * pf){
	struct map_entry * e = NULL;
	struct list_entry_t * _iter;
	struct list_t * l = NULL;
	struct pk_rpl_entry *rpk;
	struct pk_req_entry *pke = data;
	
	struct mapping_flags * mflags = (struct mapping_flags *)rn->flags;
	int pe;
	
	if(_debug == LDEBUG)	
		printf("Send Map-Reply to ITR\n");
		
	rpk = fct->reply_add(pke);

	/* get the RLOCs */
	
	l = (struct list_t *)db_node_get_info(rn);
	assert(l);
	_iter = l->head.next;
	if(!_iter){
		fct->reply_error(rpk);
		fct->reply_terminate(rpk);
		return (TRUE);
	}
	/*PCD*/
	if( (_fncs & _FNC_XTR) && lisp_te){
		while(_iter != &l->tail){
			e = (struct map_entry*)_iter->data;
			if(e->pe)
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
	/* negative reply */
	if(_iter == &l->tail){
		fct->reply_terminate(rpk);
		return (TRUE);
	}

	while(_iter != &l->tail){
		e = (struct map_entry*)_iter->data;

		fct->reply_add_locator(rpk, e);
		_iter = _iter->next;
	}

	fct->reply_terminate(rpk);
	return TRUE;	
}

/* processing with map-request - only MS|NODE|MR function*/
	int 
generic_process_request(void *data, struct communication_fct * fct){
	struct db_table * table;
	struct db_node * rn = NULL;
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
	if(is_ddt){
		/*function of {map-register-with-DDT|DDT-node}*/
		if(!rn){
			/*If the requested XEID did not match either a configured delegation or
				an authoritative XEID-prefix, then the request is dropped and a
				negative Map-Referral with action code NOT-AUTHORITATIVE is returned.
			*/	
			if(_fncs & _FNC_NODE){
				rt =  _request_referral_negative(pke, fct, node, &p, 0, 0, LISP_REFERRAL_NOT_AUTHORITATIVE, 0, 1);
				
			}				
			return (TRUE);
		}
		node = rn;
		if( !rn->flags || !((struct mapping_flags *)rn->flags)->range){
			node = ms_get_target(rn);
		}
		
		/* existing mapping for request */	
		if (ms_node_is_type(node, _MAPP)){
			/* not referral node, it must belong to MS */			
			if( !((struct mapping_flags *)node->flags)->referral){
				/* do ms function: reply or foward to ETR */
				if(_fncs & _FNC_MS){
					if(ms_node_is_proxy_reply(node)){
						rt = _request_reply(pke, fct, node, NULL);
						
						return (TRUE);
					}
					
					if(_debug == LDEBUG)	
						fprintf(OUTPUT_STREAM, "Forwarding to ETR\n");
						
					_request_referral(pke, fct, node);
					
					rt = _forward_to_etr(pke,node);	
						
					return (TRUE);
				}
				/*it not be here: it is not MS but is has normal mapping */
				return FALSE;
			}
			
			/* referral node, must belong to NODE or MR*/
			if ( _fncs & _FNC_NODE){
				/*Auth EID referral - return with map-referral*/				
				if( ((struct mapping_flags *)node->flags)->A ){					
					rt =  _request_referral(pke, fct, node);	
					return (TRUE);
				}else{
					while(node != table->top && 
							(!node->flags ||
							!((struct mapping_flags *)node->flags)->A))
						node = node->parent;			
					if(node == table->top){
						rt =  _request_referral_negative(pke, fct, node, &p, 0, 0, LISP_REFERRAL_NOT_AUTHORITATIVE, 0, 1);					
						return TRUE;
					}
					rt =  _request_referral(pke, fct, node);
					return TRUE;
				}				
			}
		}
		else{//not exist mapping
			if ( _fncs & _FNC_MS || _fncs & _FNC_NODE){
				/* node has type */
				while (node != table->top && 
						( !node->flags || 
						!( ((struct mapping_flags *)node->flags)->range & (_EID | _GEID | _GREID)) ))
					node = node->parent;
				
				if(node == table->top){
					rt =  _request_referral_negative(pke, fct, node, &p, 0, 0, LISP_REFERRAL_NOT_AUTHORITATIVE, 0, 1);
					return TRUE;
				}else{
					switch (((struct mapping_flags *)node->flags)->range){
						case _EID: /* EID not is registered */
							if ( _fncs & _FNC_MS){
								rt =  _request_referral_negative(pke, fct, node, &p, 60, 1, LISP_REFERRAL_MS_NOT_REGISTERED, 0, 1);	
								return TRUE;
							}
							break;
						case _GEID:/* EID not assign for any ETR */
							if ( _fncs & _FNC_MS){
								/* in ieft, this case is same as _EID, but it think TTL must longer*/
								rt =  _request_referral_negative(pke, fct, node, &p, 900, 1, LISP_REFERRAL_MS_NOT_REGISTERED, 0, 1);	
								return TRUE;
							}	
							break;
						case _GREID:/* EID not delegated */
							if ( _fncs & _FNC_NODE){
								rt = _request_referral_negative(pke, fct, rn, &p, 60, 0, LISP_REFERRAL_DELEGATION_HOLE,0, 1 );		
								return TRUE;	
							}
							break;						
					}
					/*can not here or database has problem */
					return FALSE;
				}
			}
		}	
		if(_debug == LDEBUG)	
			printf("Not process...ignore packet\n");
		return FALSE;
	}
	/* Received non DDT request */
	else{
		/*function of {map-resolver |map-register-with-no-DDD-function} */
		node = rn;		
		if(!(rn->flags) || !((struct mapping_flags *)rn->flags)->range){
			node = ms_get_target(rn);
		}
		
		if ( ms_node_is_type(node, _MAPP)){
			/* node is MAPP, must belong to MS */
			if( !ms_node_is_referral(node)){
				if(_fncs & _FNC_MS){
					if(ms_node_is_proxy_reply(node)){
						rt =  _request_reply(pke, fct, node, NULL);						
						return rt;
					}
					else{
						if(_debug == LDEBUG)
							fprintf(OUTPUT_STREAM, "Forwarding to ETR\n");
						
						rt = _forward_to_etr(pke,node);							
						return rt;	
					}				
				}
				return FALSE;
			}
			else{
				/* do MR function */
				if(_fncs & _FNC_MR){
					pending_request(pke, fct, node);					
					return 1;
				}
			}
		}
		else{/*node is not mapping */
			while (node != table->top && 
						( !node->flags || 
						!( ((struct mapping_flags *)node->flags)->range & (_EID | _GEID)) ))
				node = node->parent;
			if(_fncs & _FNC_MS){
				if(node == table->top)
					return FALSE;
				if ( ms_node_is_type(node,_EID))
					rt = _request_reply_negative(pke, fct, node, &p, 60, 1, 1, 0);	
				else
					rt = _request_reply_negative(pke, fct, node, &p, 900, 1, 1, 0);	
				return TRUE;					
			}
			if(_fncs & _FNC_MR){
				pending_request(pke, fct, node);					
				return TRUE;
			}
		}	
	}
	if(_debug == LDEBUG)	
		printf("Not process...ignore packet\n");
	return FALSE;			
}

/* processing with map-request for xTR */
	int 
xtr_generic_process_request(void *data, struct communication_fct * fct){
	struct db_table * table;
	struct db_node * rn = NULL;
	struct prefix p;
	struct db_node *node = NULL;
	int rt;
	struct pk_req_entry *pke = data;
	
	/* look for the eid */
	fct->request_get_eid(pke, &p);
	table = ms_get_db_table(ms_db,&p);
	rn = db_node_match_prefix(table, &p);
	
	if(pke->ecm){
		/*ETR received this packet from MS */
		if(!rn){
			/* this can not happen because ECM is forwared from MS to ETR
				it mean that MS has an old mapping of ETR
				drop packet and wait for MS timeout mapping or refesh
				with nex map-register from ETR
			*/
			return (FALSE);
		}
		node = rn;		
		if(!(rn->flags) || !((struct mapping_flags *)rn->flags)->range){
			node = ms_get_target(rn);
		}
		
		if ( ms_node_is_type(node, _MAPP_XTR)){
			rt = _request_reply(pke, fct, node, NULL);			
			return rt;
		}
		else{
			/* similar the case rn is NULL */			
			return (FALSE);
		}
	}else { /* ETR received packet from xTR or PxTR */
		/* process with SMR...?? */
		if(!rn){
			/*ITR has cached an old mapping. 
			Drop request and ITR will timeout and send map-request to mapping system
			*/			
			return (FALSE);
		}

		node = rn;
		if(!(rn->flags) || !((struct mapping_flags *)rn->flags)->range){
			node = ms_get_target(rn);
		}
			
		if ( ms_node_is_type(node, _MAPP_XTR)){
			rt = _request_reply(pke, fct, node, NULL);			
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
reconfigure(int signum){
	if (ms_db)
		ms_finish_db(ms_db);
	ms_db = ms_init_db();	
	printf("Init database ...\n\n");
	site_db = list_init();	
	etr_db = list_init();
	printf("Parse main configuration file ...\n\n");
	_parser_config(config_file[0]);	
}


/* main function */
	int 
main(int argc, char ** argv){
		
	if(argc == 2)
		config_file[0] = argv[1];
	else
		config_file[0] = "opencp.conf";
		
	signal(SIGHUP, reconfigure);
	reconfigure(SIGHUP);
	if(!udp_init_socket())
		exit(0);
	list_db(ms_db->lisp_db4);
	list_db(ms_db->lisp_db6);
	list_site(site_db);
	plumb(); 
	exit(EXIT_SUCCESS);
}
