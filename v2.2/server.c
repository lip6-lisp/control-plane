
#include "lib.h"
#include "plumbing.h"
uint32_t _forward_to_etr(uint32_t request_id,struct db_node * rn);

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


/* make DDT-map-request */

	int 
_request_ddt(uint32_t request_id, struct communication_fct * fct, \
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
	
	/* get the EID prefix to request */
	fct->request_get_eid(request_id, &eid);
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
			fct->referral_error(request_id);
			return (FALSE);
	}

	/* determine the ITR address */
	//fct->request_get_itr(request_id, &itr,);
	memcpy(&itr,&_pk_req_pool[request_id]->ih_si,sizeof(union sockunion));
	/* determine the ITR source port */
	fct->request_get_port(request_id, &sport);

	/* determine the nonce used by the ITR */
	fct->request_get_nonce(request_id, &nonce);
	nonce_ptr = (uint32_t *)&nonce;

	/* determine the RLOC of the DDT server to send a request to */
	/* get the RLOCs */
	l = (struct list_t *)db_node_get_info(rn);
	_iter = l->head.next;
	
	mflags = (struct mapping_flags *)rn->flags;
	
	if(!_iter){
		fct->referral_error(request_id);
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
		fct->referral_error(request_id);
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
	 uint32_t reply_id;
	 
	if( (reply_id = fct->request_add(request_id, 0, 1, \
			1, 0, 0, 0, 0, 0,\
			*nonce_ptr, *(nonce_ptr + 1),\
			&itr ,  &dst, sport,\
			&eid)) < 0 ){
		fct->referral_error(request_id);
		return (FALSE);
	}
	
	if( (mflags->referral == LISP_REFERRAL_MS_REFERRAL+1) || \
	    (mflags->referral == LISP_REFERRAL_MS_ACK+1) || \
		(_pk_req_pool[request_id]->hop++ > MTTL))
		fct->request_ddt_terminate(reply_id, best_rloc, 1);
	else
		fct->request_ddt_terminate(reply_id, best_rloc, 0);
	
	return (TRUE);
}

/* make a negative referral reply */
	int 
_request_referral_negative(uint32_t request_id, struct communication_fct *fct, \
		struct db_node * rn, struct prefix *pf, uint32_t ttl, uint8_t A, uint8_t act,uint8_t version, uint8_t incomplete ){
		
	uint32_t reply_id;
	struct mapping_flags * mflags;
	uint32_t iid;
	
	/* create the referral container  */
	reply_id = fct->referral_add(request_id);
	mflags = rn->flags;
	if(mflags)
		iid = mflags->iid;
	else
		iid = 0;
		
	fct->referral_add_record(reply_id, iid, pf, ttl, 0, version, A, act, incomplete, 0);

	fct->referral_terminate(reply_id);
	return (TRUE);	
}

/* make a map-referral reply */
	int 
_request_referral(uint32_t request_id, struct communication_fct *fct, \
		struct db_node * rn){
	struct map_entry * e = NULL;
	struct list_entry_t * _iter;
	struct list_t * l = NULL;
	uint8_t act;
	struct mapping_flags * mflags = (struct mapping_flags *)rn->flags;
	uint32_t reply_id;
	
	/* create the referral container  */
	reply_id = fct->referral_add(request_id);
	
	/* get the RLOCs and add each of them in the referral */
	l = (struct list_t *)db_node_get_info(rn);
	_iter = l->head.next;
	/* something bad happened */
	if(!_iter){
		fct->referral_error(reply_id);
		return (FALSE);
	}

	/* Create one record container to put the locators */
	if(!mflags->referral && ms_node_is_type(rn,_MAPP)){
		act = LISP_REFERRAL_MS_ACK;
	}
	else{
		act = mflags->referral-1;		
	}

	fct->referral_add_record(reply_id, mflags->iid, &rn->p, mflags->ttl, l->count, mflags->version, mflags->A, act, mflags->incomplete, 0);

	/* negative reply */
	if(_iter == &l->tail){
		fct->referral_terminate(reply_id);
		return (TRUE);
	}

	/* add each locator into the record */
	while(_iter != &l->tail){
		e = (struct map_entry*)_iter->data;

		fct->referral_add_locator(reply_id, e);
		_iter = _iter->next;
	}

	fct->referral_terminate(reply_id);

	return (TRUE);
}

/* make a negative map-reply */
	int 
_request_reply_negative(uint32_t request_id, struct communication_fct * fct, \
		struct db_node * rn, struct prefix * pf, uint32_t ttl, uint8_t A, uint8_t act,	uint8_t version ){
	uint32_t reply_id;
	
	printf("Send Map-Reply to ITR\n");
	reply_id = fct->reply_add(request_id);
	if (rn){
		fct->reply_add_record(reply_id, &rn->p, ttl, 0, version, A, act);
	}
	else if(pf) {
		fct->reply_add_record(reply_id, pf, ttl, 0, version, A, act);
	}
	else {
		printf("No process\n");
		return (0);
	}
	
	fct->reply_terminate(reply_id);
	fct->request_terminate(request_id);
	
	return (TRUE);
}

/* make a map-reply */
	int 
_request_reply(uint32_t request_id, struct communication_fct * fct, \
		struct db_node * rn, struct prefix * pf){
	struct map_entry * e = NULL;
	struct list_entry_t * _iter;
	struct list_t * l = NULL;
	uint32_t reply_id;
	
	struct mapping_flags * mflags = (struct mapping_flags *)rn->flags;
	
	printf("Send Map-Reply to ITR\n");
	reply_id = fct->reply_add(request_id);

	/* get the RLOCs */
	
	l = (struct list_t *)db_node_get_info(rn);
	assert(l);
	_iter = l->head.next;
	if(!_iter){
		fct->reply_error(reply_id);
		fct->reply_terminate(reply_id);
		fct->request_terminate(request_id);
		return (TRUE);
	}
	fct->reply_add_record(reply_id, &rn->p, mflags->ttl, l->count, mflags->version, mflags->A, mflags->act);

	/* negative reply */
	if(_iter == &l->tail){
		fct->reply_terminate(reply_id);
		fct->request_terminate(request_id);
		return (TRUE);
	}

	while(_iter != &l->tail){
		e = (struct map_entry*)_iter->data;

		fct->reply_add_locator(reply_id, e);
		_iter = _iter->next;
	}

	fct->reply_terminate(reply_id);
	fct->request_terminate(request_id);
	return (TRUE);	
}

/* processing with map-request */
	int 
generic_process_request(uint32_t request_id, struct communication_fct * fct){
	struct db_table * table;
	struct db_node * rn = NULL;
	struct prefix p;
	int is_ddt;
	struct db_node *node = NULL;
		
	/* look for the eid */
		
	//printf("get_eid::%d\n",fct->request_get_eid(request_id, &p));
	fct->request_get_eid(request_id, &p);
	table = ms_get_db_table(ms_db,&p);
	rn = db_node_match_prefix(table, &p);
			
	if(!rn){
		//printf("no mapping found\n");		
		_request_reply_negative(request_id, fct, rn, &p, 900, 0, 0,	0);
		fct->request_terminate(request_id);
		return (FALSE);
	}
	
	fct->request_is_ddt(request_id, &is_ddt);

	/* Received DDT request */
	if(is_ddt){
		//function of {map-register-with-DDT|DDT-node}
		node = rn;
		if( !rn->flags || !((struct mapping_flags *)rn->flags)->range){
			node = ms_get_target(rn);
		}
					
		if (ms_node_is_type(node, _MAPP)){
			if( ((struct mapping_flags *)node->flags)->referral && ((struct mapping_flags *)node->flags)->A){
				return _request_referral(request_id, fct, node);
			}
			if( !((struct mapping_flags *)node->flags)->referral){
				if(ms_node_is_proxy_reply(node))
					return _request_reply(request_id, fct, node, NULL);
				 else{
					 fprintf(OUTPUT_STREAM, "Forwarding to ETR\n");
					 return _forward_to_etr(request_id,node);					
				 }
			}
		}
		else{
			if ( ms_node_is_type(node,_EID) || ms_node_is_type(node,_GEID))
				return _request_referral_negative(request_id, fct, node, &p, 60, 1, LISP_REFERRAL_MS_NOT_REGISTERED, 0, 1);	
			else if ( ms_node_is_type(node,_GREID) )  
				return _request_referral_negative(request_id, fct, rn, &p, 60, 0, LISP_REFERRAL_DELEGATION_HOLE,0, 1 );				
			else
				return _request_reply_negative(request_id, fct, node, &p, 900, 0, LISP_REFERRAL_NOTE_AUTHORITATIVE, 0);		
		}	
		
		printf("Not process\n");
		return (0);
	}
	/* Received non DDT request */
	else{
		//function of {map-resolver |map-register-with-no-DDD-function}
		node = rn;
		
		if(!(rn->flags) || !((struct mapping_flags *)rn->flags)->range){
			node = ms_get_target(rn);
		}
			
		if ( ms_node_is_type(node, _MAPP)){
			if( !ms_node_is_referral(node)){
				if(ms_node_is_proxy_reply(node))
					return _request_reply(request_id, fct, node, NULL);
				 else{
					 fprintf(OUTPUT_STREAM, "Forwarding to ETR\n");
					 return _forward_to_etr(request_id,node);					
				 }				
			}
			else{
				return _request_ddt(request_id, fct, node);				
			}
		}
		else{
			if ( ms_node_is_type(node,_EID) || ms_node_is_type(node,_GEID)){
				return _request_reply_negative(request_id, fct, node, &p, 60, 1, LISP_REFERRAL_MS_NOT_REGISTERED, 0);	
			}
			else{
				if ( ms_node_is_type(node,_GREID) )  {
					return _request_reply_negative(request_id, fct, node, &p, 900, 0, LISP_REFERRAL_DELEGATION_HOLE, 0);
				}
				else
					return _request_reply_negative(request_id, fct, node, &p, 900, 0, LISP_REFERRAL_NOTE_AUTHORITATIVE, 0);		
			}
		}	
	}	
	printf("Not process\n");
	return (0);		
	
	assert(FALSE);
}

/* processing with map-request for xTR */
	int 
xtr_generic_process_request(uint32_t request_id, struct communication_fct * fct){
	struct db_table * table;
	struct db_node * rn = NULL;
	struct prefix p;
	struct db_node *node = NULL;
		
	/* look for the eid */
	fct->request_get_eid(request_id, &p);
	table = ms_get_db_table(ms_db,&p);
	rn = db_node_match_prefix(table, &p);
	//show_eid_info(rn);
	
	if(!rn){
		_request_reply_negative(request_id, fct, rn, &p, 900, 0, 0,	0);
		fct->request_terminate(request_id);
		return (FALSE);
	}

	node = rn;
	if(!(rn->flags) || !((struct mapping_flags *)rn->flags)->range){
		node = ms_get_target(rn);
	}
		
	if ( ms_node_is_type(node, _MAPP_XTR)){
		return _request_reply(request_id, fct, node, NULL);
	}
	else{
		return _request_reply_negative(request_id, fct, node, &p, 60, 1, LISP_REFERRAL_MS_NOT_REGISTERED, 0);	
	}
	return (TRUE);			
}

/* free function */

	void 
rem(void * e){
	free(e);
}


/* load configure file */

	void 
reconfigure(int signum){
	//printf("Update mapping table\n");
	if (ms_db)
		ms_finish_db(ms_db);
	ms_db = ms_init_db();	
	printf("Init database ...\n\n");
	site_db = list_init();
	printf("Init site list ...\n\n");
	etr_db = list_init();
	_parser_config(config_file[0]);
	
}


/* main function */
	int 
main(int argc, char ** argv){
		
	config_file[0] = "opencp.conf";
	if(!udp_init_socket())
		exit(0);
	signal(SIGHUP, reconfigure);
	reconfigure(SIGHUP);
	
	list_db(ms_db->lisp_db4);
	list_db(ms_db->lisp_db6);
	list_site(site_db);
	plumb(); 
	exit(EXIT_SUCCESS);
}
