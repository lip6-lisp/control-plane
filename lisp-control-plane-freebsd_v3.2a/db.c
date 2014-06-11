
#include "lib.h"

struct lisp_db * ms_db = NULL;
struct list_t * site_db;
struct list_t * etr_db;
struct list_t * xtr_ms;
struct list_t * xtr_mr;
struct in_addr *src_addr[MIF];
struct in6_addr *src_addr6[MIF];
struct db_table * table;

	void 
ms_free_node(void * node)
{
	struct db_node * nd;
	
	if(node){
			
		nd = (struct db_node *)node;
		if(nd->flags)
			free(nd->flags);
		if(nd->info)
			free(nd->info);
		free(node);
	}
}

	struct lisp_db * 
ms_init_db()
{
	struct prefix p;
	struct db_node * dn;
	struct lisp_db * db;
	db = calloc(1, sizeof(struct lisp_db));
	
	//make new tree 
	db->lisp_db4 = db_table_init(&ms_free_node);
	db->lisp_db6 = db_table_init(&ms_free_node);

	//assign 0.0.0.0/0 as root of ipv4 tree
	str2prefix("0.0.0.0/0",&p);
	apply_mask(&p);
	dn = db_node_get(db->lisp_db4,&p);
	assert(dn == (db->lisp_db4->top));
	dn->flags = ms_new_node_ex(_ROOT);
		
	//and 0::/0 as root of ipv6 tree
	str2prefix("0::/0",&p);
	apply_mask(&p);
	dn = db_node_get(db->lisp_db6,&p);
	assert( dn == (db->lisp_db6->top));
	dn->flags = ms_new_node_ex(_ROOT);
	
	return db;
}


	void 
ms_finish_db(struct lisp_db *db)
{
	db_table_finish(db->lisp_db4);
	db_table_finish(db->lisp_db6);
	free(db);
}

	struct site_info * 
ms_new_site_info()
{
	struct site_info *rt;
	
	rt = calloc(1, sizeof(struct site_info));
	rt->name = NULL;
	rt->key = NULL;
	rt->contact = NULL;
	rt->active = _ACTIVE;
	rt->hashing = NULL;
	rt->eid = list_init();
	return rt;
}

	
	struct list_entry_t * 
ms_new_site(struct list_t * l_site)
{
	struct site_info * site_info;
	struct list_entry_t * rt;
	
	site_info = ms_new_site_info();
	rt = list_insert(l_site, site_info, NULL);	
	return rt;
}

	struct mapping_flags 
* ms_new_node_ex(u_char n_type)
{
	struct mapping_flags * rt;
	
	rt = calloc(1, sizeof(struct mapping_flags));
	bzero(rt,sizeof(struct mapping_flags));
	rt->range = n_type;
	rt->active = _ACTIVE;
	rt->rsvd = NULL;
	return rt;
}

	void 
ms_node_update_type(struct db_node * node, u_char n_type)
{
	assert(node);
	if (node->flags == NULL)
		node->flags = ms_new_node_ex(n_type);
	else{
		((struct mapping_flags *)node->flags)->range |= n_type;		
	}
	
}

	u_char 
ms_node_is_type(struct db_node * node, u_char n_type)
{
	assert(node);
	return ( node->flags && ( ((struct mapping_flags *)node->flags)->range & n_type));
}

	u_char 
ms_node_is_referral(struct db_node * node)
{
	assert(node);
	return ( node->flags &&  ((struct mapping_flags *)node->flags)->referral);	
}

	u_char 
ms_node_is_proxy_reply(struct db_node * node)
{
	assert(node);
	return ( node->flags &&  ((struct mapping_flags *)node->flags)->proxy);	
}


	struct db_table * 
ms_get_db_table(const struct lisp_db * db, struct prefix * pf)
{
	assert(pf);
	if (pf->family == AF_INET){
		return db->lisp_db4;
	}
	else if(pf->family == AF_INET6){
		return db->lisp_db6;
	}
	cp_log(LDEBUG,"AF_NOT_SUPPORT\n");
	
	return NULL;	
}

	struct db_node * 
ms_get_target(struct db_node * node)
{
	while( (!node->flags || !((struct mapping_flags *)node->flags)->range) && (node != node->table->top)){
		node = node->parent;
	}
	return node;
}

/* find all node matched special tag in tree */
	int 
ms_get_tree(struct db_node * node, struct list_t *rt, int flag)
{
	if(!node)
		return 0;
	if(ms_node_is_type(node, flag))
		list_insert(rt,node,NULL);
	ms_get_tree(node->l_left,rt,flag);
	ms_get_tree(node->l_right,rt,flag);
	return rt->count;
}

//=================================================================
//debug function
	void  
node_type2_str(struct db_node * rn, char * buf)
{
	
	char * node_type[33];
	u_char n_type;
	u_char tmp = 1;
	uint8_t  i;
	uint8_t len=0;
	
	node_type[0] = "ROOT";
	node_type[1] = "MAPP";
	node_type[2] = "MAPP_xTR";
	node_type[4] = "EID";
	node_type[8] = "GEID";
	node_type[16] = "GREID";
	node_type[32] = "TMP";
	
	if(!rn->flags){
		memcpy(buf,node_type[32],strlen(node_type[32])+1);		
		return;
	}
	
	n_type = ((struct mapping_flags *)rn->flags)->range;
	len = 0;
	i = 1;
	if(!n_type){
		memcpy(buf,node_type[0],strlen(node_type[0])+1);		
		return;
	}
	
	while (n_type){
		
		if(n_type & tmp){
			if(len){
				buf[len] = '|';
				len++;
			}	
			memcpy((char *)buf+len,node_type[i], strlen(node_type[i]));
			len += strlen(node_type[i]);
			
		}
		n_type = n_type >> 1;
		i = i*2;
	}
	
	buf[len] = '\0';		
}
#define _LEFT 0
#define _RIGHT 1
#define _CENTER 2

	void 
list_db(struct db_table * db)
{
	struct db_node *rn;
	static struct pool_node {
		int n_direct;
		struct db_node * link2node;
	} node_list[50000];
	char * sref[7];
	sref[1] = "NODE";
	sref[2] = "MS";
	sref[3] = "MS_ACK";
	sref[4] = "MS_NOT_REGISTERED";
	sref[5] = "DELEGATION_HOLE";
	sref[6] = "NOTE_AUTHORITATIVE";

	int i = 0;
	int j = 0;
	int k;
	int count_list = 0;
	int trdeep[50000];
	assert(db);
	assert(db->top);
	
	rn = db->top;
	for (i = 0; i<50000 ;i++ ) {
		node_list[i].link2node = NULL;		
	}
	
	node_list[count_list++].link2node = rn;
	node_list[count_list].n_direct = _CENTER;
	for (i = 0; i<50000; i++)
		trdeep[i] = 0;
		
	trdeep[count_list] = 0;
	while (rn != NULL) {
		k = trdeep[j]+1;
		if (rn->l_left != NULL) {
			node_list[count_list].link2node = rn->l_left;
			node_list[count_list++].n_direct = _LEFT;
			trdeep[count_list]=k;
		}
		if (rn->l_right != NULL) {
			node_list[count_list].link2node = rn->l_right;
			node_list[count_list++].n_direct = _RIGHT;
			trdeep[count_list]=k;
		}
		rn = node_list[++j].link2node;
	}
	int deep = 0;
	int deep_avg = 0;
	for (i = 0; i < 50000; i++){
		if(trdeep[i] > 0){
			deep_avg += trdeep[i];
		}
			
		if (deep < trdeep[i])
			deep = trdeep[i];
	}
	cp_log(LDEBUG, "Max deep of tree::%d\n",deep);
	cp_log(LDEBUG, "Avg deep of tree::%d\n",deep_avg/count_list);
	cp_log(LDEBUG, "Number of Node::%d\n",count_list);
	
	char buf2[BSIZE];
	struct list_t * info2;
	char * s_direct;
	char refe[50];
	char buf[50];
	struct list_entry_t * rl;
	struct map_entry * e;	
		
	for (j = 0; j < count_list ; j++ ) {
		rn = node_list[j].link2node;
		if ( rn == db->top)
			s_direct = "ROOT";
		else	
			s_direct = (node_list[j].n_direct == _LEFT ) ? "LEFT":"RIGHT";
			
		bzero(buf2, BSIZE);
		inet_ntop(rn->p.family, (void *)&rn->p.u.prefix, buf2, BSIZE);
		
		if( rn->flags && ((struct mapping_flags *)rn->flags)->referral){
			sprintf(refe, "%s%s","Reference::",sref[((struct mapping_flags *)rn->flags)->referral]);
		}
		else
			sprintf(refe, "%s"," ");
		node_type2_str(rn, buf);	
		
		cp_log(LLOG, "%d:: %s - %s/%d - %s - %s \n", j, s_direct, buf2, rn->p.prefixlen,buf, refe);
		if(ms_node_is_type(rn,_MAPP)){
			assert(rn->info);
			info2 = (struct list_t *)rn->info;
			rl = info2->head.next;
			while(rl != &info2->tail){
				char buf[BSIZE];
				bzero(buf, BSIZE);
				e = (struct map_entry *)rl->data;
				switch(e->rloc.sa.sa_family){
					case AF_INET:
						inet_ntop(AF_INET, (void *)&e->rloc.sin.sin_addr, buf, BSIZE);
						break;
					case AF_INET6:
						inet_ntop(AF_INET6, (void *)&e->rloc.sin6.sin6_addr, buf, BSIZE);
						break;
					default:
						cp_log(LDEBUG, "unsuported family\n");
						continue;
				}
				cp_log(LDEBUG, "\t•[rloc=%s, priority=%u, weight=%u, m_priority=%u, m_weight=%u, r=%d]\n", \
					buf, \
					e->priority, \
					e->weight, \
					e->m_priority, \
					e->m_weight, \
					e->r);
				rl = rl->next;
			}
		}			
	}
}


	void 
explore_list(struct list_t * list, int (* data_process)(void *))
{
	struct list_entry_t *cur;
	
	cur = list->head.next;
	while (cur != &(list->tail))
	{
		data_process(cur->data);		
		cur = cur->next;
	}
}

	int 
show_eid_info(void *data)
{
	struct db_node * eid_data;
	char buf[512];
	struct list_entry_t * p;
	struct site_info *site;
	assert(data);
	
	eid_data = (struct db_node *)data;
	bzero(buf, 512);
	inet_ntop(eid_data->p.family, (void *)&eid_data->p.u.prefix, buf, 512);
	site = NULL;
	if(eid_data->flags){
		if(((struct mapping_flags *)eid_data->flags)->rsvd ){
			p = (struct list_entry_t *)(((struct mapping_flags *)eid_data->flags)->rsvd);
			site = (struct site_info *)(p->data);
		}
	}
	else 
		site = NULL;
	cp_log(LLOG, "EID prefix::%s/%d - belong to site: %s\n", 
			buf, eid_data->p.prefixlen, (site)?site->name:" ");
	return 1;
}


	int 
show_site_info(void * data)
{
	struct site_info * site_data;
	site_data = (struct site_info *) data;
	cp_log(LLOG, "\nInformation of site: %s\n",site_data->name);
	cp_log(LLOG, "Key: %s\n",site_data->key);
	cp_log(LLOG, "Contact: %s\n",site_data->contact);
	cp_log(LLOG, "EID prefix number:: %d\n",site_data->eid->count);
	explore_list(site_data->eid, &show_eid_info);
	return 1;
}

	void 
list_site(struct list_t *list)
{
	cp_log(LLOG, "\nSite number:: %d\n",list->count);
	explore_list(list, &show_site_info);
}
