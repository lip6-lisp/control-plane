
#include "db.h"
#include "lib.h"

	void 
ms_free_node(void * node)
{
	if(node)
		free(node);
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
	dn->reserve = ms_new_node_ex(_ROOT);
		
	//and 0::/0 as root of ipv6 tree
	str2prefix("0::/0",&p);
	apply_mask(&p);
	dn = db_node_get(db->lisp_db6,&p);
	assert( dn == (db->lisp_db6->top));
	dn->reserve = ms_new_node_ex(_ROOT);
	
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

	struct node_extern 
* ms_new_node_ex(u_char n_type)
{
	struct node_extern * rt;
	
	rt = calloc(1, sizeof(struct node_extern));
	rt->type = n_type;
	rt->active = _ACTIVE;
	rt->ex_info = NULL;
	return rt;
}

	void 
ms_node_update_type(struct db_node * node, u_char n_type)
{
	assert(node);
	u_char tmp;
	
	if (node->reserve == NULL)
		node->reserve = ms_new_node_ex(n_type);
	else{
		tmp = ((struct node_extern *)node->reserve)->type;
		tmp = tmp | n_type;
		((struct node_extern *)node->reserve)->type = tmp;
	}		
}

	u_char 
ms_node_is_type(struct db_node * node, u_char n_type)
{
	assert(node);
	u_char tmp;
	if(node->reserve == NULL)
		return 0;	
	
	tmp = ((struct node_extern *)node->reserve)->type;
	return (tmp & n_type);
}

	

	u_char 
ms_node_is_referral(struct db_node * node)
{
	struct mapping_flags * flags;
	if(!node->flags)
		return 0;
	flags = (struct mapping_flags *)node->flags;
	if(!flags->referral)
		return 0;
	return 1;
}

	u_char 
ms_node_is_proxy_reply(struct db_node * node)
{
	struct mapping_flags * flags;
	if(!node->flags)
		return 0;
	flags = (struct mapping_flags *)node->flags;
	if(!flags->proxy)
		return 0;
	return 1;
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
	printf("AF_NOT_SUPPORT\n");
	return NULL;	
}

	struct db_node * 
ms_get_target(struct db_node * node)
{
	while( !node->reserve && node != node->table->top){
		node = node->parent;
	}
	return node;
}

//=================================================================
//debug function
	char * 
node_type2_str(struct db_node * rn)
{
	
	char * node_type[17];
	u_char n_type;
	u_char tmp = 1;
	u_char  i;
	char rt[255];
	char rt_len;
	
	node_type[0] = "ROOT";
	node_type[1] = "MAPP";
	node_type[2] = "MAPP_xTR";
	node_type[4] = "EID";
	node_type[8] = "GEID";
	node_type[16] = "GREID";
	node_type[32] = "TMP";
	
	if(!rn->reserve)
		return node_type[32];
	
	n_type = ((struct node_extern *)rn->reserve)->type;
	rt_len = 0;
	i = 1;
	memset(rt,0,255);
	while (n_type){
		if(n_type & tmp){
			if(rt_len){
				rt[rt_len] = 0x7c;
				rt_len++;
			}	
			memcpy((char *)rt+rt_len,node_type[i], strlen(node_type[i]));
			rt_len += strlen(node_type[i]);		
		}
		n_type = n_type >> 1;
		i = i*2;
	}
	
	rt[rt_len] = '\0';	
	return rt;
}

	
	void 
list_db(struct db_table * db)
{
	struct db_node *rn;
	#define _LEFT 0
	#define _RIGHT 1
	#define _CENTER 2
	struct pool_node {
		int n_direct;
		struct db_node * link2node;
	} node_list[100];
	
	int i = 0;
	int j = 0;
	int count_list = 0;
	
	assert(db);
	assert(db->top);
	
	rn = db->top;
	
	for (i = 0; i<100 ;i++ ) {
		node_list[i].link2node = NULL;		
	}
	
	node_list[count_list++].link2node = rn;
	node_list[count_list].n_direct = _CENTER;
	
	while (rn != NULL) {
		if (rn->l_left != NULL) {
			node_list[count_list].link2node = rn->l_left;
			node_list[count_list++].n_direct = _LEFT;
		}
		if (rn->l_right != NULL) {
			node_list[count_list].link2node = rn->l_right;
			node_list[count_list++].n_direct = _RIGHT;
		}
		rn = node_list[++j].link2node;
	}
	
	printf("List of tree\n");
		
	for (j = 0; j < count_list ; j++ ) {
		rn = node_list[j].link2node;
		char buf2[512];
		void * info2;
		char * s_direct;
		char refe[50];
				
		if ( rn == db->top)
			s_direct = "ROOT";
		else	
			s_direct = (node_list[j].n_direct == _LEFT ) ? "LEFT":"RIGHT";
			
		bzero(buf2, 512);
		inet_ntop(rn->p.family, (void *)&rn->p.u.prefix, buf2, 512);
		info2 = db_node_get_info(rn);
		
		if( rn->flags && ((struct mapping_flags *)rn->flags)->referral){
			sprintf(refe, "%s%d","Reference::",((struct mapping_flags *)rn->flags)->referral);
		}
		printf("%d:: %s - %s/%d - %s - %s\n", j, s_direct, buf2, rn->p.prefixlen,node_type2_str(rn), refe );
	}
}


	void 
explore_list(struct list_t * list, int (* data_process)(void *))
{
	struct list_entry_t *cur;
	
	cur = list->head.next;
	while (cur != &(list->tail))
	{
		//printf("Entry addr :: %p\n",cur);
		data_process(cur->data);
		
		cur = cur->next;
	}
}

	int 
show_eid_info(void *data)
{
	struct db_node * eid_data;
	char buf[512];
	struct list_entry_t * info;
	struct ms_eid_ex_info * p;
	struct site_info *site;
	assert(data);
	
	eid_data = (struct db_node *)data;
	bzero(buf, 512);
	inet_ntop(eid_data->p.family, (void *)&eid_data->p.u.prefix, buf, 512);
	
	if(eid_data->reserve && ((struct node_extern *)eid_data->reserve)->ex_info ){
		p = ((struct node_extern *)eid_data->reserve)->ex_info;
		info = p->site_entry;
		site = (struct site_info *)(info->data);
	}
	else site = NULL;
	printf("EID prefix::%s/%d - belong to site: %s\n", 
			buf, eid_data->p.prefixlen, (site != NULL)? site->name: "" );
	return 1;
}


	int 
show_site_info(void * data)
{
	struct site_info * site_data;
	site_data = (struct site_info *) data;
	printf("Information of site: %s\n",site_data->name);
	printf("Key: %s\n",site_data->key);
	printf("Contact: %s\n",site_data->contact);
	printf("EID prefix number:: %d\n",site_data->eid->count);
	explore_list(site_data->eid, &show_eid_info);
	return 1;
}

	void 
list_site(struct list_t *list)
{
	printf("Site number:: %d\n\n",list->count);
	explore_list(list, &show_site_info);
}
