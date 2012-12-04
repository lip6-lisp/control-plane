
#ifndef __HAVE_MSDB_H
#define __HAVE_MSDB_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/select.h>
#include <signal.h>
#include <netdb.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/errno.h>

#include "radix/db.h"
#include "radix/db_table.h"
#include "radix/db_prefix.h"
#include "list/list.h"

#include <expat.h>

#define	TRUE	1
#define	FALSE	0

#define BSIZE   2048

#define	_MAPP		1
#define	_MAPP_XTR	2
#define _EID		4
#define _GEID		8
#define _GREID		16
#define _ROOT		0

#define	_ACTIVE 	1
#define _NOACTIVE 	0

//db include 2 radix tree, one for ipv4 and other for ipv6
struct lisp_db {
		struct db_table *lisp_db4;
		struct db_table *lisp_db6;
};

struct node_extern {
	u_char type;
	u_char active;
	void * ex_info;	
};

struct ms_eid_ex_info {
	struct list_entry_t * site_entry;
};

//second db: db of sites
struct site_info{
		char * name;
		char * key;
		char * contact;
		u_char active;
		char * hashing;
		struct list_t  * eid;		 		
};

//struct of map-server for xTR send map-register


//make new node with pre-set type
struct node_extern * ms_new_node_ex(u_char n_type);

//add type to node. Note that: one node can have many roles (types)
void ms_node_update_type(struct db_node * node, u_char n_type);

//get a real parent of node (real parent = node with type not null)
struct db_node * ms_get_target(struct db_node * node);

//delete a node
void ms_free_node(void * node);

//create a new site info
struct site_info * ms_new_site_info();

//create a new site in list of site
struct list_entry_t * ms_new_site();

//check type of node
u_char ms_node_is_type(struct db_node * node, u_char n_type);

//check if a node has referrall flag or not
u_char ms_node_is_referral(struct db_node * node);
//check if a mapping is proxy-map-reply or not
u_char ms_node_is_proxy_reply(struct db_node * node);

//load configure to database
void ms_load_config();

//init database
struct lisp_db * ms_init_db();

//finish database
void ms_finish_db(struct lisp_db *db);

//select db_table base on AF
struct db_table * ms_get_db_table(const struct lisp_db * db, struct prefix * pf);

//parser configure file an
int ms_parser_config();

//get paramater from map-register --> reused existing functions
void ms_get_register(void *mr_id);

//get list of mapping from map-register package
void * ms_get_register_mapping(void *mr_id);

//get hashing from map-register package
int ms_get_register_hashing(void *mr_id);

//void ms_get_register_info(void *mr_id);
			
//Check if map-register is new or not
int ms_validate_register(void *mr_id);

//get site which mr belong to
struct list_entry_t * ms_get_register_site(void * mr_id);

//compare hashing to see if mr package is new or not
int ms_exist_hashing(void * mr_id);

//compare if all mapping in the mr package are the same site or not
int ms_same_site(void * mr_id);

//check if mr package is authentecated or not
int ms_auth_register(void * mr_id);


//update dabase with new mapping
void ms_accept_register(void * mr_id);

//empty mapping of a site
void ms_empty_mapping(struct list_entry_t * site_entry);

//insert mapping for a site
void ms_insert_mapping(struct list_entry_t * site_entry, void * mr_id);

//debug function
//show database
void list_db(struct db_table * db);
//show site's database
void list_site(struct list_t *list);
void explore_list(struct list_t * list, int (* data_process)(void *));
int show_eid_info(void *data);
int show_site_info(void * data);

struct lisp_db * ms_db;
struct list_t * site_db;
struct list_t * etr_db;


char * xtr_sip[2];
struct list_t * xtr_ms;
struct list_t * xtr_mr;

#endif
