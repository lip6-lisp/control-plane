#ifndef _PLUGIN_OPENLISP_H_
#define _PLUGIN_OPENLISP_H_

#include "lib.h"

#ifdef OPENLISP

/* Size of socket must be multiple of long (from OpenLISP code) 
	so size of sockaddr_in6 is 32 instead 28 
*/
#define SS_LEN(ss)							\
	((!(ss) || ((struct sockaddr_storage *)(ss))->ss_len == 0) ?	\
	sizeof(long) :							\
	1 + ((((struct sockaddr_storage *)(ss))->ss_len - 1) | (sizeof(long) - 1)))

void *plugin_openlisp(void *data);

int get_mr(void *data);

void opl_errno(int oerrno);
void *opl_new_msg(uint16_t version, uint16_t map_type,
		  uint32_t map_flags, uint16_t map_addrs);
int opl_add(int s, struct db_node *node, int db);
int opl_del(int s, struct db_node *node, int db);
int opl_get(int s, struct db_node *mapp, int db, struct db_node *rs);
int opl_update(int s, struct db_node *node, uint8_t);
int opl_add_mapp(void *buf, struct db_node *mapp);

#endif /* OPENLISP*/

#endif /* _PLUGIN_OPENLISP_H_ */
