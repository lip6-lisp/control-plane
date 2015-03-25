#include "db.h"

	int
rtr_forward_map_register(struct pk_req_entry *pke)
{
	return 0;
}

	int
rtr_process_map_register(struct pk_req_entry *pke)
{
	return rtr_forward_map_register(pke);
}
