
#include "lib.h"

uint64_t cli_request_get_nonce(uint32_t id);
void *cli_start_communication(void *context);
void *cli_stop_communication(void *context);

/* Map-Reply handling code */
	int
cli_reply_add(uint32_t id)
{
	uint64_t nonce = cli_request_get_nonce(id);

	printf("Map-Reply %u\n", id);
	printf(" <");
	printf("nonce=%lld", (long long int)nonce);
	printf(">\n");

	return (TRUE);
}

	int
cli_reply_add_record(struct prefix *p,
		uint32_t ttl, uint8_t lcount,
		uint32_t version, uint8_t A, uint8_t act)
{
	char buf[BSIZE];

	bzero(buf, BSIZE);
	inet_ntop(p->family, (void *)&p->u.prefix, buf, BSIZE);
	printf("EID %s/%d: ", buf, p->prefixlen);

	printf("<");
	printf("Lcount=%u", lcount);

	printf(", ");
	printf("TTL=%u", ttl);

	if (lcount == 0) {
		printf(", ");
		printf("ACT=%d", act);
	}

	printf(", ");
	printf("version=%u", version);

	printf(", ");
	printf("A=%u", A);

	printf(">\n");

	if (lcount == 0) {
		printf("\tNegative reply\n");
	}
	return (TRUE);

}

	int
cli_reply_add_locator(uint32_t id, struct map_entry *e)
{
	char buf[BSIZE];
	bzero(buf, BSIZE);
	switch (e->rloc.sa.sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, (void *)&e->rloc.sin.sin_addr, buf, BSIZE);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, (void *)&e->rloc.sin6.sin6_addr, buf, BSIZE);
			break;
		default:
			printf("unsuported family\n");
			return (FALSE);
	}

	printf("\t[rloc=%s, p=%d, w=%d, r=%d, L=%d, p=%d]\n", buf, e->priority, e->weight, e->r, e->L, e->p);

	return (TRUE);
}

	int
cli_reply_error(uint32_t id)
{
	printf("Unknown error (%u)\n", id);
	return (TRUE);
}

	int
cli_reply_terminate(uint32_t id)
{
	printf("send Map-Reply %u\n", id);
	return (TRUE);
}

/* ! Map-Reply handling code */

/* Map-Request handling code */
struct map_request{
	char *eid;
	uint64_t nonce;
};

#define	MAX_INCOMING_QUEUE	1024
struct map_request incoming_messages[MAX_INCOMING_QUEUE];

	uint32_t
cli_request_add(char *eid, uint64_t nonce)
{
	struct map_request *mr = &incoming_messages[666];

	mr->eid = eid;
	mr->nonce = nonce;

	return (666);
}

	int
cli_request_terminate(uint32_t id)
{
    assert(id < MAX_INCOMING_QUEUE);

	bzero(&incoming_messages[id], sizeof(struct map_request));

	return (TRUE);
}

	int
cli_request_get_eid(uint32_t id, struct prefix *p)
{
	assert(id < MAX_INCOMING_QUEUE);
	char *eid;

	eid = incoming_messages[id].eid;
	str2prefix(eid, p);

	return (TRUE);
}

	uint64_t
cli_request_get_nonce(uint32_t id)
{
	assert(id < MAX_INCOMING_QUEUE);

	return incoming_messages[id].nonce;
}

/* ! Map-Request handling code */


/* CLI function binding */
struct communication_fct cli_fct = {\
	.start_communication = cli_start_communication, \
	.stop_communication = cli_stop_communication, \
	.reply_add  =  cli_reply_add,\
	.reply_add_record  =  cli_reply_add_record, \
	.reply_add_locator  =  cli_reply_add_locator,\
	.reply_error  =  cli_reply_error, \
	.reply_terminate  =  cli_reply_terminate, \
	.request_terminate  =  cli_request_terminate, \
	.request_get_eid  =  cli_request_get_eid , \
	.request_get_nonce  =  cli_request_get_nonce
};

	void *
cli_start_communication(void *context)
{
	char line[2048];
	char *params[100];
	char *token;
	uint32_t rid;
	int i = 0;

	while (fgets(line, sizeof line, stdin) != NULL) {
		line[strlen(line)-1] = '\0';
		token = strtok (line, " ");

		while (token != NULL) {
			params[i++] = token;
			token = strtok (NULL, " ,");
		}

		if (!i)
			continue;

		/* == GET  a mapping */
		/* Map-Request <eid> <nonce> */
		if (strcasecmp("map-request", params[0]) == 0 && i == 3) {
			rid = cli_request_add(params[1], (uint64_t)atoi(params[2]));
			generic_process_request(rid, &cli_fct);
		}
		/* == Stop the CLI */
		/* quit */
		if (strcasecmp("quit", params[0]) == 0) {
			cli_fct.stop_communication(NULL);
			return (NULL);
		}
		/* == Register a new mapping */
		/* example:
		   =======
		   map-register 6.6.6.6/24  version 65 A true TTL 56 -rloc address 127.0.0.1 priority 1 weight 100 m_priority 255 m_priority 0 reachable false -rloc address6 fe80::226:bbff:fe0e:882c priority 2  weight 100 m_priority 255 m_priority 0 reachable true
		   map-register 1.2.3.4/32 ACT 2 TTL 5 A true
		   map-request 6.6.6.6 123567
		   map-request 1.2.3.4 098765
		  */
		/* Map-Register <eid>  */
		if (strcasecmp("map-register", params[0]) == 0) {
			void *_mapping;
			struct prefix p1;
			struct mapping_flags *mflags;
			struct map_entry *entry = NULL;
			int j = 1;

			printf("p1:%s\n", params[j]);
			str2prefix (params[j], &p1);
			apply_mask(&p1);
			_mapping = generic_mapping_new(&p1);
			j++;
			int prev = 0;
			int count = 0;
			void *ptr = NULL;
			mflags = calloc(1, sizeof(struct mapping_flags));


			while (j < i - 1) {
					if (0 == strcasecmp(params[j], "-rloc")) {
					j++;
					if (prev && count > 0) {
						printf("ADD RLOC\n");
						assert(entry != NULL);
						generic_mapping_add_rloc(_mapping, entry);
						prev = 0;
					}
					printf("new rloc\n");
					entry = calloc(1, sizeof(struct map_entry));
					printf("%p\n", entry);
					continue;
				}else if (0 == strcasecmp(params[j], "priority")) {
					entry->priority = atoi(params[j+1]);
				}else if (0 == strcasecmp(params[j], "m_priority")) {
					entry->m_priority = atoi(params[j+1]);
				}else if (0 == strcasecmp(params[j], "weight")) {
					entry->weight = atoi(params[j+1]);
				}else if (0 == strcasecmp(params[j], "m_weight")) {
					entry->m_weight = atoi(params[j+1]);
				}else if (0 == strcasecmp(params[j], "reachable")) {
					entry->r = (strcasecmp(params[j+1], "true")==0);
				}else if (0 == strcasecmp(params[j], "local")) {
					entry->L = (strcasecmp(params[j+1], "true")==0);
				}else if (0 == strcasecmp(params[j], "rloc-probing")) {
					entry->p = (strcasecmp(params[j+1], "true")==0);
				}else if (0 == strcasecmp(params[j], "address")) {
					entry->rloc.sa.sa_family = AF_INET;
					ptr = &(entry->rloc.sin.sin_addr);
				}else if (0 == strcasecmp(params[j], "address6")) {
					entry->rloc.sa.sa_family = AF_INET6;
					ptr = &entry->rloc.sin6.sin6_addr;
				} /* mapping flags*/
				else if (0 == strcasecmp(params[j], "act")) {
					mflags->act = atoi(params[j+1]);
				}else if (0 == strcasecmp(params[j], "a")) {
					mflags->A = (strcasecmp(params[j+1], "true")==0);
				}else if (0 == strcasecmp(params[j], "version")) {
					mflags->version = atoi(params[j+1]);
				}else if (0 == strcasecmp(params[j], "ttl")) {
					mflags->ttl = atoi(params[j+1]);
				}
				/* an RLOC */
				if (ptr) {
					count++;
					inet_pton(entry->rloc.sa.sa_family, params[j+1], ptr);
					ptr = NULL;
				}

				//printf("%s -> %s\n", params[j], params[j+1]);
				j = j+2;
				prev = 1;
			}

			if (prev && count > 0) {
				printf("ADD RLOC\n");
				generic_mapping_add_rloc(_mapping, entry);
				prev = 0;
			}

			generic_mapping_set_flags(_mapping, mflags);
		}

		if (strcasecmp("map-database", params[0]) == 0) {
			assert(ms_db->lisp_db4);
			assert(ms_db->lisp_db6);
			list_db(ms_db->lisp_db4);
			list_db(ms_db->lisp_db6);
		}
		if (strcasecmp("reload", params[0]) == 0) {
			reconfigure();
		}

		if (strcasecmp("help", params[0]) == 0) {
			printf("""\t•map-database\n");
			printf("\t•map-register\n");
			printf("\t\tExample:\n \t\t\t map-register 6.6.6.6/24  version 65 A true TTL 56 \\ \n \t\t\t-rloc address 127.0.0.1 priority 1 weight 100 m_priority 255 m_priority 0 reachable false \\ \n \t\t\t -rloc address6 fe80::226:bbff:fe0e:882c priority 2 weight 100 m_priority 255 m_priority 0 reachable true\n");
			printf("\t•map-request\n");
			printf("\t\ttexample:\n \t\t\tmap-request 6.6.6.6 123567\n");
			printf("\t•reload\n");
		}
	}
	return (NULL);
}

	void *
cli_stop_communication(void *context)
{
	printf("bye\n");
	exit(EXIT_FAILURE);
	return (NULL);
}
