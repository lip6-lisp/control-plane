#include "map_register_reply.h"
#include "hmac_sha.h"

#define BUFLEN 255

#define ACTV_RLOC 1
#define D_ACTV_RLOC 255 // means that the RLOC MUST NOT be used for unicast forwarding
unsigned char * hyp_key = "lip6-xtr";

void * openlisp2(void *args);

void changepriority(int s, void *message, void *d) 
{
	
	int 				i;
	int 				length = 0;
	ushort 				tmp_keyid;
	ushort 				tmp_auth_len;
	unsigned char 		tmp_auth[20];
	HMAC_SHA1_CTX 		ctx;
	unsigned char 		buf[BUFLEN];
	uchar 				mask_len;
	uchar 				eid_afi;
	char 				eid_prefix[INET6_ADDRSTRLEN];
	char 				l_ip[INET6_ADDRSTRLEN];
	struct map_db		params;
	char 				dst[INET6_ADDRSTRLEN];
	char 				res[INET6_ADDRSTRLEN];
	int 				openlisp_sck;
	ushort 				l_afi;
	
	struct lisp_change_priority_pkt *cpm = NULL;
	void							*ptr = NULL;
	void 							*tmp_ptr = NULL;
	
	cpm = (struct lisp_change_priority_pkt *) message;
	ptr = CO(cpm, sizeof(struct lisp_change_priority_pkt));
	tmp_ptr = CO(cpm, sizeof(struct lisp_change_priority_pkt)); // used to calculate the length of the message for verification
	length = sizeof(struct lisp_change_priority_pkt);
	
	
	// 01- Extract EID from Change Priority Message
	
	mask_len = cpm->eid_mask_len;
	eid_afi = ntohs(cpm->eid_prefix_afi);
	if (eid_afi == LISP_AFI_IP)
	{
		memcpy(eid_prefix, cpm->eid_prefix, sizeof(struct in_addr));
		length += sizeof(struct in_addr);
		ptr = CO(ptr, sizeof(struct in_addr));
		tmp_ptr	= CO(tmp_ptr, sizeof(struct in_addr));	
	}
	else
	{
		memcpy(eid_prefix, cpm->eid_prefix, sizeof(struct in6_addr));
		length += sizeof(struct in6_addr);
		ptr = CO(ptr, sizeof(struct in6_addr));	
		tmp_ptr	= CO(tmp_ptr, sizeof(struct in6_addr));		
	}
	
	// 01.1- Calculate the hash and compare with the one calculated by the sender
	
	struct lisp_change_priority_rec	*tmp_lcpr;
	for (i = 0; i < cpm->record_count; i++) 
	{
		tmp_lcpr = (struct lisp_change_priority_rec *) tmp_ptr;
		length += sizeof(struct lisp_change_priority_rec);
		tmp_ptr = CO(tmp_ptr, sizeof(struct lisp_change_priority_rec));

		if (ntohs(tmp_lcpr->l_ip_afi) == LISP_AFI_IP)
		{
			length += sizeof(struct in_addr);
			tmp_ptr = CO(tmp_ptr, sizeof(struct in_addr));
		}
		else if (ntohs(tmp_lcpr->l_ip_afi) == LISP_AFI_IPV6)
		{
			length += sizeof(struct in6_addr);
			tmp_ptr = CO(tmp_ptr, sizeof(struct in6_addr));
		}
		else 
		{
			return;
		}
	}
	
	printf("length = %d\n",length);
	
	tmp_auth_len 		= ntohs(cpm->auth_data_len);
	char 				received_auth[tmp_auth_len * 2 + 1];
	
	for (i = 0; i < tmp_auth_len; i++) 
	{	
		sprintf(received_auth + i * 2, "%02x", cpm->auth_data[i]);
		cpm->auth_data[i] = 0;
	}	 
	printf("%s\n",received_auth);
	
	HMAC_SHA1_Init(&ctx);
	HMAC_SHA1_UpdateKey(&ctx, hyp_key, strlen((char *)hyp_key));
	HMAC_SHA1_EndKey(&ctx);
	HMAC_SHA1_StartMessage(&ctx);
	HMAC_SHA1_UpdateMessage(&ctx, cpm, length);
	HMAC_SHA1_EndMessage(buf, &ctx);
	
	char calculated_auth[20 * 2 + 1];
	for (i = 0; i<20; i++)
	{
		sprintf(calculated_auth + i * 2, "%02x", buf[i]);
	}
	printf("%s\n",calculated_auth);
	if(strcmp(calculated_auth, received_auth) != 0){
		printf("SHA1 doesn't match\n");
		return;
	}
	
	// 02- Transform EID prefix to presentable IP address
	
	inet_ntop(AF_INET, cpm->eid_prefix, dst,INET_ADDRSTRLEN);
	printf("eid_prefix: %s\n",dst);
	
	// 03- Get the data from the configuration file and put them in a map_db struct
	
	getparameters_reg(&params,eid_afi);

	// 04- Find the extracted EID within the map_db struct 
	
	struct eid_rloc_db	*next = params.data;
	struct sockaddr_in	*temp = (struct sockaddr_in *) &(next->ed_ip);
	inet_ntop(AF_INET, &temp->sin_addr, res, INET6_ADDRSTRLEN); 
	printf("res: %s\n",res);
	
	while (strcmp(res, dst) != 0)
	{
		if ((next = next->ed_next) != NULL)
		{
			temp = (struct sockaddr_in *) &(next->ed_ip);
			inet_ntop(AF_INET, &(temp->sin_addr), res, INET6_ADDRSTRLEN);
			printf("res: %s\n",res);
		}
		else
		{
			printf("EID does not exist in the caching system\n");
			return;		
		}
	}

	
	// 05- Change The priority of the RLOCs for the matched EID
	
	struct rloc_db *rloc_next = NULL;
	rloc_next = next->rloc;

	while(rloc_next !=NULL)
	{
		if (rloc_next->priority == ACTV_RLOC)
		{
			rloc_next->priority = D_ACTV_RLOC;
		}
		else if (rloc_next->local == 1)
		{
			rloc_next->priority = ACTV_RLOC;
		}
		rloc_next = rloc_next->rl_next;
	//printf("%d\n",next->rloc->priority);
	//printf("changing priority ... OK\n");
	}
	
	
	// 06 - Update the configuration file
	
	write_parametes_2_file(&params);
	printf("updating configuration file ... OK\n");
	
	//openlisp2((void *)&params);

	// 07- Trigger a Map Register to update the Mapping System
	
	send_map_register2(d);
	printf("Map Register sent ... OK\n");

	// 08- Open the socket one OpenLISP 
	
	if((openlisp_sck = socket(PF_MAP, SOCK_RAW, 0)) < 0)
	{
		printf("ERROR -- Couldn't open openlisp_sck\n");
		exit(BAD);
	}
	
	// 09- Analyze the rest of the packet (rec fields) 
	
	struct lisp_change_priority_rec	*lcpr = NULL;
	struct eid_rloc_db 				*l_eid = NULL;
	struct eid_rloc_db 				*tmpd = (struct eid_rloc_db *) malloc(sizeof(struct eid_rloc_db));
	struct sockaddr_in 				sa;
	sa.sin_port 					= htons(0);
	memset(sa.sin_zero, '\0', sizeof sa.sin_zero);
	tmpd->locator					= 0; // locator won't be use in get_eid;
	tmpd->flag 						= 0; //ignored in get_eid;
	tmpd->record_ttl 				= 0;
	tmpd->ed_next					= NULL;
	
	// My address for Map Request (must be taken from map_db)
	struct 							sockaddr_in my_addr;
	my_addr.sin_family 				= AF_INET;
	my_addr.sin_port 				= htons(4342);
	inet_pton(AF_INET, "132.227.62.242", &(my_addr.sin_addr));
	memset(my_addr.sin_zero, '\0', sizeof my_addr.sin_zero);
	
	// Map Resolver Map Request (must be taken from map_db)
	struct sockaddr_in 				map_resolver;
	map_resolver.sin_family 		= AF_INET;
	map_resolver.sin_port 			= htons(4342);
	inet_pton(AF_INET, "195.50.116.18", &(map_resolver.sin_addr));
	memset(map_resolver.sin_zero, '\0', sizeof map_resolver.sin_zero);
	
	struct timeval 					before;
	unsigned int 					nonce0, nonce1;
	
	printf("Begin record count ... OK\n");
	for (i = 0; i < cpm->record_count; i++) 
	{
		lcpr = (struct lisp_change_priority_rec *)ptr;
		ptr = CO(ptr, sizeof(struct lisp_change_priority_rec));
		memset(l_ip, '\0', INET6_ADDRSTRLEN);
		l_afi = ntohs(lcpr->l_ip_afi);		
		
		if (l_afi == LISP_AFI_IP) 
		{
			memcpy(l_ip, lcpr->l_ip, sizeof(struct in_addr));
			ptr = CO(ptr, sizeof(struct in_addr));
			sa.sin_family = AF_INET;
		}
		else if (l_afi == LISP_AFI_IPV6)
		{ 
            memcpy(l_ip, lcpr->l_ip, sizeof(struct in6_addr));
            ptr = CO(ptr, sizeof(struct in6_addr));
			sa.sin_family = AF_INET6;			
		}
		else
		{
			return;
		}
		printf("rec: %s\n",inet_ntop(AF_INET, l_ip, res, INET6_ADDRSTRLEN));
		inet_pton(AF_INET, res, &(sa.sin_addr));
		memcpy(&tmpd->ed_ip, (struct sockaddr_storage *) &sa, sizeof (struct sockaddr_storage));

		// 09.1- Search OpenLISP cache for matche IP; Note That these IP are the list that the VM or the mobile agent wad
		//		 communicating with
		
		// get_eid(openlisp_sck, tmpd, l_eid);
		
	    
		make_nonce(&nonce0, &nonce1);
		
		if (l_eid != NULL)
		{
			// 09.2- Send SMR if the entry exists in the database
			send_map_request(s, nonce0, nonce1, &before, (struct sockaddr *) &sa,(struct sockaddr *) &map_resolver, (struct sockaddr *) &my_addr, 4342, 1);  
			printf("SMR sent ... OK\n");
		}
		else
		{
			//09.2- Send Map Request if the entry does not exist in the database
			send_map_request(s, nonce0, nonce1, &before, (struct sockaddr *) &sa, (struct sockaddr *) &map_resolver, (struct sockaddr *) &my_addr, 4342, 0);
			printf("Map Request sent ... OK\n");
		}
	}
}
