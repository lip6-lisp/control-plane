#include "map_register_reply.h"
#include "hmac_sha.h"


#define BUFLEN 255
#define ACTV_RLOC 1
#define D_ACTV_RLOC 255 // admin-down
unsigned char * hyp_key = "uniroma-xtr";

/*
*****************\\PROCESS---CP---ALGORITHM\\********************
*	Listen on port 4342 and wait for CP							*
*	Verify packet using MAC										*
*	Extract EID from EID-prefix field							*
*	if H-bit set then											*
*		Search for EID in mapping database						*
*		Put own-RLOCs in CPN’s List-IP field					*
*		Send CPN to multicast group of xTRs						*
*	end if														*
*																*
*	if N-bit set then											*
*		if own-RLOCs in EID’s are set to 1 then					*
*			Change own-RLOCs for EID to 255						*
*			Extract RLOCs from List-IP							*
*			Set RLOCs priority for EID to 1						*
*			Stop registering for EID							*
*			Put logged-RLOCs for EID in CPR’s List-IP field		*
*			Send CPR to one of RLOCs							*
*		else													*
*			Extract RLOCs from List-IP							*
*			Change sender RLOC for EID to 1						*
*		end if													*
*	end if														*
*																*
*	if R-bit set then											*
*		Change own RLOCs for EID to 1							*
*		Send SMRs to RLOCs in CPR and to PxTRs					*
*	end if														*
*****************************************************************
*/

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
	uchar				src_rloc_afi;
	char 				eid_prefix[INET6_ADDRSTRLEN];
	char 				l_ip[INET6_ADDRSTRLEN];
	char				src_rloc[INET6_ADDRSTRLEN];
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
	tmp_ptr = CO(cpm, sizeof(struct lisp_change_priority_pkt)); // for message verification
	length = sizeof(struct lisp_change_priority_pkt);
	
	int hyper_bit = cpm->hyper_bit;
	int src_bit = cpm->src_bit;
	int dest_bit = cpm->dest_bit;
	printf("des = %d\n",dest_bit);
	printf("src: %d\n",src_bit);
	printf("HYPER = %d\n",cpm->hyper_bit);
	printf("type = %d\n",cpm->type);
	
		
	// extract EID from CP
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
	
	
	// verify packet
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
		
	
	//convert eid to presentable ip address 
	inet_ntop(AF_INET, cpm->eid_prefix, dst,INET_ADDRSTRLEN);
	printf("eid_prefix: %s\n",dst);
	
	
	// get data from /etc/register_paramters.txt
	getparameters_reg(&params,eid_afi);

	
	// search for eid entry in /etc/register_parameter.txt 
	struct eid_rloc_db	*next = params.data;
	struct eid_rloc_db *del = params.data;
	struct sockaddr_in	*temp = (struct sockaddr_in *) &(next->ed_ip);
	inet_ntop(AF_INET, &temp->sin_addr, res, INET6_ADDRSTRLEN); 
	printf("res: %s\n",res);
	while (strcmp(res, dst) != 0)
	{
		del = next;
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

	
	if (hyper_bit == 1) 
	{
		printf("I'M IN H-BIT MODE....\n");
		
		// get local and non local rlocs
		struct rloc_db *rloc_next = NULL;
		rloc_next = next->rloc;
		struct sockaddr_storage nl_rlocs_table[20]; // non local rloc table
		struct sockaddr_storage rlocs_table[20];	// local rloc table
		int nl_count = 0; // non local rloc count
		int count = 0; // local rloc count

		while(rloc_next !=NULL)
		{
			if (rloc_next->local == 1)
			{
				rlocs_table[count] = rloc_next->rl_ip;
				count++;
			}
			else if (rloc_next->local == 0)
			{
				nl_rlocs_table[count] = rloc_next->rl_ip;
				nl_count++;
			}
			rloc_next = rloc_next->rl_next;
		//printf("%d\n",next->rloc->priority);
		//printf("changing priority ... OK\n");
		}
		
		
		uchar rec_ptr[1024];
		struct lisp_change_priority_rec *rec;
		struct sockaddr_storage *res;
		struct sockaddr_in *ska;
		struct sockaddr_in6 *ska6;
		int length = 0;
		

		//put local rlocs in list-ip field
		rec = (struct lisp_change_priority_rec *) rec_ptr;
		for (i = 0; i< count ; i++ ) {
			res = &rlocs_table[i];
			rec->l_ip_afi = (res->ss_family == AF_INET)?LISP_AFI_IP:LISP_AFI_IPV6;
			if (res->ss_family == AF_INET) {
				ska = (struct sockaddr_in *) res;
				memcpy(rec->l_ip, &(ska->sin_addr),sizeof(struct in_addr));
				rec = CO(rec,4+sizeof(struct in_addr));
				length += 4+sizeof(struct in_addr);
			}else{
				ska6 = (struct sockaddr_in6 *)res;
				memcpy(rec->l_ip, &(ska6->sin6_addr),sizeof(struct in6_addr));
				rec = CO(rec,4+sizeof(struct in6_addr));
				length += 4+sizeof(struct in6_addr);
			}
		}

		
		// send cp with N-bit set
		for (i=0; i<nl_count;i++)
		{
			send_cpm(dst,(struct sockaddr_in *) &nl_rlocs_table[i], rec, count, 1, 0);
			send_cpm(dst,(struct sockaddr_in *) &nl_rlocs_table[i], rec, count, 1, 0);
		}
		
	}//end if h-bit
	else
	{
		// N-bit is set
		if(dest_bit == 1)
		{
			
			// extract rlocs from list-ip field
			struct sockaddr_in list_ip[20];
			int count = 0;
			for(i = 0; i < cpm->record_count; i++)
			{
				lcpr = (struct lisp_change_priority_rec *)ptr;
				ptr = CO(ptr, sizeof(struct lisp_change_priority_rec));
				//memset(l_ip, '\0', INET6_ADDRSTRLEN);
				l_afi = ntohs(lcpr->l_ip_afi);		
				
				if (l_afi == LISP_AFI_IP) 
				{
					memcpy(&(sa.sin_addr), lcpr->l_ip, sizeof(struct in_addr));
					ptr = CO(ptr, sizeof(struct in_addr));
					sa.sin_family = AF_INET;
				}
				else if (l_afi == LISP_AFI_IPV6)
				{ 
					memcpy(&(sa.sin_addr), lcpr->l_ip, sizeof(struct in6_addr));
					ptr = CO(ptr, sizeof(struct in6_addr));
					sa.sin_family = AF_INET6;			
				}
				list_ip[count] = sa;
				count++;
			
				//inet_ntop(AF_INET, l_ip, res, INET6_ADDRSTRLEN);
				//printf("rec: %s\n",inet_ntop(AF_INET, l_ip, res, INET6_ADDRSTRLEN));
			}
					
				
			// change priority in /etc/register_parameters and openlisp database	
			struct rloc_db *rloc_next = NULL;
			rloc_next = next->rloc;
			struct sockaddr_in *addr;
			char prloc[INET6_ADDRSTRLEN];
			count = 0;
			int islocal = 0;
			while(rloc_next !=NULL)
			{
				
				if (rloc_next->local == 1)
				{
					if (rloc_next->priority == 1){
						rloc_next->priority = D_ACTV_RLOC;
						islocal = 1;
					}
				}
				else
				{	
					addr = (struct sockaddr_in*) &rloc_next->rl_ip;
					inet_ntop(list_ip[count].sin_family, &(list_ip[count].sin_addr), res, INET6_ADDRSTRLEN);
					inet_ntop(addr->sin_family, &(addr->sin_addr), prloc, INET6_ADDRSTRLEN);
					if (strcmp(prloc,res) == 0)
					{
						count++;
					}
				}
				rloc_next = rloc_next->rl_next;
			//printf("%d\n",next->rloc->priority);
			//printf("changing priority ... OK\n");
			}
			write_parametes_2_file(&params,filename);
			openlisp2((void *)&params);
			
			
			//if eid is managed by local site stop registering and send a reply to 1 rlocs of the sender  
			if (islocal)
			{
				//send_map_register2(d);
				void *lp;
				int *count;
				logget((cpm->eid_prefix_afi == 0)?AF_INET:AF_INET6, cpm->eid_prefix, lp, count);
				send_cpm(dst,&list_ip[0],lp , *count, 0, 1);
			}
			
		}// end N-bit
		else
		{
			// if R-bit is set
			if (src_bit == 1)
			{
			
			// change priority in /etc/register_parameters.txt and register
			struct rloc_db *rloc_next = NULL;
			rloc_next = next->rloc;
			struct sockaddr_in *addr;
			while(rloc_next !=NULL)
			{
				if (rloc_next->local == 1)
				{
					rloc_next->priority = ACTV_RLOC;
				}
				else
				{	
					if (rloc_next->priority == 1)
						rloc_next->priority = ACTV_RLOC;
				}
				rloc_next = rloc_next->rl_next;
			//printf("%d\n",next->rloc->priority);
			//printf("changing priority ... OK\n");
			}
			write_parametes_2_file(&params,filename);
			openlisp2((void *)&params);
			send_map_register2(d);
				//send_smr("112.137.129.42",dst);
				//send_smr("112.137.129.42",dst);
				
				
			// send smr to rlocs and pxtrs
			for(i = 0; i < cpm->record_count; i++)
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
				send_smr(l_ip,dst);
				send_smr(l_ip,dst);
				//inet_ntop(AF_INET, l_ip, res, INET6_ADDRSTRLEN);
				//printf("rec: %s\n",inet_ntop(AF_INET, l_ip, res, INET6_ADDRSTRLEN));
			}	
			
			return;
				
			}// end if src_bit	
		}//end esle
	}//end else
}// end function

int send_smr(char *rloc,char *eid)
{
	int s;
  	struct addrinfo	    hints;
    struct addrinfo	    *res;
    struct protoent	    *proto;
	unsigned char packet[4000];
	unsigned int   nonce0;
    unsigned int   nonce1;
	int nbytes, e;

	struct map_request_pkt2 *map_request;
	struct map_request_eid2 *map_request_eid;

	struct sockaddr_in sa;

    if ((proto = getprotobyname("UDP")) == NULL) {
		perror ("getprotobyname");
		exit(0);
    }

    if ((s = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) {
		perror("SOCK_DGRAM (s)");
		exit(1);
    }
	make_nonce(&nonce0, &nonce1);
	map_request = (struct map_request_pkt2 *)packet;
	map_request_eid = (struct map_request_eid2 *)(packet + sizeof(struct map_request_pkt2));

	map_request->smr_bit                     = 1;
    map_request->rloc_probe                  = 0;
    map_request->map_data_present            = 0;
    map_request->auth_bit                    = 0;
    map_request->lisp_type                   = 1;
    map_request->irc                         = 0;
    map_request->record_count                = 1;
    map_request->lisp_nonce0                 = htonl(nonce0); 
    map_request->lisp_nonce1                 = htonl(nonce1); 
    map_request->source_eid_afi              = htons(LISP_AFI_IP);
	inet_pton(AF_INET, "132.227.62.242", &(sa.sin_addr));

 map_request->itr_afi    = htons(LISP_AFI_IP);
    memcpy(map_request->originating_itr_rloc,
                &(sa.sin_addr), sizeof(struct in_addr));
	
	map_request_eid->eid_mask_len = 32;
	map_request_eid->eid_prefix_afi = htons(LISP_AFI_IP);
	inet_pton(AF_INET, eid, &(sa.sin_addr));
    memcpy(map_request_eid->eid_prefix,
                &(sa.sin_addr), sizeof(struct in_addr));
 memcpy(map_request->source_eid,
                &(sa.sin_addr), sizeof(struct in_addr));
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET;	/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = proto->p_proto;

	if ((e = getaddrinfo(rloc, "4342", &hints, &res)) != 0) {
		fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(BAD);
	}
	hexout(packet,sizeof(struct map_request_pkt2)+ sizeof(struct map_request_eid2));
	
	if ((nbytes = sendto(s,
		(const void *) packet,
		sizeof(struct map_request_pkt2)+ sizeof(struct map_request_eid2) ,
		0,
		res->ai_addr,
		SA_LEN(res->ai_family))) < 0) {
	perror("sendto");
	exit(1);
	}
	printf("Send SMR to %s\n for %s\n",rloc,eid);
	return 0;
}

void send_cpm(char *eid, struct sockaddr_in *_rloc, struct lisp_change_priority_rec *rec_field, int rec_count, int dest_bit, int src_bit)
{

	int s;
	struct addrinfo	    hints;
	struct addrinfo	    *res;
	struct protoent	    *proto;
  
	char  emr_inner_src_port_str[NI_MAXSERV];

	int e		= 0;
	
	if ((proto = getprotobyname("UDP")) == NULL) 
	{
		perror ("getprotobyname");
		exit(BAD);
	}

  	if ((s = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) 
	{
		perror("SOCK_DGRAM (s)");
		exit(1);
    	}
	
	emr_inner_src_port = LISP_CONTROL_PORT;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_INET;		/* Bind on AF based on AF of Map-Server */
	hints.ai_socktype  = SOCK_DGRAM;	/* Datagram socket */
	hints.ai_flags     = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol  = proto->p_proto;

	//sprintf(emr_inner_src_port_str, "%d", emr_inner_src_port);

	if ((e = getaddrinfo(NULL, "5555", &hints, &res)) != 0) 
	{
		fprintf(stderr, "getting local socket: getaddrinfo: %s\n", gai_strerror(e));
		exit(BAD);
	}

	//Bind the socket to 4342 and the internet interface 
	if (bind(s, res->ai_addr, res->ai_addrlen) == -1) 
	{
		perror("bind");
		exit(BAD);
	}

	struct lisp_change_priority_pkt 	*cpm = NULL;
	struct lisp_change_priority_rec 	*rec = NULL;
	unsigned int 				nonce0, nonce1;
	void 					*ptr;
	int 					i;
	int 					length;
	unsigned char 				buf[BUFLEN];	
	int 					nbytes = 0;
	uint32_t                            md_len;
	HMAC_SHA1_CTX 				ctx;
	uchar 					packet[MAX_IP_PACKET];
	uchar 					packet2[MAX_IP_PACKET];
	
	make_nonce(&nonce0, &nonce1);
	
	cpm = (struct lisp_change_priority_pkt *) packet;
	cpm->reserved 			= 0;
	cpm->hyper_bit			= 0;
	cpm->dest_bit			= dest_bit;
	cpm->src_bit			= src_bit;
	cpm->type 			= LISP_CHANGE_PRIORITY;
	cpm->reserved1  		= 0;
	cpm->lisp_nonce0		= htonl(nonce0);
	cpm->lisp_nonce1		= htonl(nonce1);
	cpm->key_id 			= htons(01);
	cpm->auth_data_len 		= htons(20);
	

	for (i = 0; i < 20; i++)
	{
		cpm->auth_data[i] = 0;
	}

	

	//get eid of the VM - > write a function to do that
	cpm->eid_mask_len 		= 32; //or 128 -> must be added dynamically	
	cpm->eid_prefix_afi		= UHTONS(LISP_AFI_IP); // or /IPV6 -> must be filled dynamically
	struct in_addr vm_eid;
	inet_pton(AF_INET, eid, &vm_eid); // just an example ...
	memcpy(cpm->eid_prefix, &vm_eid, sizeof(struct in_addr));

	length = sizeof(struct lisp_change_priority_pkt) + sizeof(struct in_addr);
	ptr = CO(cpm, sizeof(struct lisp_change_priority_pkt) + sizeof(struct in_addr));

	// write a function to get the list of IP that the VM was communicating with 
	
	rec = (struct lisp_change_priority_rec *) ptr;
	memcpy(rec, rec_field, sizeof rec_field);
	ptr = CO(ptr, sizeof rec);

	cpm->record_count 		= rec_count;
	
	// calculate hash
	
	printf("length = %d\n",length);
	memcpy(packet2, packet, length);
        HMAC_SHA1_Init(&ctx);
        HMAC_SHA1_UpdateKey(&ctx, hyp_key, strlen((char *)hyp_key));
        HMAC_SHA1_EndKey(&ctx);
        HMAC_SHA1_StartMessage(&ctx);
        HMAC_SHA1_UpdateMessage(&ctx, packet2, length);
        HMAC_SHA1_EndMessage(buf, &ctx);

	char hex_output[20 * 2 + 1];
	for (i = 0; i < 20; i++)
	{
		sprintf(hex_output + i * 2, "%02x", buf[i]);
		cpm->auth_data[i] = buf[i];
	}
	printf("%s\n",hex_output);
	printf("last\n");
	printf("last1\n");
	
		
	//printcpm((void *) packet);
	if ((nbytes = sendto(s, 
				(const void *) packet,
				length,
				0,
				(struct sockaddr *) _rloc,
				SA_LEN(_rloc->sin_family))) < 0)
	{
		perror("sendto");
		exit(BAD);
	}
	printf("last2\n");
}
