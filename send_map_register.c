/* 
 *	send_map_register.c --
 * 
 *	send_map_register -- OpenLISP control-plane 
 *
 *	Copyright (c) 2012 LIP6 <http://www.lisp.ipv6.lip6.fr>
 *	Base on <Lig code> copyright by David Meyer <dmm@1-4-5.net>
 *	All rights reserved.
 *
 *	LIP6
 *	http://www.lisp.ipv6.lip6.fr
 *
 *Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     o Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the University nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 *
 */

 

#include	"map_register_reply.h"
#include	"hmac_sha.h"

# define BUFLEN 255

/*
 *	send_map_register --
 *
 *	Sends a IP/UDP map-register for eid(s) to map_server
 *
 *
 *	Here's the packet we need to build:
 *
 *                      IP header (ip.src = <us>, ip.dst = <map-server>) 
 *                      UDP header (udp.srcport = <kernel>, udp.dstport = 4342) 
 *       map_register -> struct map-request 
 *
 *
 *	
 *
 */

void * send_map_register(void *threadarg){
	
	int		s;
	int		s6;
    unsigned int		nonce0;
    unsigned int		nonce1;	
	struct sockaddr_in	*t_sk;
	struct sockaddr_in6	*t_sk6;

    struct map_register_data *my_data;
	my_data= (struct map_register_data *)threadarg;
	nonce0=my_data->nonce0;
	nonce1=my_data->nonce1;
	
	s=my_data->register_socket;
	s6=my_data->register_socket6;

	struct map_register_pkt	*map_register;
	struct lisp_map_register_eidtype  *eidtype	   = NULL;
    struct lisp_map_register_loctype  *loctype    = NULL; 

    int length = 0;
	int i = 0;		
	int n_eid;
    HMAC_SHA1_CTX	ctx;
	unsigned char	buf[BUFLEN];    	  	    
    int				nbytes		   = 0;
    uchar			packet[MAX_IP_PACKET];	
    uchar			packet2[MAX_IP_PACKET];	
   	struct map_db params;		
	void * ptr;
	struct map_server_db *ms_ptr;
	struct eid_rloc_db *eid_ptr;
	struct rloc_db *rloc_ptr;
	int rec_c = 0;
	//Getting the parameters for the map register message
	getparameters_reg(&params, 0);
				
	//build lisp register message
	memset(packet, 0, MAX_IP_PACKET);
	map_register = (struct map_register_pkt *) packet;
	map_register->lisp_type                   = LISP_MAP_REGISTER;
	map_register->rloc_probe                  = 0;
	map_register->want_map_notify             = 0;
	map_register->lisp_nonce0                 = htonl(nonce0); 
	map_register->lisp_nonce1                 = htonl(nonce1); 
	map_register->key_id                      = htons(01);
	map_register->key_len                     = htons(20);

	for (i = 0; i < 20; i++){
		map_register->auth_data[i]=0;
	}

	length = sizeof(struct map_register_pkt);
	ptr = CO(map_register,sizeof(struct map_register_pkt));
	//append eid record(s)
	
	eid_ptr = params.data;
	while (eid_ptr != NULL){

		//If there are any locators, append eid to lisp-register message
		if(eid_ptr->locator > 0 && eid_ptr->flag == 1) {
			rec_c++;
			eidtype  = (struct lisp_map_register_eidtype *) ptr;
			eidtype->record_ttl=UHTONL(eid_ptr->record_ttl);
			eidtype->record_ttl = UHTONL(eid_ptr->record_ttl);
			eidtype->auth_bit = 1; 
			eidtype->action = 0;
			eidtype->loc_count=eid_ptr->locator;
			
			//Check for the EID

			if (eid_ptr->ed_ip.ss_family == AF_INET6){
				eidtype->eid_mask_len=eid_ptr->eidlen;
				eidtype->eid_afi      = UHTONS(LISP_AFI_IPV6);
				t_sk6 = (struct sockaddr_in6 *)&eid_ptr->ed_ip;
				memcpy(eidtype->eid_prefix,&t_sk6->sin6_addr,sizeof(struct in6_addr));
				ptr = CO(ptr, sizeof(struct lisp_map_register_eidtype) + sizeof(struct in6_addr));
				length += sizeof(struct lisp_map_register_eidtype)+ sizeof(struct in6_addr);		
			}
			else if (eid_ptr->ed_ip.ss_family == AF_INET){
				eidtype->eid_mask_len=eid_ptr->eidlen;
				eidtype->eid_afi      = UHTONS(LISP_AFI_IP);
				t_sk = (struct sockaddr_in *)&eid_ptr->ed_ip;
				memcpy(eidtype->eid_prefix,&t_sk->sin_addr,sizeof(struct in_addr));
				ptr = CO(ptr, sizeof(struct lisp_map_register_eidtype) + sizeof(struct in_addr));
				length += sizeof(struct lisp_map_register_eidtype)+ sizeof(struct in_addr);		
			}
			else return 0;
   
			//append rloc record(s)		
			rloc_ptr = eid_ptr->rloc;
	
			while (rloc_ptr != NULL){

				loctype = (struct lisp_map_register_loctype *) ptr;
				loctype->priority=rloc_ptr->priority;
				loctype->weight=rloc_ptr->weight;

				loctype->mweight=0;					
				loctype->mpriority=255;
				loctype->reach_bit=1;
				loctype->rloc_probe=0;
				loctype->rloc_local=rloc_ptr->local;
				
				if (rloc_ptr->rl_ip.ss_family == AF_INET) {
					loctype->loc_afi = UHTONS(LISP_AFI_IP);
					t_sk = (struct sockaddr_in *)&rloc_ptr->rl_ip;
					memcpy(loctype->locator,&t_sk->sin_addr,sizeof(struct in_addr));
					ptr = CO(ptr, sizeof(struct lisp_map_register_loctype)+sizeof(struct in_addr));
					length += sizeof(struct lisp_map_register_loctype)+sizeof(struct in_addr);
				}
				else {
					loctype->loc_afi = UHTONS(LISP_AFI_IPV6);
					t_sk6 = (struct sockaddr_in6 *)&rloc_ptr->rl_ip;
					memcpy(loctype->locator,&t_sk6->sin6_addr,sizeof(struct in6_addr));
					ptr = CO(ptr, sizeof(struct lisp_map_register_loctype)+sizeof(struct in6_addr));
					length += sizeof(struct lisp_map_register_loctype)+sizeof(struct in6_addr);
				}
				rloc_ptr = rloc_ptr->rl_next;
			}//end rloc
			eid_ptr = eid_ptr->ed_next;
		}//end if
	}//end while
	map_register->record_count                = rec_c;

	ms_ptr = params.ms;
	while (ms_ptr != NULL){

		// Calculate Hash and fill in Authentication Data field
		for (i = 0; i < 20; i++){
			map_register->auth_data[i]=0;
		}

		memcpy(packet2, packet, length);			
		HMAC_SHA1_Init(&ctx);
		HMAC_SHA1_UpdateKey(&ctx, ms_ptr->ms_key, strlen((char *)ms_ptr->ms_key));
		HMAC_SHA1_EndKey(&ctx);
		HMAC_SHA1_StartMessage(&ctx);
		HMAC_SHA1_UpdateMessage(&ctx, packet2,length);
		HMAC_SHA1_EndMessage(buf, &ctx);
		
		char hex_output[20*2 + 1];
		for (i = 0; i < 20; i++){
			sprintf(hex_output + i * 2, "%02x", buf[i]);
			map_register->auth_data[i]=buf[i];
		}
		
		print_map_register(&packet, length);

		//send map register message to each map server
		int t_s;
		if (ms_ptr->ms_ip.ss_family == AF_INET)
			t_s = s;
		else
			t_s = s6;
		
		if ((nbytes = sendto(t_s,
								(const void *) packet,
								length,
								0,
								(struct sockaddr *)&ms_ptr->ms_ip,
								SA_LEN(ms_ptr->ms_ip.ss_family))) < 0) {
						perror("sendto");
						exit(BAD);

		}
			
		if (nbytes != length) {
			fprintf(stderr,
					"send_map_register: nbytes (%d) != packet_len(%d)\n",
					nbytes, length+32);
			exit(BAD);
		}
		ms_ptr = ms_ptr->ms_next;
	}
	pthread_exit(NULL);	
}
