/* 
 *	send_map_reply.c --
 * 
 *	lisp_register_reply -- OpenLISP control-plane 
 *
 *	Copyright (c) 2012 lip6 <http://www.lisp.ipv6.lip6.fr>
 *	Base on <Lig code> copyright by David Meyer <dmm@1-4-5.net>
 *	All rights reserved.
 *
 *	lip6
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
 *	send_map_reply
 *
 *	Sends a IP/UDP map-reply to answer for map-request
 *
 *
 *	Here's the packet we need to build:
 *
 *                      IP header (ip.src = <us>, ip.dst = <map-request sender>) 
 *                      UDP header (udp.srcport = <4342>, udp.dstport = map-request's source port) 
 *       map_reply -> struct map-request 
 *
 *	
 */
void * eid_search(struct map_db *, uchar, ushort, char *);

int send_map_reply(s,noncereply0,noncereply1,from,source_eid_afi,source_eid_prefix,source_eid_mask_len, probe)
  
	int		s;
	int source_eid_afi;
	struct sockaddr_storage	*from;
	unsigned int		noncereply0;
	unsigned int		noncereply1;
	char *source_eid_prefix;
	uchar source_eid_mask_len;
	uchar probe;
    
{

	struct map_db params;		
	struct sockaddr_in	*t_sk;
	struct sockaddr_in6	*t_sk6;

	struct sockaddr	*eid_addr;
	eid_addr=(struct sockaddr*) malloc(sizeof(struct sockaddr));

	struct map_reply_pkt	*map_reply=NULL;
	struct map_reply_eidtype  *eidtype	   = NULL;
    struct map_reply_loctype  *loctype    = NULL; 

	int length;
	int				nbytes		   = 0;
	uchar			packet[MAX_IP_PACKET];
	memset(packet, 0, MAX_IP_PACKET);
	void * ptr;

	struct eid_rloc_db *eid_ptr;
	struct rloc_db *rloc_ptr;
	int rec_c = 0;

	//Getting the parameters for the map reply message
	getparameters_reg(&params, source_eid_afi);
	eid_search(&params,source_eid_mask_len,source_eid_afi,source_eid_prefix);

	
	//build map-reply package
	map_reply	= (struct map_reply_pkt *) packet;
	map_reply->rsvd                        = 0;
	map_reply->echo_nonce_capable		   = 0;
	map_reply->security_bit				   = 0;
	map_reply->lisp_type                   = LISP_MAP_REPLY;
	map_reply->lisp_nonce0                 = noncereply0; 
	map_reply->lisp_nonce1                 = noncereply1;
	map_reply->rloc_probe                  = probe;     	

	length = sizeof(struct map_reply_pkt);
	ptr = CO(map_reply,sizeof(struct  map_reply_pkt));
	

	eid_ptr = params.data;
	rec_c = 0;
	while (eid_ptr != NULL){
		
		//Building the map reply message
		if(eid_ptr->locator > 0 && eid_ptr->flag == 1) {
			rec_c ++;
			
			eidtype  = (struct map_reply_eidtype *) ptr;
			
			eidtype->record_ttl=UHTONL(eid_ptr->record_ttl);
			eidtype->eid_mask_len	     = eid_ptr->eidlen;
			eidtype->action = 0;
			eidtype->auth_bit = 1; 
			eidtype->loc_count = eid_ptr->locator;

			//Check for the requested EID
			if (eid_ptr->ed_ip.ss_family == AF_INET6){
				t_sk6 = (struct sockaddr_in6 *)&eid_ptr->ed_ip;
				memcpy(eidtype->eid_prefix,&t_sk6->sin6_addr,sizeof(struct in6_addr));
				eidtype->eid_afi      = UHTONS(LISP_AFI_IPV6);
				ptr = CO(ptr, sizeof(struct map_reply_eidtype)+sizeof(struct in6_addr));
				length += sizeof(struct map_reply_eidtype)+sizeof(struct in6_addr);
			}
			else if (eid_ptr->ed_ip.ss_family == AF_INET){
				t_sk = (struct sockaddr_in *)&eid_ptr->ed_ip;
				memcpy(eidtype->eid_prefix,&t_sk->sin_addr,sizeof(struct in_addr));
				eidtype->eid_afi      = UHTONS(LISP_AFI_IP);
				ptr = CO(ptr, sizeof(struct map_reply_eidtype)+sizeof(struct in_addr));
				length += sizeof(struct map_reply_eidtype)+sizeof(struct in_addr);
			}
			else return(BAD);
					 

			rloc_ptr = eid_ptr->rloc;
	
			while (rloc_ptr != NULL){
				loctype = (struct map_reply_loctype *) ptr;
				loctype->priority=rloc_ptr->priority;
				loctype->weight=rloc_ptr->weight;
				loctype->mpriority=255;
				loctype->mweight=0;					
				loctype->rloc_local=rloc_ptr->local;
				loctype->rloc_prob=0;
				loctype->reach_bit=1;

				if (rloc_ptr->rl_ip.ss_family == AF_INET) {
					loctype->loc_afi = UHTONS(LISP_AFI_IP);
					t_sk = (struct sockaddr_in *)&rloc_ptr->rl_ip;
					memcpy(loctype->locator,&t_sk->sin_addr,sizeof(struct in_addr));
					ptr = CO(ptr, sizeof(struct map_reply_loctype)+sizeof(struct in_addr));
					length += sizeof(struct map_reply_loctype)+sizeof(struct in_addr);
				}
				else {
					loctype->loc_afi = UHTONS(LISP_AFI_IPV6);
					t_sk6 = (struct sockaddr_in6 *)&rloc_ptr->rl_ip;
					memcpy(loctype->locator,&t_sk6->sin6_addr,sizeof(struct in6_addr));
					ptr = CO(ptr, sizeof(struct map_reply_loctype)+sizeof(struct in6_addr));
					length += sizeof(struct map_reply_loctype)+sizeof(struct in6_addr);
				}
				rloc_ptr = rloc_ptr->rl_next;
			}//end rloc
			eid_ptr = eid_ptr->ed_next;
		}//end if
	}//end while
	
	map_reply->record_count                =  rec_c;

	print_map_reply(packet, length);
	
	//Send the packet
	if ((nbytes = sendto(s,
			(const void *) packet,
			length,
			0,
			(struct sockaddr *)from,
			SA_LEN(from->ss_family))) < 0) {
		perror("sendto");
		exit(BAD);
	}

	if (nbytes != (length)) {
		fprintf(stderr,
				"send_map_reply: nbytes (%d) != length(%d)\n",
				nbytes, length);
		exit(BAD);
	}
	return(GOOD);
}




//thread reply for request mapping

void * mapreply(void *d){
	
	while(1){
	
		uchar		reply[4096];

		struct	map_reply_data * map_reply_data;
		map_reply_data = (struct	map_reply_data *)d;

		int t_s;
		int from_afi;
		struct sockaddr_in * t_from;
		struct sockaddr_in6 * t_from6;

		struct sockaddr_storage	from;			
		int source_eid_afi;
		char source_eid[INET6_ADDRSTRLEN];
		char eid_mask_len;


		socklen_t fromlen = sizeof(struct sockaddr_storage);
		int rcvl;
		if ((rcvl = recvfrom(map_reply_data->l_sk,
					 reply,
					 MAX_IP_PACKET,
					0,
					(struct sockaddr *)&from,
					&fromlen)) < 0) {
			perror("recvfrom");
			exit(BAD);
		}
		else {
			char ipstr[INET6_ADDRSTRLEN];
			from_afi = from.ss_family;
			
			if (from_afi == AF_INET) {
				t_from = (struct sockaddr_in *)&from;
				inet_ntop(from_afi, &t_from->sin_addr, ipstr, INET6_ADDRSTRLEN);	
			}
			else if(from_afi == AF_INET6) {
				t_from6 = (struct sockaddr_in6 *)&from;
				inet_ntop(from_afi, &t_from6->sin6_addr, ipstr, INET6_ADDRSTRLEN);	
			}
			printf("From: %s\n",ipstr);

			print_map_request((struct map_request_pkt *)reply,rcvl);

			unsigned int noncereply0 ;
			unsigned int noncereply1;
			uchar probe;
			

			if (((struct map_request_pkt *) reply)->lisp_type == LISP_MAP_REQUEST) //Map-Request from local RLOC for probing
			{
				//get params for map request
				
				int i;
				struct map_request_pkt * map_request = (struct map_request_pkt *) reply;
				void *ptr = CO(map_request, sizeof(struct map_request_pkt) - 2  );
				
				//Must have at least one EID prefix
				if (map_request->record_count == 0) {
					return 0;
				}

				//Pass EID AFI
				if (ntohs(map_request->source_eid_afi) == LISP_AFI_IP ) {
					//memcpy(&from.sin_addr, &map_request->itr_afi, sizeof(struct in_addr));
					ptr = CO(ptr, sizeof(struct in_addr));
				}
				else if (ntohs(map_request->source_eid_afi) == LISP_AFI_IPV6) {
					ptr = CO(ptr, sizeof(struct in6_addr));
				}
				
				//Pass all ITR AFI,must there is at lease 1 ITR AFI
				for (i = 0; i<=map_request->irc; i++ ) {
					if (ntohs(*((ushort*)ptr)) == LISP_AFI_IP ) {
						ptr = CO(ptr, sizeof(struct in_addr)+2);
					}
					else if (ntohs(*((ushort*)ptr)) == LISP_AFI_IPV6 ) {
						ptr = CO(ptr, sizeof(struct in6_addr)+2);
					}
				}

				//Get one of EID prefix (In future draft must support multi EID prefix)
				struct	map_request_eid *map_request_eid;
				
				//for (i = 0; i<= map_request->record_count; i++ ) {

				map_request_eid = (struct map_request_eid *) ptr;
				eid_mask_len = map_request_eid->eid_mask_len;
				ptr = CO(ptr,2);
				source_eid_afi = ntohs(map_request_eid->eid_prefix_afi);

				if (ntohs(map_request_eid->eid_prefix_afi) == LISP_AFI_IP ) {
					memcpy(source_eid, map_request_eid->eid_prefix, sizeof(struct in_addr));
					ptr = CO(ptr, sizeof(struct in_addr)+2);
				}
				else if (ntohs(map_request_eid->eid_prefix_afi) == LISP_AFI_IPV6 ) {
					memcpy(source_eid, map_request_eid->eid_prefix, sizeof(struct in6_addr));
					ptr = CO(ptr, sizeof(struct in6_addr)+2);
				}
				
				noncereply0= map_request->lisp_nonce0;
				noncereply1= map_request->lisp_nonce1;
				probe =		map_request->rloc_probe;		

				//call send_map_reply function to send reply
				if (send_map_reply(map_reply_data->l_sk,
									noncereply0,
									noncereply1,
	      							(struct sockaddr *)&from,source_eid_afi,source_eid,eid_mask_len, probe))
				{
						fprintf(stderr, "send_map_reply: can't send map-reply\n");
	    		}
				
	
			}
            else if (((struct lisp_control_pkt *) reply)->type == LISP_ENCAP_CONTROL_TYPE)//Map encapsulated package
			{
	    		
				struct map_request_pkt	*map_request;
				struct map_request_eid	*map_request_eid;
				uchar probe;
				struct ip			*iph;
				struct ip6_hdr		*iph6;
				struct udphdr		*udph;
				
				iph		= (struct ip *)  CO(reply,  sizeof(struct lisp_control_pkt));
				
				int ipversion = iph->ip_v;
				if (ipversion == 4){
					iph		= (struct ip *)  CO(reply,  sizeof(struct lisp_control_pkt));
					iph6	= NULL;
					udph	= (struct udphdr *) CO(iph,  sizeof(struct ip));
				}
				else if (ipversion == 6){
					iph		= NULL;
					iph6	= (struct ip6_hdr *)  CO(reply,  sizeof(struct lisp_control_pkt));
					udph	= (struct udphdr *) CO(iph6,  sizeof(struct ip6_hdr));
				}
				else{
					printf("Error ip version\n");
					exit(2);
				}
				map_request = (struct map_request_pkt *)  CO(udph, sizeof(struct udphdr));
				
				//pass over ITR-RLOC records..
				void *ptr;
				ptr = CO(map_request, sizeof(struct map_request_pkt)-2);
				if (map_request->source_eid_afi == LISP_AFI_IP) {
					ptr = CO(ptr, sizeof(struct in_addr));
				}
				else if (map_request->source_eid_afi == LISP_AFI_IPV6) {
					ptr = CO(ptr, sizeof(struct in6_addr));
				}

				int k;
				for (k = 0; k <= map_request->irc; k++ ) {
					if (ntohs(*(ushort *)ptr) == LISP_AFI_IP) {
						ptr = CO(ptr, sizeof(struct in_addr)+2);												
					}
					else if (ntohs(*(ushort *)ptr) == LISP_AFI_IPV6) {
						ptr = CO(ptr, sizeof(struct in6_addr)+2); 
					}
					
				}

				map_request_eid = (struct map_request_eid *)ptr;
				source_eid_afi =  ntohs(map_request_eid->eid_prefix_afi);
				eid_mask_len = map_request_eid->eid_mask_len;

				struct in_addr *tmp2;
				tmp2 = (struct in_addr *)&map_request_eid->eid_prefix;
				
				if (ntohs(map_request_eid->eid_prefix_afi) == LISP_AFI_IP ) {
					memcpy(source_eid, map_request_eid->eid_prefix, sizeof(struct in_addr));
				}
				else if (ntohs(map_request_eid->eid_prefix_afi) == LISP_AFI_IPV6 ) {
					memcpy(source_eid, map_request_eid->eid_prefix, sizeof(struct in6_addr));
				}
				noncereply0= map_request->lisp_nonce0;
				noncereply1= map_request->lisp_nonce1;
				probe =		map_request->rloc_probe;
		
				if (ipversion == 4){
					t_from = (struct sockaddr_in *)&from;
					t_from->sin_port = udph->uh_sport;
					memcpy(&t_from->sin_addr, &iph->ip_src, sizeof(struct in_addr));
					t_from->sin_family = AF_INET;
					t_s = map_reply_data->sk;
				}
				else if(ipversion == 6){
					t_from6 = (struct sockaddr_in6 *)&from;
					t_from6->sin6_port = udph->uh_sport;
					memcpy(&t_from6->sin6_addr, &iph6->ip6_src, sizeof(struct in6_addr));
					t_from6->sin6_family = AF_INET6;
					t_s = map_reply_data->sk6;
				}
				

				if (send_map_reply(t_s,
									noncereply0,
									noncereply1,
									(struct sockaddr *)&from,source_eid_afi,source_eid,eid_mask_len,probe)){
					fprintf(stderr, "send_map_reply: can't send map-reply\n");
				}

			 }//end else   
		}//end send
	}//end while
}

//Compare bit by bit of two varible, return the number of bits equal
int bcp(void * bptr1, void * bptr2, int s){
	unsigned char *hi1, *hi2;
	unsigned char t1,t2;
	int i = 0;
	int c = 0;
	while(i < s){
		if ((i == 0) || (i % 8 == 0) ) {//next blog 8bits
				hi1 = (unsigned char *)bptr1 + (i / 8);
				hi2 = (unsigned char *)bptr2 + (i / 8);
				t1 = *hi1;
				t2 = *hi2;
		}
		//compare 1st bit
		if ( ((~(t1 ^ t2)) & 0x80) != 0)
			c++;
		else
			break;

		t1=t1 << 1;
		t2=t2 << 1;
		i++;
	}
	return c;
}

//Search eid match with eid_prefix
void * eid_search(params,eid_mask_len,eid_prefix_afi,eid_prefix)
	struct map_db *params;
	uchar eid_mask_len;
	ushort	eid_prefix_afi;
	char *eid_prefix;
{
	struct eid_rloc_db *eid;
	struct eid_rloc_db *eid_next;
	struct eid_rloc_db *eid_ptr[32];//array content points to all eid
	uchar * eid_ip[32]; //aray content ip of all eid
	int eid_mask[32]; //array content mask len of all eid
	int eid_match[32];//array content result of comparing bw eid and eid_prefix

	struct sockaddr_in * tmp;
	struct sockaddr_in6 * tmp6;
	int c = 0;
	int i;
	int m;
	//parse all eid
	eid = params->data;
	eid_prefix_afi = (eid_prefix_afi == LISP_AFI_IP)? AF_INET:AF_INET6;
	for (c = 0; c < 32 ;c++ ) {
		eid_ptr[c] = NULL;
	}
	c = 0;
	m = 0;
	while (eid != NULL) {
		if (eid->ed_ip.ss_family == eid_prefix_afi) {
			eid_ptr[c] = eid;
			eid_ip[c] = malloc(((eid_prefix_afi == AF_INET)?sizeof(struct in_addr):sizeof(struct in6_addr) )*sizeof(char));
			if (eid_prefix_afi == AF_INET) {
				tmp = (struct sockaddr_in *)&eid->ed_ip;
				memcpy(eid_ip[c],&tmp->sin_addr,sizeof(struct in_addr));
			}
			else{
				tmp6 = (struct sockaddr_in6 *)&eid->ed_ip;
				memcpy(eid_ip[c],&tmp6->sin6_addr,sizeof(struct in6_addr));
			}

			eid_mask[c] = eid->eidlen;
			eid_match[c] = bcp(eid_ip[c], eid_prefix, (eid_mask[c] > eid_mask_len)?eid_mask_len:eid_mask[c]);
			if (eid_match[c] > m) {
				m = eid_match[c];
			}
			c++;
		}

		eid = eid->ed_next;
	}//end while
	eid = eid_next = NULL;

	for (i=0; i<c ;i++ ) {
		if (eid_match[i] == m) {
			if (eid == NULL) {
				eid = eid_ptr[i];
				eid_next = eid;
			}else {
				eid_next->ed_next = eid_ptr[i];
				eid_next = eid_ptr[i];
			}
			eid_next->ed_next = NULL;
		}
	}
	params->data = eid;
}
