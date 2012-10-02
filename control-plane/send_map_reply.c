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
void changepriority(int s, void *message, void *d);

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
	void *from_addr;
	if (from->ss_family == AF_INET) {
		from_addr = &((struct sockaddr_in *)from)->sin_addr;		
	}
	else{
		from_addr = &((struct sockaddr_in6 *)from)->sin6_addr;	
	}

	
	logprocess(source_eid_prefix, source_eid_mask_len, (source_eid_afi == LISP_AFI_IP)?AF_INET:AF_INET6,(char *)from_addr, from->ss_family);

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
	
		printf("-----------------------------\n");
		uchar		reply[4096];

		struct	map_reply_data * map_reply_data;
		map_reply_data = (struct	map_reply_data *)d;
		
		struct map_register_data mrd;
		mrd.register_socket = map_reply_data->sk;
		mrd.register_socket6 = map_reply_data->sk6;
		make_nonce(&mrd.nonce0,&mrd.nonce1);

		int t_s;
		int from_afi;
		struct sockaddr_in * t_from;
		struct sockaddr_in6 * t_from6;

		struct sockaddr_storage	from;			
		int source_eid_afi;
		char source_eid[INET6_ADDRSTRLEN];
		char eid_mask_len;
		char source_rloc[INET6_ADDRSTRLEN];
		int smr_bit;


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

			//print_map_request((struct map_request_pkt *)reply,rcvl);

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
					continue;
				}

				smr_bit = map_request->smr_bit;
				if (smr_bit == 1){
					smr_process(map_request, (struct sockaddr_storage *)&from);
					continue;
				}

				//Pass EID AFI
				if (ntohs(map_request->source_eid_afi) == LISP_AFI_IP ) {
					//memcpy(&from.sin_addr, &map_request->itr_afi, sizeof(struct in_addr));
					ptr = CO(ptr, sizeof(struct in_addr));
				}
				else if (ntohs(map_request->source_eid_afi) == LISP_AFI_IPV6) {
					ptr = CO(ptr, sizeof(struct in6_addr));
				}
				memcpy(source_rloc, map_request->originating_itr_rloc, sizeof(struct in6_addr));
				
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
				smr_bit = map_request->smr_bit;
				if (smr_bit == 1){
					smr_process(map_request, (struct sockaddr_storage *)&from);
					continue;
				}

				if (map_request->source_eid_afi == LISP_AFI_IP) {
					ptr = CO(ptr, sizeof(struct in_addr));
				}
				else if (map_request->source_eid_afi == LISP_AFI_IPV6) {
					ptr = CO(ptr, sizeof(struct in6_addr));
				}
				

				memcpy(source_rloc, map_request->originating_itr_rloc, sizeof(struct in6_addr));
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
			else if (((struct lisp_change_priority_pkt *) reply)->type == LISP_CHANGE_PRIORITY)
				{
					printf("I'm in map reply\n");					
					changepriority(map_reply_data->l_sk,reply, &mrd);
				}//end if
				//else {printf("not matched\n");}
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
	int max_mask = 0;
	while (eid != NULL) {
		if (eid->ed_ip.ss_family == eid_prefix_afi) {
			eid_ptr[c] = eid;
			eid_ip[c] = malloc(((eid_prefix_afi == AF_INET)?sizeof(struct in_addr):sizeof(struct in6_addr) )*sizeof(char));
			if (eid_prefix_afi == AF_INET) {
				tmp = (struct sockaddr_in *)&eid->ed_ip;
				memcpy(eid_ip[c],&tmp->sin_addr,sizeof(struct in_addr));
				max_mask = 32;
			}
			else{
				tmp6 = (struct sockaddr_in6 *)&eid->ed_ip;
				memcpy(eid_ip[c],&tmp6->sin6_addr,sizeof(struct in6_addr));
				max_mask = 128;
			}

			eid_mask[c] = eid->eidlen;
			eid_match[c] = bcp(eid_ip[c], eid_prefix, max_mask);
                        if ( (eid_match[c] >= eid->eidlen) &&(eid_match[c] >= m)) {
                                m = eid_match[c];
                        }
                        else
                                eid_match[c] = -1;
                        c++;

		}
		eid = eid->ed_next;
	}//end while
	eid = eid_next = NULL;
	int n = m;
	for (i=0; i<c ;i++ ) {
              if ( eid_match[i] == n ) {
                        if ( (eid_match[i] + eid_ptr[i]->eidlen) >= m) {
                                m = eid_match[i]+ eid_ptr[i]->eidlen;
                                eid_match[i] += eid_ptr[i]->eidlen;
                        }
                        else
                                eid_match[i] = -1;
                }
                else
                        eid_match[i] = -1;

		
	}
	for (i=0; i<c ;i++ ) {
              if ( eid_match[i] == m) {
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


char root_dir[] = "/var/log/lisp/";
struct log_line {
	time_t ltime; //how long rloc was in log
	char liptype;//0:ipv4, 1:ipv6
	char lip[INET6_ADDRSTRLEN];
} log_arr[100];

//Check if a log of an EID is exist or not
//eid in humal format: 153.16.44.117
int logexist(char *eid, char *fname){
	sprintf(fname, "%s%s.log", root_dir,eid);
	FILE *file = fopen(fname,"r");
	if (file != NULL) {
		fclose(file);
		return 1;
	}
	printf("not exist");
	return 0;
}

//load log file to array
int log2arr(char *fname, int *log_size){
	int i, j;	
	FILE *file = fopen(fname, "r"); /* try to open the file */
	struct timespec ctime;
	clock_gettime(CLOCK_REALTIME, &ctime);

	if ( file != NULL ){
		char line[BUFSIZ]; /* space to read a line into */
		j = 0;

		while ( fgets(line, sizeof line, file) != NULL ) /* read each line */
		{
			char data[50][255];
			char *token = line;
			char * sep_t =  "\t ";
			char * tk;
			char * ptr;
			
			//skip empty and comment line
			if (token[1] == '\0') {
				continue;
			}
			
			//split line
			i = 0;
			puts(line);			
			for (tk = strtok_r(line, sep_t, &ptr); tk ; tk = strtok_r(NULL, sep_t, &ptr)){
				strcpy(data[i++], tk);
			}

			token = data[i-1];
			//token[strlen(data[i-1])-1] = '\0';
			//skip log which expired (default is a day)
			if ( (unsigned long)(ctime.tv_sec) - 86400 < atoi(data[0])) {
				
				log_arr[j].ltime = atoi(data[0]);
				log_arr[j].liptype = atoi(data[1]);
				strncpy(log_arr[j++].lip,data[2], strlen(data[2]));
			}
		}
		*log_size = j;
		fclose(file);
	}
	return 0;
}

//Check if an EID is in log or not
int logsearch( int log_size, char *rloc, int *locator){
	int i;
	for (i = 0; i< log_size ; i++ ) {
		if (strncmp(log_arr[i].lip,rloc,strlen(rloc)) == 0) {
			*locator = i;
			return 1;
		}
	}
	return 0;
}


//proccess log
int logprocess(char *_eid, int _eid_mask, int _eid_af, char *_rloc, int _rloc_af){
	char fname[255];
	int log_size;
	int i;
	int place;
	time_t  ctime;
	time(&ctime);

	char eid[INET6_ADDRSTRLEN];
	char rloc[INET6_ADDRSTRLEN];
	inet_ntop(_eid_af, _eid, eid, INET6_ADDRSTRLEN);
	inet_ntop(_rloc_af, _rloc, rloc, INET6_ADDRSTRLEN);
	//printf("========================================================================\n");
	//printf("ipstr = %s\n",eid);
	//printf("mask len = %d\n",_eid_mask);
	//printf("rlocstr = %s\n",rloc);
	//printf("========================================================================\n");

	int max_mask = (_eid_af == AF_INET)?32:128;
	if (_eid_mask != max_mask ) {
		return 1;
	}

	//1.Check if exist a log of this EID
		//if exist,load log file to array, check to delete rloc expired 
		//else change to step 2.2
	if (logexist(eid, fname)) {
		//printf("exist file %s\n---------------",fname);
		log2arr(fname,&log_size);
	}
	else
		log_size = 0;

	//printf("log_size = %d\n",log_size);
	//2.Check if exist this rlog in log file
		//if exist, update TTL of it in array log
		//2.2. else add new rloc to array log
	if (logsearch(log_size, rloc, &place)) {
		//update rloc
		log_arr[place].ltime = ctime;
	}
	else{
		//add rloc
		log_arr[log_size].ltime = ctime;
		struct addrinfo *res;
		ip2sockaddr(rloc, &res, 0);
		if (res->ai_family == AF_INET)
			log_arr[log_size].liptype = 0;
		else
			log_arr[log_size].liptype = 1;
		
		strncpy(log_arr[log_size].lip,rloc,strlen(rloc));
		//printf("=================%s\n",log_arr[log_size].lip);
		log_size++;
	}
	//3.Write log file
	FILE *file = fopen(fname,"w");
	for (i = 0; i< log_size ; i++ ) {
		fprintf(file,"%lu\t%d\t%s\n",(unsigned long)(log_arr[i].ltime),log_arr[i].liptype,log_arr[i].lip);
		//printf("%lu\t%d\t%s\n",(unsigned long)(log_arr[i].ltime),log_arr[i].liptype,log_arr[i].lip);
	}
	fclose(file);
	return 0;
}

//get log and put to List-IP
//_eid_af: AF_INET or AF_INET6
//eid: format as in_addr or in6_addr
//list_ip: poi to result
//retun: length of list_ip;

int logget(int _eid_af, char *_eid, void *list_ip, int *count){
	char fname[255];
	int log_size;
	int i;
	char eid[INET6_ADDRSTRLEN];
	inet_ntop(_eid_af, _eid, eid, INET6_ADDRSTRLEN);
	struct lisp_change_priority_rec *rec;
	struct addrinfo *res;
	struct sockaddr_in *ska;
	struct sockaddr_in6 *ska6;
	int length = 0;
	//1.Check if exist a log of this EID
		//if exist,load log file to array, check to delete rloc expired 
		//else exit
	if (logexist(eid, fname)) {
		log2arr(fname,&log_size);
	}
	else
		return 0;
	count = &log_size;
	//put log to list-IP
	rec = (struct lisp_change_priority_rec *)list_ip;
	for (i = 0; i< log_size ; i++ ) {
		rec->l_ip_afi = (log_arr[i].liptype == 0)?LISP_AFI_IP:LISP_AFI_IPV6;
		ip2sockaddr(log_arr[i].lip, &res, 0);
		if (res->ai_family == AF_INET) {
			ska = (struct sockaddr_in *)(res->ai_addr);
			memcpy(rec->l_ip, &(ska->sin_addr),sizeof(struct in_addr));
			rec = CO(rec,4+sizeof(struct in_addr));
			length += 4+sizeof(struct in_addr);
		}else{
			ska6 = (struct sockaddr_in6 *)res->ai_addr;
			memcpy(rec->l_ip, &(ska6->sin6_addr),sizeof(struct in6_addr));
			rec = CO(rec,4+sizeof(struct in6_addr));
			length += 4+sizeof(struct in6_addr);
		}
	}
	return length;
}