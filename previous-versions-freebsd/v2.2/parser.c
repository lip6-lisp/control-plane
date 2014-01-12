
#include <expat.h>
#include "lib.h"

#ifdef XML_LARGE_SIZE
	#if defined(XML_USE_MSC_EXTENSIONS) && _MSC_VER < 1400
		#define XML_FMT_INT_MOD "I64"
	#else
		#define XML_FMT_INT_MOD "ll"
	#endif
#else
	#define XML_FMT_INT_MOD "l"
#endif

static XML_Parser parser;
static const char * _xml_name;
static char * _prefix;
static struct mapping_flags _mflags;
static int _fam = AF_INET;
static void * _mapping;
u_char _fncs;
char * config_file[4];

	int 
_insert_prio_ordered(void * data, void * entry)
{
	uint8_t _a;
	uint8_t _b;
	_a = ((struct map_entry *)data)->priority;
	_b = ((struct map_entry *)entry)->priority;

	return (_a - _b);
}

	int 
xml_configure(const char * filename,
	void (* startElement)(void *, const char *, const char **),
	void (* endElement)(void *, const char *),
	void (* getElementValue)(void *, const XML_Char *, int)
)
{
	int done;
	//char buf[BUFSIZ];
	char buf[900000];
	FILE * config;


	parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, NULL);

	XML_SetStartElementHandler(parser, startElement);
	XML_SetEndElementHandler(parser, endElement);

	XML_SetCharacterDataHandler(parser, getElementValue);

	config = fopen(filename, "r");

	do {
		int len = (int)fread(buf, 1, sizeof(buf), config);
		done = len < sizeof(buf);
		//buf[len]='\0';
		//printf("-------------\n%s\n---------\n",buf);
		if (XML_Parse(parser, buf, len, done) == XML_STATUS_ERROR) {
			fprintf(stderr, "%s at line %" XML_FMT_INT_MOD "u\n",\
					XML_ErrorString(XML_GetErrorCode(parser)),\
					XML_GetCurrentLineNumber(parser));
			fclose(config);
			return 1;
		}
	} while (!done);
	XML_ParserFree(parser);

	fclose(config);
	return 0;
}

//====================================================================
/* Parse for map-resolve configure */
struct ms_entry * xtr_ms_entry;
struct mr_entry * xtr_mr_entry;

	static void XMLCALL
xtr_startElement(void *userData, const char *name, const char **atts)
{
	int len;
	struct map_entry * entry;
		
	if(0 == strcasecmp(name, "eid")) {
		while(*atts){
			/* EID prefix */
			if(0 == strcasecmp(*atts, "prefix")){
				/*get eid-prefix */
				struct prefix p1;
				atts++;
				len = strlen(*atts);
				_prefix = (char *)calloc(1, len+1);
				memcpy(_prefix, *atts, len);
				*(_prefix + len) = '\0';
				str2prefix (_prefix, &p1);
				apply_mask(&p1);				
				/* append to db */
				_mapping = generic_mapping_new(&p1);
				bzero(&_mflags, sizeof(struct mapping_flags));
				_mflags.range = _MAPP_XTR;
				list_insert(etr_db, _mapping, NULL);
			}
			/* ACT bits */
			if(0 == strcasecmp(*atts, "act")){
				atts++;
				_mflags.act = atoi(*atts);
			}
			/* Echo-noncable */
			if(0 == strcasecmp(*atts, "a")){
				atts++;
				_mflags.A = (strcasecmp(*atts, "true")==0);
			}
			/* Version */
			if(0 == strcasecmp(*atts, "version")){
				atts++;
				_mflags.version = atoi(*atts);	
			}
			/* TTL */
			if(0 == strcasecmp(*atts, "ttl")){
				atts++;
				_mflags.ttl = atoi(*atts);  
			}
			/**/
			atts++;
		}
	} else {
		if( 0 == strcasecmp(name, "address") ||
			0 == strcasecmp(name, "ms") ||
			0 == strcasecmp(name, "mr")){
			
			if(0 == strcasecmp(name, "ms")){
				xtr_ms_entry = calloc(1, sizeof(struct ms_entry));
				list_insert(xtr_ms, xtr_ms_entry, NULL);
			}
						
			if(0 == strcasecmp(name, "address"))
				_fam = AF_INET;
				
			while(*atts){
				if(0 == strcasecmp(*atts, "family")){
					atts++;
					_fam = (0 == strcasecmp(*atts, "IPV6"))?AF_INET6:AF_INET;
				}
				if(0 == strcasecmp(*atts, "key")){
					atts++;
					len = strlen(*atts);
					xtr_ms_entry->key = (char *)calloc(1, len+1);
					memcpy(xtr_ms_entry->key, *atts, len);
					xtr_ms_entry->key[len] = '\0';	
				}
				atts++;
			}
		}
	}
	if(!userData){
		entry = calloc(1, sizeof(struct map_entry));
		XML_SetUserData(parser, entry);
	}
	_xml_name = name;
}

	static void XMLCALL
xtr_endElement(void *userData, const char *name)
{
	struct map_entry * entry;
	
	if(0 == strcasecmp(name, "rloc")){
		entry = (struct map_entry*)userData;
		XML_SetUserData(parser, NULL);
		generic_mapping_add_rloc(_mapping, entry);
	}else{
		if(0 == strcasecmp(name, "eid")){
			generic_mapping_set_flags(_mapping, &_mflags);			
			bzero(&_mflags, sizeof(struct mapping_flags));
			free(_prefix);
			_prefix = NULL;
		}
		
		if(0 == strcasecmp(name, "ms")){
			xtr_ms_entry = NULL;
		}
		
		if(0 == strcasecmp(name, "mr")){
			xtr_mr_entry = NULL;
		}	
	}
}

	static void XMLCALL
xtr_getElementValue(void *userData, const XML_Char *s, int len)
{
	struct map_entry * entry;
	void * ptr;
	
	char buf[len+1];

	buf[len] = '\0';
	memcpy(buf, s, len);

	entry = (struct map_entry *)userData;

	if(0 == strcasecmp(_xml_name, "priority")){
		entry->priority = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "m_priority")){
		entry->m_priority = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "weight")){
		entry->weight = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "m_weight")){
		entry->m_weight = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "reachable")){
		entry->r = (strcasecmp(buf, "true")==0);
	}else if(0 == strcasecmp(_xml_name, "local")){
		entry->L = (strcasecmp(buf, "true")==0);
	}else if(0 == strcasecmp(_xml_name, "rloc-probing")){
		entry->p = (strcasecmp(buf, "true")==0);
	}else if(0 == strcasecmp(_xml_name, "address")){
		entry->rloc.sa.sa_family = _fam;
		switch(_fam){
			case AF_INET:
				ptr = &entry->rloc.sin.sin_addr;
				break;
			case AF_INET6:
				ptr = &entry->rloc.sin6.sin6_addr;
				break;
			default:
				_fam = AF_INET;
				ptr = &entry->rloc.sa.sa_data;
				break;
		}
		inet_pton(_fam, buf, ptr);
		_fam = AF_INET;
	}else {
			if(0 == strcasecmp(_xml_name, "ms")){
				switch(_fam){
					case AF_INET:
						xtr_ms_entry->addr.sin.sin_family = _fam;
						xtr_ms_entry->addr.sin.sin_port = htons(LISP_CP_PORT);
						ptr = &xtr_ms_entry->addr.sin.sin_addr;
					break;
					case AF_INET6:
						xtr_ms_entry->addr.sin6.sin6_family = _fam;
						xtr_ms_entry->addr.sin6.sin6_port = htons(LISP_CP_PORT);
						ptr = &xtr_ms_entry->addr.sin6.sin6_addr;
					break;
					default:
						xtr_ms_entry->addr.sa.sa_family = AF_INET;
						xtr_ms_entry->addr.sin.sin_port = htons(LISP_CP_PORT);
						ptr = &xtr_ms_entry->addr.sa.sa_data;
						break;
				}
				inet_pton(_fam, buf, ptr);
				_fam = AF_INET;
			}else
				if(0 == strcasecmp(_xml_name, "mr")){
					xtr_mr_entry = calloc(1, sizeof(struct mr_entry));
					union sockunion * mr = &xtr_mr_entry->addr;
					switch(_fam){
						case AF_INET:
							mr->sin.sin_family = _fam;
							mr->sin.sin_port = LISP_CP_PORT;
							ptr = &mr->sin.sin_addr;
						break;
						case AF_INET6:
							mr->sin6.sin6_family = _fam;
							mr->sin6.sin6_port = LISP_CP_PORT;
							ptr = &mr->sin6.sin6_addr;
						break;
						default:
							mr->sa.sa_family = AF_INET;
							mr->sin.sin_port = LISP_CP_PORT;
							ptr = &mr->sa.sa_data;
							break;
					}
					inet_pton(_fam, buf, ptr);
					list_insert(xtr_mr,xtr_mr_entry, NULL);
					_fam = AF_INET;					
				}
	}

	_xml_name = "DUMMY";
}

//====================================================================
/*Parse for map-resolve configure */

	static void XMLCALL
mr_startElement(void *userData, const char *name, const char **atts)
{
	int len;
	struct map_entry * entry;
	if(0 == strcasecmp(name, "eid")) {
		_mflags.iid = 0;
		while(*atts){
			/* EID prefix */
			if(0 == strcasecmp(*atts, "prefix")){
				struct prefix p1;
				atts++;
				len = strlen(*atts);
				_prefix = (char *)calloc(1, len+1);
				memcpy(_prefix, *atts, len);
				*(_prefix + len) = '\0';
				str2prefix (_prefix, &p1);
				apply_mask(&p1);
				
				_mapping = generic_mapping_new(&p1);
				bzero(&_mflags, sizeof(struct mapping_flags));
				_mflags.range = _MAPP;
				
				if(!_mapping){
					printf("Configure error:%s\n",*atts);
					exit(0);
				}
				
			}
			/* ACT bits */
			if(0 == strcasecmp(*atts, "act")){
				atts++;
				_mflags.act = atoi(*atts);
			}
			if(0 == strcasecmp(*atts, "iid")){
				atts++;
				_mflags.iid = atoi(*atts);
			}
			/* Echo-noncable */
			if(0 == strcasecmp(*atts, "a")){
				atts++;
				_mflags.A = (strcasecmp(*atts, "true")==0);
			}
			/* Version */
			if(0 == strcasecmp(*atts, "version")){
				atts++;
				_mflags.version = atoi(*atts);	
			}
			/* TTL */
			if(0 == strcasecmp(*atts, "ttl")){
				atts++;
				_mflags.ttl = atoi(*atts);  
			}
			/* Referral */
			if(0 == strcasecmp(*atts, "referral")){
				atts++;
				//in case can not detect type of referral, set to NODE_REFERRAL;
				_mflags.referral = LISP_REFERRAL_NODE_REFERRAL+1;
				if( strcasecmp(*atts, "true")==0 || strcasecmp(*atts, "node")==0  )
					_mflags.referral = LISP_REFERRAL_NODE_REFERRAL+1;
				if( strcasecmp(*atts, "ms")==0)
					_mflags.referral = LISP_REFERRAL_MS_REFERRAL+1;					
			}
			/* Incomplete Referral */
			if(0 == strcasecmp(*atts, "incomplete")){
				atts++;
				_mflags.incomplete = (strcasecmp(*atts, "true")==0);
			}

			/**/
			atts++;
		}
	} else if(0 == strcasecmp(name, "address")){
		while(*atts){
			if(0 == strcasecmp(*atts, "family")){
				atts++;
				_fam = (0 == strcasecmp(*atts, "IPV6"))?AF_INET6:AF_INET;
			}
			else
				_fam = AF_INET;
			atts++;
		}
		
	}
	if(!userData){
		entry = calloc(1, sizeof(struct map_entry));
		XML_SetUserData(parser, entry);
	}
	_xml_name = name;
}

	static void XMLCALL
mr_endElement(void *userData, const char *name)
{
	struct map_entry * entry;
	
	if(0 == strcasecmp(name, "rloc")){
		entry = (struct map_entry*)userData;
		XML_SetUserData(parser, NULL);
		generic_mapping_add_rloc(_mapping, entry);
	}else if(0 == strcasecmp(name, "eid")){
		generic_mapping_set_flags(_mapping, &_mflags);
		bzero(&_mflags, sizeof(struct mapping_flags));		
		free(_prefix);
		_prefix = NULL;
	}
}

	static void XMLCALL
mr_getElementValue(void *userData, const XML_Char *s, int len)
{
	struct map_entry * entry;
	struct db_table * db;
	struct db_node *dn;
	struct prefix  pf;
	
	char buf[len+1];

	buf[len] = '\0';
	memcpy(buf, s, len);

	entry = (struct map_entry *)userData;

	if(0 == strcasecmp(_xml_name, "priority")){
		entry->priority = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "m_priority")){
		entry->m_priority = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "weight")){
		entry->weight = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "m_weight")){
		entry->m_weight = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "reachable")){
		entry->r = (strcasecmp(buf, "true")==0);
	}else if(0 == strcasecmp(_xml_name, "local")){
		entry->L = (strcasecmp(buf, "true")==0);
	}else if(0 == strcasecmp(_xml_name, "rloc-probing")){
		entry->p = (strcasecmp(buf, "true")==0);
	}else if(0 == strcasecmp(_xml_name, "address")){
		void * ptr;
		entry->rloc.sa.sa_family = _fam;
		switch(_fam){
			case AF_INET:
				ptr = &entry->rloc.sin.sin_addr;
				break;
			case AF_INET6:
				ptr = &entry->rloc.sin6.sin6_addr;
				break;
			default:
				ptr = &entry->rloc.sa.sa_data;
				break;
		}
		inet_pton(_fam, buf, ptr);

		_fam = AF_INET;
	}else if(0 == strcasecmp(_xml_name, "arrange")){
		if (str2prefix(buf, &pf)) {
			apply_mask(&pf);
			if ( (db= ms_get_db_table(ms_db, &pf)) ){
				dn = db_node_get(db, &pf);
				ms_node_update_type(dn,_GREID);				
			}
		}
	}

	_xml_name = "DUMMY";
}

//====================================================================
//Parse for map-server configure
static struct list_entry_t * site_entry;
static struct db_node * eid_node;


	static void XMLCALL
ms_startElement(void *userData, const char *name, const char **atts)
{
	
	if(0 == strcasecmp(name, "site")) {
		site_entry = ms_new_site(site_db);		
	} else if(0 == strcasecmp(name, "eid")){
		eid_node = NULL;
		bzero(&_mflags,sizeof(struct mapping_flags));
		//printf("new_eid\n");
		_mflags.range = _EID;
		_mflags.rsvd = site_entry;
		
	}else if (0 == strcasecmp(name, "addr") || 0 == strcasecmp(name, "arrange")){
		while(*atts){
			if(0 == strcasecmp(*atts, "family")){
				atts++;
				_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
			}
			else
				_fam = AF_INET;
			atts++;
		}
	}
	
	_xml_name = name;
}

	static void XMLCALL
ms_endElement(void *userData, const char *name)
{
	if(0 == strcasecmp(name, "site")){
		site_entry = NULL;		
	}else if(0 == strcasecmp(name, "eid")){
		//printf("eid_node_addr2::%p\n",eid_node);
		generic_mapping_set_flags(eid_node,&_mflags);		
		bzero(&_mflags,sizeof(struct mapping_flags));		
	}
}

	static void XMLCALL
ms_getElementValue(void *userData, const XML_Char *s, int len)
{
	
	char buf[len+1];
	struct prefix pf;
	struct db_table *db;
	struct site_info *s_data;
	struct db_node * dn;
	
	buf[len] = '\0';
	
	if(!s)
		return ;
		
	memcpy(buf, s, len);
	s_data = NULL;
	if(site_entry){
		s_data = (struct site_info *)site_entry->data;
	}
	
	if(0 == strcasecmp(_xml_name, "name")){
		s_data->name = calloc(len+1,sizeof(char));
		memcpy(s_data->name, buf,len+1);		
	}
	else if(0 == strcasecmp(_xml_name, "key")){
		s_data->key = calloc(len+1,sizeof(char));
		memcpy(s_data->key, buf,len+1);				
	}else if(0 == strcasecmp(_xml_name, "contact")){
		s_data->contact = calloc(len+1,sizeof(char));
		memcpy(s_data->contact, buf,len+1);				
	}else if(0 == strcasecmp(_xml_name, "active")){
		if (_mflags.range){
			_mflags.active = (strncasecmp(buf,"yes",3) == 0)? _ACTIVE: _NOACTIVE;
		}
		else{	
			s_data->active = (strncasecmp(buf,"yes",3) == 0)? _ACTIVE: _NOACTIVE;
		}
	}else if(0 == strcasecmp(_xml_name, "addr")){
		if (str2prefix(buf, &pf) == 1){
			apply_mask(&pf);
			//printf("site::%s::addr::%s\n",s_data->name,buf);
			//add new eid node to tree
			if ( (db = ms_get_db_table(ms_db, &pf) )){
				eid_node = db_node_get(db, &pf);
				//printf("eid_node_addr1::%p\n",eid_node);
				//generic_mapping_set_flags(eid_node,&_mflags);					
				list_insert( s_data->eid, eid_node,NULL);				
			}			
		}
	}else if(0 == strcasecmp(_xml_name, "arrange")){
		if (str2prefix(buf, &pf)) {
			apply_mask(&pf);
			//new geid node
			if ( (db= ms_get_db_table(ms_db, &pf)) ){
				dn = db_node_get(db, &pf);
				ms_node_update_type(dn,_GEID);				
			}
		}
	}

	_xml_name = "DUMMY";
}

//====================================================================
	int 
xtr_parser_config(const char * filename)
{	
	xtr_ms = list_init();
	xtr_mr = list_init();
	xml_configure(filename, xtr_startElement, xtr_endElement, xtr_getElementValue);
	printf("Parse configure file ...\n\n");
	return 0;
}	

	int 
ms_parser_config(const char * filename)
{
	xml_configure(filename, ms_startElement, ms_endElement, ms_getElementValue);
	printf("Parse configure file ...\n\n");
	return 0;
}	

	int 
mr_parser_config(const char * filename)
{	
	xml_configure(filename, mr_startElement, mr_endElement, mr_getElementValue);
	printf("Parse configure file ...\n\n");
	return 0;
}

/* parse the main configuration file and load extern config */
	int
_parser_config(const char * filename)
{
	int nl;
	char buf[BUFSIZ];
	FILE * config;
	
	config = fopen(filename, "r");
	nl = 0;
	config_file[1] = config_file[2] = config_file[3] = NULL;
	listening_address[0] = 	listening_address[1] = NULL;
	while ( fgets(buf, sizeof(buf), config) != NULL )
	{
		char data[50][255];
		char *token = buf;			
		char * tk;
		char * ptr;
		char * sep_t =  "\t ";
		int	i = 0; //counter
				
		nl++;
		if ((token[1] == '\0') || (token[0] == '#'))
			continue;	//skip empty and comment line
		
		i = 0;
		//configure line: key  =  value
		for (tk = strtok_r(buf, sep_t, &ptr); tk ; tk = strtok_r(NULL, sep_t, &ptr))
			strcpy(data[i++], tk);
		
		// int j ;
		// for (j = 0 ; j < i ; j++)
			// printf("data[%d] = %s\n",j,data[j]);
			
		//token[0] = key, token[1] = "=", token[2] = value, token[3] = value,...
		if(i < 3 || ( i > 1 && strcasecmp(data[1],"=")!= 0 ) ){
			printf("Error configure file : at line: %d\n",nl);
			exit(1);
		}
		
		//skip \n in the end of last token
		data[i-1][strlen(data[i-1])-1]='\0';
		
		if(0 == strcasecmp(data[0], "functions")){
			while(--i > 1){
				if( 0 == strcasecmp(data[i],"xTR"))
					_fncs = _fncs | _FNC_XTR;
									
				if( 0 == strcasecmp(data[i],"ms"))
					_fncs = _fncs |  _FNC_MS;
					
				if( 0 == strcasecmp(data[i],"mr"))
					_fncs = _fncs | _FNC_MR;
				
				if( (0 == strcasecmp(data[i],"ddt")) || (0 == strcasecmp(data[i],"node")))
					_fncs = _fncs | _FNC_NODE;	
				//printf("_fncs=%d\n",_fncs);
			}
			if( _fncs % 2 && _fncs > 1 )
				printf("Error Configure file: xTR can not run as ms or mr or node, at line: %d\n",nl);
		}
		
		if( 0 == strcasecmp(data[0], "source_ipv4") ){
			if(strcasecmp(data[2], "auto") !=0){
				listening_address[0] = calloc(1,strlen(data[2]));
				memcpy(listening_address[0], data[2],strlen(data[2]));
			}
			else
				listening_address[0] = NULL;
		}	
		
		if( 0 == strcasecmp(data[0], "source_ipv6")){
			if (strcasecmp(data[2], "auto") !=0){
				listening_address[1] = calloc(1,strlen(data[2]));
				memcpy(listening_address[1], data[2],strlen(data[2]));
			}
			else
				listening_address[1] = NULL;
		}
		
		if( (0 == strcasecmp(data[0], "queue_size"))){
			if(strcasecmp(data[2], "default") !=0){
				PK_POOL_MAX = atoi(data[2]);
			}
			else
				PK_POOL_MAX = 1000;
			_pk_req_pool =calloc(PK_POOL_MAX, sizeof(struct pk_req_entry *));
			_pk_rpl_pool = calloc(PK_POOL_MAX,sizeof(struct pk_rpl_entry * ));
			_pk_work_pool = calloc(PK_POOL_MAX, sizeof(int *));
			_pk_req_prefix = calloc(PK_POOL_MAX,sizeof(struct prefix *));
		}
		
		if( (0 == strcasecmp(data[0], "min_threads"))){
			if(strcasecmp(data[2], "default") !=0){
				min_thread = atoi(data[2]);
			}
			else
				min_thread = 1;			
		}
		
		if( (0 == strcasecmp(data[0], "max_thread"))){
			if(strcasecmp(data[2], "default") !=0){
				max_thread = atoi(data[2]);
			}
			else
				max_thread = 2;			
		}
		
		if( (0 == strcasecmp(data[0], "linger_thread"))){
			if(strcasecmp(data[2], "default") !=0){
				linger_thread = atoi(data[2]);
			}
			else
				linger_thread = 10;			
		}
		
		if( 0 == strcasecmp(data[0], "xtr_configure")){
			config_file[1] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[1], data[2],strlen(data[2]));
			config_file[1][strlen(data[2])]='\0';
			//printf("data[1]=%s\n",config_file[1]);
		}
		
		if(0 == strcasecmp(data[0], "ms_configure")){
			config_file[2] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[2], data[2],strlen(data[2]));
			config_file[2][strlen(data[2])]='\0';
			//printf("data[2]=%s\n",config_file[2]);
		}
		
		if(0 == strcasecmp(data[0], "mr_configure")){
			config_file[3] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[3], data[2],strlen(data[2]));
			config_file[3][strlen(data[2])]='\0';
			printf("data[3]=%s\n",config_file[3]);
		}
		
	}
	
	
	if((_fncs & _FNC_XTR) && config_file[1]){
		printf("Parser file:%s\n",config_file[1]);
		xtr_parser_config(config_file[1]);
	}
	
	if((_fncs & _FNC_MS) && config_file[2]){
		printf("Parser file:%s\n",config_file[2]);
		ms_parser_config(config_file[2]);
	}
	
	if((_fncs & _FNC_MR) && config_file[3]){
		printf("Parser file:%s\n",config_file[3]);
		mr_parser_config(config_file[3]);		
	}
	fclose(config);
	return 0;
}	
