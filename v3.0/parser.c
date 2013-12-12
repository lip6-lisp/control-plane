
#include <expat.h>
#include "lib.h"
#include <sys/stat.h>

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
u_char lisp_te=0;
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
	void 
_err_config(char *err_msg){
	printf("Error Configure file: %s, at line %" XML_FMT_INT_MOD "u\n",err_msg,XML_GetCurrentLineNumber(parser));
}

/* validate if an eid-prefix is overlap or not
	xTR EID must belong to root
	GEID, GREID must only belong to root and not overlap
	EID must belong to GEID and overlap each other
	EID-referral must belong to GREID and overlap each other
*/
	int
_valid_prefix(struct prefix *p, int type)
{
	struct db_node * rn = NULL;
	struct db_table * table;
	
	table = ms_get_db_table(ms_db,p);
	rn = db_node_match_prefix(table, p);
	/* database seem empty */
	if(!rn)
		return 1;
	
	/*duplicate EID */
	if(rn && rn->p.prefixlen == p->prefixlen)
		return 2;
		
	switch (type) {
		case _MAPP_XTR:
		/* EID-prefix of xTR must have target is root but can not overlap*/
			while (rn != table->top && !rn->flags)
				rn = rn->parent;
			return ( rn == table->top || ((struct mapping_flags *)rn->flags)->range == _MAPP_XTR);
			break;
		case _GEID:
		case _GREID:
		/* _GEID prefix must have target is root and not overlap */	
			while (rn != table->top && !rn->flags)
				rn = rn->parent;
			return (rn == table->top);
			break;
		case _EID:
		/* _EID prefix must have target is one of _GEID*/	
			while (rn != table->top && !rn->flags)
				rn = rn->parent;
				
			return (rn == table->top || ((struct mapping_flags *)rn->flags)->range & (_GEID | _EID));
			break;	
		case _REID:	
			/* _EID prefix must have target is one of _GREID*/	
			while (rn != table->top && !rn->flags)
				rn = rn->parent;
			return (rn == table->top || ((struct mapping_flags *)rn->flags)->range == _GREID);	
			break;					
	}
	return 0;	
}


	int
_get_file_size(const char *filename)
{
	struct stat sb;
    if(stat(filename, &sb) == 0)
		return sb.st_size;
	else
		return -1;
}
	int 
xml_configure(const char * filename,
	void (* startElement)(void *, const char *, const char **),
	void (* endElement)(void *, const char *),
	void (* getElementValue)(void *, const XML_Char *, int)
)
{
	int done;
	int bsize;
	char *buf;
	FILE * config;
	
	if( (bsize = _get_file_size(filename)) == -1){
		printf("Error configure file: can not open file %s\n",filename);
		exit(1);
	 }
	buf = (char *)malloc(bsize+1);
	bzero(buf, bsize+1);

	parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, NULL);

	XML_SetStartElementHandler(parser, startElement);
	XML_SetEndElementHandler(parser, endElement);

	XML_SetCharacterDataHandler(parser, getElementValue);

	config = fopen(filename, "r");

	do {
		int len = (int)fread(buf, 1, bsize, config);
		done = len < sizeof(buf);
		if (XML_Parse(parser, buf, len, done) == XML_STATUS_ERROR) {
			fprintf(stderr, "Error Configure file: %s at line %" XML_FMT_INT_MOD "u\n",\
					XML_ErrorString(XML_GetErrorCode(parser)),\
					XML_GetCurrentLineNumber(parser));
			fclose(config);
			exit(1);
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
struct pe_entry *pe;
struct hop_entry *hop;

	static void XMLCALL
xtr_startElement(void *userData, const char *name, const char **atts)
{
	int len;
	struct map_entry *entry;

	if(0 == strcasecmp(name, "eid")) {
		if(_mapping){
			_err_config("mismatch tag");
			exit(1);
		}
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
				if(str2prefix (_prefix, &p1) <=0){
					_err_config("invalid prefix");
					exit(1);				
				}				
				apply_mask(&p1);				
				/* append to db */
				if( !_valid_prefix(&p1, _MAPP_XTR) || !(_mapping = generic_mapping_new(&p1)) ){
					_err_config("invalid prefix");
					exit(1);
				}
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
			0 == strcasecmp(name, "mr") ||
			0 == strcasecmp(name, "pe")||
			0 == strcasecmp(name, "hop") ){
			
			if(0 == strcasecmp(name, "ms")){
				xtr_ms_entry = calloc(1, sizeof(struct ms_entry));
				xtr_ms_entry->proxy = 0;
				list_insert(xtr_ms, xtr_ms_entry, NULL);
			}
			if(0 == strcasecmp(name, "pe") && lisp_te){
				pe = calloc(1,sizeof(struct pe_entry));				
			}
			
			if(0 == strcasecmp(name, "address") )
				_fam = AF_INET;
			
			if(0 == strcasecmp(name, "hop") && lisp_te){
				_fam = AF_INET;
				hop = calloc(1, sizeof(struct hop_entry));				
			}
			
			
			while(*atts){
				if(0 == strcasecmp(*atts, "family")){
					atts++;
					_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
				}
				if(0 == strcasecmp(*atts, "key")){
					atts++;
					len = strlen(*atts);
					xtr_ms_entry->key = (char *)calloc(1, len+1);
					memcpy(xtr_ms_entry->key, *atts, len);
					xtr_ms_entry->key[len] = '\0';	
				}
				if(0 == strcasecmp(*atts, "proxy")){
					atts++;
					xtr_ms_entry->proxy = (strncasecmp(*atts,"yes",3) == 0)? _ACTIVE: _NOACTIVE;						
				}
				if(pe){
					if(0 == strcasecmp(*atts, "priority")){
						atts++;
						pe->priority = atoi(*atts);
					}
					if(0 == strcasecmp(*atts, "weight")){
						atts++;
						pe->weight = atoi(*atts);
					}
				}
				
				atts++;
			}
		}else{
			if(0 == strcasecmp(name, "rloc")){
				if(userData || !_mapping){ 
					_err_config("Mismatch tag");	
					exit(1);
				}
				entry = calloc(1, sizeof(struct map_entry));
				XML_SetUserData(parser, entry);
			}
			
		}
	}

	_xml_name = name;
}

	static void XMLCALL
xtr_endElement(void *userData, const char *name)
{
	struct map_entry * entry;
	
	if(0 == strcasecmp(name, "rloc")){
		entry = (struct map_entry*)userData;
		if(!entry){ 
			_err_config("Mismatch tag");
			exit(1);
		}
		XML_SetUserData(parser, NULL);
		generic_mapping_add_rloc(_mapping, entry);
		entry = NULL;
	}else{
		if(0 == strcasecmp(name, "eid")){			
			generic_mapping_set_flags(_mapping, &_mflags);			
			bzero(&_mflags, sizeof(struct mapping_flags));
			free(_prefix);
			_prefix = NULL;
			_mapping = NULL;
		}
		
		if( 0 == strcasecmp(name, "db") || 
			0 == strcasecmp(name, "mapserver") ||
			0 == strcasecmp(name, "mapresolve")){			
		}
		
		if(0 == strcasecmp(name, "ms")){
			xtr_ms_entry = NULL;
		}
		
		if(0 == strcasecmp(name, "mr")){
			xtr_mr_entry = NULL;
		}
		
		if(0 == strcasecmp(name, "pe")){
			if(entry && !entry->pe)
					entry->pe = list_init();
			if(entry && entry->pe)
				list_insert(entry->pe, pe,NULL);
			pe = NULL;
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
	if(entry){
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
		}else if(0 == strcasecmp(_xml_name, "hop")){
			hop->addr.sa.sa_family = _fam;
			switch(_fam){
				case AF_INET:
					ptr = &hop->addr.sin.sin_addr;
					break;
				case AF_INET6:
					ptr = &hop->addr.sin6.sin6_addr;
					break;
				default:
					_fam = AF_INET;
					ptr = &hop->addr.sa.sa_data;
					break;
			}
			if(inet_pton(_fam, buf, ptr) <=0){
				_err_config("invalid address");
				exit(1);
			}
			if(pe && !pe->hop)
				pe->hop = list_init();
			list_insert(pe->hop, hop,NULL);
			hop = NULL;
			_fam = AF_INET;
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
			if(inet_pton(_fam, buf, ptr) <=0){
				_err_config("invalid address");
				exit(1);
			}
			_fam = AF_INET;
		}
	}
	
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
		if(inet_pton(_fam, buf, ptr) <=0){
				_err_config("invalid address");
				exit(1);
		}
		
		_fam = AF_INET;
	}else{
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
			if(inet_pton(_fam, buf, ptr) <=0){
				_err_config("invalid address");
				exit(1);
			}
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
				if(str2prefix (_prefix, &p1) <=0){
					_err_config("invalid prefix");
					exit(1);				
				}				
				apply_mask(&p1);
				if( !_valid_prefix(&p1, _REID) || !(_mapping = generic_mapping_new(&p1)) ){	
					_err_config("invalid prefix");
					exit(0);
				}
				bzero(&_mflags, sizeof(struct mapping_flags));
				_mflags.range = _MAPP;				
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
				_fam = (0 == strcasecmp(*atts, "IPv6"))?AF_INET6:AF_INET;
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
	}else if(0 == strcasecmp(_xml_name, "weight")){
		entry->weight = atoi(buf);
	}else if(0 == strcasecmp(_xml_name, "reachable")){
		entry->r = (strcasecmp(buf, "true")==0);
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
		if(inet_pton(_fam, buf, ptr) <=0){
				_err_config("invalid address");
				exit(1);
		}

		_fam = AF_INET;
	}else if(0 == strcasecmp(_xml_name, "arrange")){
		if (str2prefix(buf, &pf)) {
			apply_mask(&pf);
			if ( _valid_prefix(&pf, _GREID) && (db= ms_get_db_table(ms_db, &pf)) ){
				dn = db_node_get(db, &pf);
				ms_node_update_type(dn,_GREID);				
			}
		}else{				
				_err_config("invalid address");
				exit(1);							
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
		if(site_entry != NULL){
			_err_config("mismatch tag");
			exit(0);
		}
		site_entry = ms_new_site(site_db);		
	} else if(0 == strcasecmp(name, "eid")){
		if ((site_entry == NULL) || eid_node != NULL){
			_err_config("mismatch tag");
			exit(0);
		}
		bzero(&_mflags,sizeof(struct mapping_flags));
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
		generic_mapping_set_flags(eid_node,&_mflags);		
		bzero(&_mflags,sizeof(struct mapping_flags));
		eid_node = NULL;
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
	if(site_entry && site_entry->data){
		s_data = (struct site_info *)site_entry->data;
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
			if (!_mflags.range){
				s_data->active = (strncasecmp(buf,"yes",3) == 0)? _ACTIVE: _NOACTIVE;
			}
		}
	}
	if(site_entry){
		if(0 == strcasecmp(_xml_name, "addr")){
			if (str2prefix(buf, &pf) == 1){
				apply_mask(&pf);
				if ( _valid_prefix(&pf, _EID) && (db = ms_get_db_table(ms_db, &pf) ) && (eid_node = db_node_get(db, &pf)) ){
					list_insert( s_data->eid, eid_node,NULL);				
				}else{
					_err_config("invalid address");
					exit(1);
				}
			}
		}
	}
	if(site_entry && eid_node){
		if(0 == strcasecmp(_xml_name, "active"))
			if (_mflags.range){
				_mflags.active = (strncasecmp(buf,"yes",3) == 0)? _ACTIVE: _NOACTIVE;
			}				
	}		
	
	if(0 == strcasecmp(_xml_name, "arrange")){
		if (str2prefix(buf, &pf)) {
			apply_mask(&pf);
			if ( _valid_prefix(&pf, _GEID) && (db= ms_get_db_table(ms_db, &pf)) ){
				dn = db_node_get(db, &pf);
				ms_node_update_type(dn,_GEID);				
			}
		}else{
				_err_config("invalid address");
				exit(1);							
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
	return 0;
}	

	int 
ms_parser_config(const char * filename)
{
	xml_configure(filename, ms_startElement, ms_endElement, ms_getElementValue);
	return 0;
}	

	int 
mr_parser_config(const char * filename)
{	
	xml_configure(filename, mr_startElement, mr_endElement, mr_getElementValue);
	return 0;
}

/* parse the main configuration file and load extern config */
	int
_parser_config(const char * filename)
{
	char buf[BUFSIZ];
	FILE *config, *sconfig;
	int ln = 0;
	
	if( (config = fopen(filename, "r")) == NULL){
		printf("Error Configure file: Can not open main configuration file %s\n",filename);
		exit(1);
	}
	
	config_file[1] = config_file[2] = config_file[3] = NULL;
	listening_address[0] = 	listening_address[1] = NULL;
	min_thread = max_thread = PK_POOL_MAX = linger_thread = 0;
	
	while ( fgets(buf, sizeof(buf), config) != NULL )
	{
		char data[50][255];
		char *token = buf;			
		char * tk;
		char * ptr;
		char * sep_t =  "\t ";
		int	i = 0; /*counter */
		ln++;
		
		if ((token[1] == '\0') || (token[0] == '#'))
			continue;	/*skip empty and comment line */
		
		i = 0;
		/*configure line: key  =  value */
		for (tk = strtok_r(buf, sep_t, &ptr); tk ; tk = strtok_r(NULL, sep_t, &ptr))
			strcpy(data[i++], tk);
				
		if(i < 3 || ( i > 1 && strcasecmp(data[1],"=")!= 0 ) ){
			printf("Error configure file : syntax error, at line: %d\n", ln);
			exit(1);
		}
		
		/* skip \n in the end of last token */
		data[i-1][strlen(data[i-1])-1]='\0';
		
		if(0 == strcasecmp(data[0], "debug_level")){
			if(strcasecmp(data[2], "default") !=0){
				_debug = atoi(data[2]);
			}
			else{
				_debug = 1;
			}
		}
		
		if(0 == strcasecmp(data[0], "functions")){
			while(--i > 1){
				if( 0 == strcasecmp(data[i],"xTR") || 0 == strcasecmp(data[i],"xtr"))
					_fncs = _fncs | _FNC_XTR;
									
				if( 0 == strcasecmp(data[i],"ms"))
					_fncs = _fncs |  _FNC_MS;
					
				if( 0 == strcasecmp(data[i],"mr"))
					_fncs = _fncs | _FNC_MR;
				
				if( (0 == strcasecmp(data[i],"ddt")) || (0 == strcasecmp(data[i],"node")))
					_fncs = _fncs | _FNC_NODE;

				if( (0 == strcasecmp(data[i],"rtr")) )
					_fncs = _fncs | _FNC_RTR;
					
			}
			if( (_fncs % 2 && _fncs > 1) || (_fncs > 16) ){
				printf("Error Configure file: xTR and RER can not run as MS or MR or DDT_NODE, at line: %d\n", ln);
				exit(1);
			}
		}
		
		if( 0 == strcasecmp(data[0], "source_ipv4") ){
			if(strcasecmp(data[2], "auto") !=0){
				listening_address[0] = calloc(1,strlen(data[2]));
				memcpy(listening_address[0], data[2],strlen(data[2]));				
			}
			else{
				listening_address[0] = NULL;
			}
		}	
		
		if( 0 == strcasecmp(data[0], "source_ipv6")){
			if (strcasecmp(data[2], "auto") !=0){
				listening_address[1] = calloc(1,strlen(data[2]));
				memcpy(listening_address[1], data[2],strlen(data[2]));
			}
			else{
				listening_address[1] = NULL;
			}
		}
		if( 0 == strcasecmp(data[0], "lisp_te")){
			if (strcasecmp(data[2], "Yes") ==0 || strcasecmp(data[2], "YES") ==0){
				lisp_te = 1;
			}
		}
		if( (0 == strcasecmp(data[0], "queue_size"))){
			if(strcasecmp(data[2], "default") !=0){
				PK_POOL_MAX = atoi(data[2]);
			}
			else{
				PK_POOL_MAX = 1000;
			}					
		}
		
		if( (0 == strcasecmp(data[0], "min_thread"))){
			if(strcasecmp(data[2], "default") !=0){
				min_thread = atoi(data[2]);
			}
			else{
				min_thread = 1;			
			}
		}
		
		if( (0 == strcasecmp(data[0], "max_thread"))){
			if(strcasecmp(data[2], "default") !=0){
				max_thread = atoi(data[2]);
			}
			else{
				max_thread = 2;			
			}
		}
		/* max_thread must greater min_thread */
		
		if(min_thread && max_thread && (max_thread < min_thread) ){
			printf("Error configure file: max_thread must greater min_thread, at line: %d\n", ln);
			exit(1);
		}
		if( (0 == strcasecmp(data[0], "linger_thread"))){
			if(strcasecmp(data[2], "default") !=0){
				linger_thread = atoi(data[2]);
			}
			else{
				linger_thread = 10;			
			}
		}
		
		if( (_fncs & _FNC_XTR) && (0 == strcasecmp(data[0], "xtr_configure")) ){
			config_file[1] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[1], data[2],strlen(data[2]));
			config_file[1][strlen(data[2])]='\0';			
			if((sconfig = fopen(config_file[1], "r")) == NULL){
				printf("Error configure file: can not open file, at line: %d\n",ln);
				exit(1);
			}
			else{
				fclose(sconfig);
			}
		}
		
		if((_fncs & _FNC_MS) && (0 == strcasecmp(data[0], "ms_configure")) ){
			config_file[2] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[2], data[2],strlen(data[2]));
			config_file[2][strlen(data[2])]='\0';			
			if((sconfig = fopen(config_file[2], "r")) == NULL){
				printf("Error configure file: can not open file, at line: %d\n",ln);
				exit(1);
			}
			else{
				fclose(sconfig);
			}
		}
		
		if( ( (_fncs & _FNC_MR) || (_fncs & _FNC_NODE) ) && (0 == strcasecmp(data[0], "mr_configure")) ){
			config_file[3] = calloc(1,strlen(data[2])+1);
			memcpy(config_file[3], data[2],strlen(data[2]));
			config_file[3][strlen(data[2])]='\0';
			if((sconfig = fopen(config_file[3], "r")) == NULL){
				printf("Error configure file: can not open file, at line: %d\n",ln);
				exit(1);
			}
			else{
				fclose(sconfig);
			}			
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


