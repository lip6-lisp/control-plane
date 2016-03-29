/*
 * rglib.h
 *
 *  Created on: Oct 8, 2014
 *      Author: sirius
 */
#include <stdint.h>

#ifndef RGLIB_H_
#define RGLIB_H_

#define LOCAL 	1
#define PEER 	2
#define PARETO_SUPERIOR 	1
#define PARETO_INFERIOR 	0

/* This structure is used only by LISP, so we should rather define in LISP control plane */
/*
struct rg_locator
{
	uint8_t 			id;
	struct in_addr 		*addr;
	struct map_entry 	*entry;
	uint8_t 			icost;
	uint8_t 			ecost;
	uint8_t 			weight;
	uint8_t 			selected;
};
*/

/* Define coordination cost structure to hold multiple cost value into a 32bit variable */
struct coordination_cost5 {
	unsigned int incost : 8;
	unsigned int egcost : 8;
	unsigned int congest : 8;
	unsigned int inPCerror : 4;
	unsigned int egPCerror : 4;
};
typedef struct coordination_cost5 coord_cost5;

struct coordination_cost4 {
	unsigned int incost : 8;
	unsigned int egcost : 8;
	unsigned int Pincost : 8;
	unsigned int Pegcost : 8;
};
typedef struct coordination_cost4 coord_cost4;

/* routing cost associated with a path */
struct path_cost
{
	unsigned int path_id;

	unsigned int egresscost;
	unsigned int Pingresscost;

	unsigned int Pegresscost;
	unsigned int ingresscost;

};
typedef struct path_cost path_cost;
/* routing path is also 1 kind of simpler routing strategy in which each out going link is consider as a strategy */
// was used in PEMP


/* routing strategy which combine the selection of source and destination, each pair of source and destination is consider as a strategy */
// was used in LISP-TE
struct routing_strategy
{
	uint8_t 	s_id;
	uint8_t 	src_id;
	uint8_t 	dst_id;
	uint8_t 	loc_in_cost;
	uint8_t 	loc_eg_cost;
	uint8_t 	rmt_in_cost;
	uint8_t 	rmt_eg_cost;
	uint8_t 	selected;
	uint8_t 	weight;
};

/*
 * strategy profile is a combination of strategy i selected by local AS and strategy j selected by peer AS profile(i,j)
 * strategy_profile structure store all the information related to this profile such as the potential value, the payoff...
 * payoff(profile(i,j)) = (routing cost of local AS if select strategy i, routing cost of peering AS if select strategy j)
 */
struct strategy_profile
{
	unsigned int localcost;			// cost for routing traffic at local
	unsigned int peercost;			// cost for routing traffic at peer side
	int 	pvalue;					// potential value
	short 	eq; 					// equilibria or not ? 1 YES 0 NO
	short 	pe; 					// pareto efficiency or not ?
	short 	status; 				// selected for routing or not ? defined according to the routing policy
};
typedef struct strategy_profile strategy_profile;


/* routing_path is the structure recored all the information required for the selected routing path */
struct routing_path
{
	int 	id;
	int 	ingresscost;
	int 	egresscost;
	int 	freq;			// frequency of occurrence in the array
	int 	pvalue; 		// potential value
	int 	status; 		// 1 selected 0 not selected
	float 	tload; 			// calculated traffic load on this path
};
typedef struct routing_path routing_path;

void game_config(int n,int p,float t,int u);
void loadFile(char filename[], path_cost s[]);
void load(int v1, int v2, int v3, int v4,path_cost s[],int *sIndex);

int routing_game_main(int nS, int p, float t, int u,path_cost s[],strategy_profile g[nS][nS],routing_path selectedpath[]);
int routing_game_output_file(char filename[],int nS, strategy_profile g[nS][nS], int npath,routing_path selectedlink[npath]);

void routing_game_result_all(int n, int p, float t, int u,path_cost pathcost[],strategy_profile routinggame[n][n],routing_path selectedpath[],routing_path peer_selectedpath[]);
int routing_game_output_file_all(char filename[],int n, strategy_profile g[n][n],routing_path selectedpath[],routing_path peer_selectedpath[]);

void routing_game_all_policy(int n, int p, float t, int u,path_cost pathcost[],strategy_profile routinggame[n][n],routing_path selectedpath[],routing_path peer_selectedpath[]);

void decode_five(uint32_t MED, coord_cost5 *r);
uint32_t encode_five(coord_cost5 *rc);

void decode_four(uint32_t e, coord_cost4 *rc);
uint32_t encode_four(coord_cost4 *rc);

int routing_game_result_LISP(int n,
		struct routing_strategy local_strategy[n],
		struct routing_strategy remote_strategy[n]);

#endif /* RGLIB_H_ */
