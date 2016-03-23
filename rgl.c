/*
 * routegame.c
 *
 *  Created on: Oct 9, 2014
 *      Author: sirius
 */

#include "rgl.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdint.h>

/* Routing game's global parameter */
int 	N;			// number of strategy or number of multipath (number of peering links ^ number of inter flow pairs)
int 	Policy;		// PEMP coordination policy (0-3), provided by user, LISP's routing policy is 4
int 	LB;			// even load-balancing (0) or weighted load-balancing (1)
float 	T;			// value of potential threshold


/* load the number of multipaths, PEMP policy, threshold and use load balancing (LB) configuration from user's input */
void game_config(int n,int p,float t,int u)
{
	N 		= n;
	Policy 	= p;
	T 		= t;
	LB 		= u;
}

/* Encoding and decoding functions */

// encode 5 different coordination cost values into coord_cost5 structure
uint32_t encode_five(coord_cost5 *rc)
{
	uint32_t e;
	e = ((rc->incost) << 24) + ((rc->egcost) << 16) + ((rc->congest) << 8)
			+ ((rc->inPCerror) << 4) + (rc->egPCerror);
	return e;
}

// encode 4 different coordination cost values into coord_cost4 structure
uint32_t encode_four(coord_cost4 *rc)
{
	uint32_t e;
	e = ((rc->incost) << 24) + ((rc->egcost) << 16) + ((rc->Pincost) << 8)
		 + (rc->Pegcost);
	return e;
}

// decode encoded value e and put results into coord_cost5 structure
void decode_five(uint32_t e, coord_cost5 *rc)
{
	uint32_t temp;
	uint32_t mask = 255 << 24;
	temp = (e & mask) >> 24;
	rc->incost = temp;

	mask = 255 << 16;
	temp = (e & mask) >> 16;
	rc->egcost = temp;

	mask = 255 << 8;
	temp = (e & mask) >> 8;
	rc->congest = temp;

	mask = 15 << 4;
	temp = (e & mask) >>4 ;
	rc->inPCerror = temp;

	mask = 15;
	temp = e & mask;
	rc->egPCerror = temp;
}

// decode encoded value e and put results into coord_cost4 structure
void decode_four(uint32_t e, coord_cost4 *rc)
{
	uint32_t temp;
	uint32_t mask = 255 << 24;
	temp = (e & mask) >> 24;
	rc->incost = temp;

	mask = 255 << 16;
	temp = (e & mask) >> 16;
	rc->egcost = temp;

	mask = 255 << 8;
	temp = (e & mask) >> 8;
	rc->Pincost = temp;

	mask = 255;
	temp = e & mask;
	rc->Pegcost = temp;
}

/* Loading cost values, associating with path and recording into path_cost array */

// Associate cost values (v1,v2,v3,v4) with a path and put into the path_cost array (sIndex as the array's index )
void load(int v1, int v2, int v3, int v4,path_cost path[],int *sIndex)
{
	path_cost temp;

	temp.path_id		= *sIndex;
	temp.egresscost		= v1;
	temp.Pingresscost	= v2;
	temp.Pegresscost	= v3;
	temp.ingresscost	= v4;

	// each time a path is loaded successfully, increase the index value (sIndex) to move to the next path
	path[(*sIndex)++]=temp;
}

// Loading the game data (path and its cost value) from configuration file into the path_cost array
void loadFile(char filename[], path_cost path[])
{
	int i=0;
	int v1,v2,v3,v4;
	path_cost temp;
	FILE *fp;

	printf("Reading from file ... ");
	fp = fopen(filename,"r");

	if ( fp == NULL)
		printf("File cannot be open");

	while (fscanf(fp,"%d %d %d %d", &v1,&v2,&v3,&v4) != EOF)
	{
		temp.ingresscost	= v1;
		temp.egresscost		= v2;
		temp.Pingresscost	= v3;
		temp.Pegresscost	= v4;
		temp.path_id		= i;

		path[i++] 			= temp;
	}

	fclose(fp);
}

// from path_cost array calculate the payoff value for each strategy profile
void buildGame(path_cost path[N],strategy_profile profile[N][N])
{
	int i=0,j;
	//i indicates the strategy(or path) selected by local player, j presents the strategy(or path) selected by its peer
	while (i < N)
	{
		for (j=0; j < N; j++)
		{
			profile[i][j].localcost = path[i].egresscost  + path[j].ingresscost;
			profile[i][j].peercost 	= path[j].Pegresscost + path[i].Pingresscost;
			/*game initialization*/
			profile[i][j].eq = 0;
			profile[i][j].pe = 0;
			profile[i][j].status = 0;
		}
		i++;
	}
}

/* Calculate the potential value for each strategy profile on the strategy profile array */

// the process of calculating potential value is a combination of calculatePvalue() and updatePvalue()

// call by calculatePvalue() (after finding the 0 potential profile) to update the potential value for all other profiles
void updatePvalue(int i, int j,strategy_profile p[N][N])
{
	int ii,jj;

	// from the profile[i,j] that has potential value = 0
	// calculate the potential value for the according profile in first column -> profile[i,0]
	p[i][0].pvalue = (p[i][0].peercost - p[i][j].peercost) + p[i][j].pvalue;

	// Potential value calculation starts based on the profile[0,0] (not the profile[i,j])
	// Then row by row
	for ( ii = 0; ii< N; ii++)
	{
		p[ii][0].pvalue = (p[ii][0].localcost - p[i][0].localcost) + p[i][0].pvalue;
		for (jj = 0; jj < N;jj++)
			p[ii][jj].pvalue = (p[ii][jj].peercost -p[ii][0].peercost)+p[ii][0].pvalue ;
	}
}

// the default approach for calculating Potential value for each strategy profile
// firstly set potential value to 0 for the profile (i,j) that has the minimum egress cost
// i is the strategy that has min egress cost on local side while j is the strategy that has min egress cost on peer
// using the updatePvalue() function to calculate potential value for all other profile
void calculatePvalue(path_cost path[], strategy_profile p[N][N])
{
	int i,j;
	uint32_t iMin = path[0].egresscost; 	//local's minimum egerss cost
	uint32_t pMin = path[0].Pegresscost;	//peer's minimum egress cost

	//find the strategy profile(i,j) that has minimum egress cost on local's side and minimum egress cost on peer's side also
	for(i=0;i<N;i++)
	{
		iMin = (path[i].egresscost <iMin) ? path[i].egresscost : iMin ;
		pMin = (path[i].Pegresscost < pMin) ? path[i].Pegresscost : pMin ;
	}

	//set potential value to 0 for the profile(i,j) then call updatePvalue function to calculate potential value for all other profiles
	for (i =0; i<N;i++)
		for (j=0; j<N;j++)
			if (path[i].egresscost == iMin && path[j].Pegresscost == pMin )
			{
				p[i][j].pvalue = 0;
				updatePvalue(i,j,p);
				break;
			}
}


// a different approach for computing the potential value (used in LISP-TE)
// set potential value to 0 for the profile (i,j) that is a social welfare (minimum (local cost + remote cost) )
void find_potential_min(struct routing_strategy local_strategy[],
		struct routing_strategy remote_strategy[],
		strategy_profile p[N][N])
{
	uint8_t min_cost = p[0][0].localcost + p[0][0].peercost;
	uint8_t i,j;

	// find the social welfare profile
	for (i =0; i<N;i++)
		for (j=0; j<N;j++)
			if ( p[i][j].localcost + p[i][j].peercost <= min_cost)
				min_cost = p[i][j].localcost + p[i][j].peercost;

	// set potential to 0 for the social welfare profile
	for (i =0; i<N;i++)
		for (j=0; j<N;j++)
			if ( p[i][j].localcost + p[i][j].peercost == min_cost){
				p[i][j].pvalue = 0;
				updatePvalue(i,j,p);
				break;
			}

}



// a different version of buildGame function - added on 14Mar
// from the two routing_strategy array local_strategy and remote_strategy, create a 2D array of strategy profiles
// number of strategy is N (global parameter),set by game_configure() function (N=number of gateway x number of locator)
// also calculate the corresponding potential value for each profile (using the find_potential_min function)
void build_routing_game(struct routing_strategy local_strategy[N],
		struct routing_strategy remote_strategy[N],
		strategy_profile profile[N][N])
{
	int i,j;
	for (i=0;i<N;i++)
	{
		for (j=0;j<N;j++)
		{
			profile[i][j].localcost = local_strategy[i].loc_eg_cost + remote_strategy[j].rmt_in_cost ;
			profile[i][j].peercost 	= local_strategy[i].rmt_in_cost + remote_strategy[j].loc_eg_cost ;
			profile[i][j].eq = 0;
			profile[i][j].pe = 0;
			profile[i][j].status = 0;
		}
	}

	find_potential_min(local_strategy,remote_strategy,profile);

	/*
	printf("\n");
	for (i=0;i<N;i++)
	{
		for (j=0;j<N;j++)
		{
			// printf(" profile[%d,%d] cost value (%d,%d) potential value %d \n",i,j,profile[i][j].localcost,profile[i][j].peercost,profile[i][j].pvalue);
			// printf("  (%d,%d)",profile[i][j].localcost,profile[i][j].peercost);
			// printf("[%d]",profile[i][j].pvalue);
			if (profile[i][j].status)
				printf("*");
			printf("   ");
		}
		printf("\n");
	}
	*/

}


/* Finding the right threshold value when the input threshold is between 0 and 1 (Not mentioned in the paper) */
// support the find_threshold function
void bubble_sort(int list[], int np)
{
	long c, d, t;

	for (c = 0 ; c < ( np - 1 ); c++)
		for (d = 0 ; d < np - c - 1; d++)
			if (list[d] > list[d+1])
			{
				t         = list[d];
				list[d]   = list[d+1];
				list[d+1] = t;
			}

}
/* Utility functions to support routing game decision */

// convert position (i,j) in 2D array into an index x in 1D array
int convert(int i, int j)
{
	return (i*N + j);
}

// for easy manipulation, convert the game data stored in 2D strategy_profile to a 1D strategy_profile
void gameConversion(strategy_profile g[N][N], strategy_profile profile[N*N])
{
	int i,j;
	for (i = 0;i<N;i++)
		for (j = 0;j<N;j++)
			profile[convert(i,j)] = g[i][j];
}

//update the game data (2D strategy profile array) with new values generating after doing computation on the the 1D profile array
void gameUpdate(strategy_profile p[N*N],strategy_profile g[N][N])
{
	int k,i,j;

	for (k=0;k<N*N;k++)
	{
		//reverse from index k in array p to according position (i,j) in the 2D array
		i = k/N;
		j = k - i*N;
		//update profile(i,j)
		g[i][j] = p[k];
 	}
}

// find and return the minimum potential value
int findPmin(strategy_profile p[N][N])
{
	int i,j;
	int Pmin=0;

	for (i = 0;i < N;i++)
		for (j = 0;j< N;j++)
			if ( p[i][j].pvalue < Pmin)
				Pmin = p[i][j].pvalue;

	return Pmin;
}

/* Coordination policy implementation */

// find the final threshold based on potential value
float find_threshold(strategy_profile g[N][N],float threshold)
{
	int i,j;
	int duplicated=0;
	int number_of_potential_value=0;
	int potential_value[N*N]; 		// array that store all potential values (the value is unique)
	strategy_profile profile[N*N];

	gameConversion(g,profile);

	for (i = 0; i < N*N; i++)
	{
		duplicated = 0;
		for (j = 0; j < i; j++)
		{
			if ( profile[i].pvalue == profile[j].pvalue )
			{
				duplicated = 1;
				break;
			}
		}
		if (!duplicated)
			potential_value[number_of_potential_value++] = profile[i].pvalue;
	}

	bubble_sort(potential_value,number_of_potential_value); // sort the potential value array

	//find the sum of all potential value
	int sum_of_p = 0;

	for (i = 0; i < number_of_potential_value ; i++)
	{
		sum_of_p = sum_of_p + potential_value[i];
	}

	//calculate potential_value/sum_of_all_potential_value
	float t_value[number_of_potential_value];
	int less_than_max_p_value = 0;
	for (i = 0; i < number_of_potential_value ; i++)
	{
		t_value[i] = (float)potential_value[i]/sum_of_p;
		if ( threshold <= t_value[i] )
		{
			less_than_max_p_value = 1;

			 if ( i == 0)
				 threshold = potential_value[i];
			 else
				 threshold = potential_value[i-1];
			 break;
		}

	}

	// threshold is not in the range of p value
	if (!less_than_max_p_value)
		threshold = potential_value[number_of_potential_value-1];

	return threshold;
}

// process the strategy_profile array, identify the equilibria one and return the number of equilibria
int findEquilibria(strategy_profile p[N][N])
{
	int nE=0;
	int i,j;

	//find the minimum potential value
	int pmin = findPmin(p);

	//find the threshold from the list of potential value
	if (0 < T && T < 1)
    	T = find_threshold(p,T);

	if (T)
	{
		for (i = 0;i<N;i++)
			for (j = 0;j<N;j++)
				if (p[i][j].pvalue <= T)
				{
					nE++;
					p[i][j].eq = 1;
				}
	}
	else
	{
		for (i = 0;i<N;i++)
			for (j = 0;j<N;j++)
				if (p[i][j].pvalue == pmin)
				{
					nE++;
					p[i][j].eq = 1;
				}
	}

	return nE;
}

// look into the input strategy_profile array for equilibria profiles, then record the index of these profiles in the nash_set array
void nashSet(strategy_profile p[N][N],int nash_set[])
{
	int k=0;
	int i,j;
	for (i = 0;i <N;i++)
		for (j = 0;j<N;j++)
			if (p[i][j].eq)
				nash_set[k++]=convert(i,j);
}

// compare the efficiency of two profiles, deciding whether a profile is Pareto superior to the other or not?
// Example: efCompare(p1,p2) results
// 1 -> p1 is Pareto superior to p2 and p2 is Pareto inferior to p1
// 0 -> p2 is not Pareto inferior to p1
int efficiencyCompare(strategy_profile p1, strategy_profile p2)
{
	if ( (p1.localcost <= p2.localcost) && (p1.peercost <= p2.peercost) )
		return PARETO_SUPERIOR;
	else
		return PARETO_INFERIOR;
}

// added on 14Mar
// determine whether a profile p1 is Pareto inferior to profile p2 or not
// return 1 if p1 is pareto inferior to p2
int paretoinferior(strategy_profile p1, strategy_profile p2)
{
	if ( ((p1.localcost > p2.localcost) && (p1.peercost >= p2.peercost))
			|| ((p1.localcost >= p2.localcost) && (p1.peercost > p2.peercost)) )
		return 1;
	else
		return 0;
}

/*
 * NEMP policy "play the equilibria of the Nash set and only the Pareto-superior ones if there is at least one"
 * compare one profile with all other profiles to see whether it is pareto superior or not
 * Note: only consider profiles on the Nash set
 */
void NEMP(strategy_profile p[N*N],int ne, int nash_set[ne])
{
	int i,j,flag;
	int n_pareto_superior=0; // number of pareto superior profile

	for (i=0;i<ne;i++)
	{
		flag = 0;
		p[nash_set[i]].status = 0; //initialization, firstly all equilibria are not selected for routing

		//find pareto superior profile: compare one profile with all other profiles using efficiencyCompare() function
		//flag to trigger, flag = 0 after comparing with all other profiles => Pareto superior
		for (j=0;j<ne;j++)
			if (efficiencyCompare(p[nash_set[i]], p[nash_set[j]]) == 0)
				flag = 1;

		if (!flag)
		{
			n_pareto_superior++;
			p[nash_set[i]].status = 1; // this profile is selected for routing
		}
	}

	if (!n_pareto_superior) // if no pareto superior profile exists, all equilibria are selected for routing
		for (i=0;i<ne;i++)
			p[nash_set[i]].status = 1;

}

// added on 14Mar
// policy used by LISP-TE
void restrict_equilibrium_set(strategy_profile p[N*N],int ne, int nash_set[ne])
{
	int i,j,flag;
	int selected =0; // number of selected profile

	for (i=0;i<ne;i++)
	{
		flag = 0;
		p[nash_set[i]].status = 0; //initialization, firstly all equilibria are not selected for routing

		// if the selected profile is pareto inferior to any other profile -> dont select it
		for (j=0;j<ne;j++)
		{
			if ( j != i && paretoinferior(p[nash_set[i]], p[nash_set[j]]) == 1)
			{
				//printf("profile(%d,%d) is pareto inferrior to (%d,%d) \n",p[nash_set[i]].localcost,p[nash_set[i]].peercost,p[nash_set[j]].localcost,p[nash_set[j]].peercost);
				flag = 1;
				break;
			}
		}

		if (!flag)
		{
			p[nash_set[i]].status = 1; // this profile is selected for routing
			selected++;
		}

	}

	if (!selected) // if no profile is selected, selected all
		for (i=0;i<ne;i++)
			p[nash_set[i]].status = 1;

}

// process the strategy_profile array, identify the Pareto efficiency one and return the number of Pareto efficiency profile
int findParetoEfficiency(strategy_profile p[N*N])
{
	int i,j,flag;
	int n_pareto_efficiency=0; 	// number of pareto efficiency profile

	// compare one profile with all other profiles
	// if it is not pareto inferior to any profiles so it is the pareto efficiency profile
	for (i=0;i<N*N;i++)
	{
		flag=0;
		p[i].pe = 0;
		for (j=0;j<N*N;j++)
		{
			if( (j!=i) && efficiencyCompare(p[j],p[i]) )  // if there exist one profile pj that pareto superior to pi
			{
				flag =1; //turn on the flag -> conclude that pi is not pareto efficiency
				break;
			}
		}
		if (!flag)  // after comparing with all other profile, that flag is still off ~ p(i) is a Pareto efficiency profile
		{
			p[i].pe=1;  // marked as Pareto efficiency profile
			n_pareto_efficiency++;
		}
	}
	return n_pareto_efficiency;
}


/*
 * Pareto Frontier policy "play the profiles of the Pareto Frontier set"
 * all profiles that are Pareto efficiency will be selected for routing
 */
void ParetoFrontierPolicy(strategy_profile p[N*N])
{
	int i;
	findParetoEfficiency(p);
	for (i = 0;i <= N*N;i++)
		if (p[i].pe)
			p[i].status=1;

}


/*
 * implementation of the unselfish jump policy - working with the NASH set, then jump out to select a better profile
 * step 0: shrinking that Nash set with respect to Pareto efficiency
 * step 1: for each equilibrium (x0,y0) find the BEST profile (x*,y*) such that
 * 	its routing cost of (x0,y0) - its routing cost of (x*,y*) + peer routing cost (x0,y0) - its routing cost (x*,y*) <= 0
 * step 2: among the (x*,y*) satisfy the condition above, find the best one ~ the smallest one
 * step 3: repeat the same procedure for the next equilibrium
 * step 4: select them for routing , set status = 1
 */

// decide whether a strategy profile x is in the Nash set or not
int inNashset(int x,int ne,int ns[ne])
{
	int i;
	int ret=0;

	for (i = 0; i < ne; i++)
		if (x == ns[i])
		{
			ret = 1;
			break;
		}

	return ret;
}


// build the starting equilibrium array staE[ne] by shrinking the Nash set ns[ne] with respect to Pareto efficiency
// return the number of starting equilibrium (to use in UnSelfishJump and ParetoJump policy)
// staE[] array stores the index of all starting equilibrium profiles
int shrinkNashset(strategy_profile p[N*N],int ne,int ns[ne],int staE[ne])
{
	int i,j,flag;
	int nSe=0;

	//shrinking the Nash set and construct the starting equilibrium list
	for (i=0;i<ne;i++)
	{
		flag = 0;
		for (j=0;j<ne;j++)
			if ( efficiencyCompare(p[ns[i]], p[ns[j]]) == 0)
				flag = 1;

		if (!flag)
			staE[nSe++]=ns[i];
	}

	//if NO Pareto superior found in Nash set, starting equilibrium contains all the equilibria in Nash set
	if (!nSe)
		for (i=0;i<ne;i++)
			staE[nSe++]=ns[i];

	return nSe;
}

//Unselfish jump policy
void UnSelfJump(strategy_profile p[N*N],int ne,int ns[ne])
{
	int i,j,delta,minD;
	int staE[ne];		//starting equilibrium set
	int bestprofile;  	//index of best profile, best jump from starting equilibrium set

	//shrinking the nash set and construct the starting equilibrium set
	int nSe = shrinkNashset(p,ne,ns,staE);

	//find the best jump for each starting equilibrium
	for (i=0;i<nSe;i++)
	{
		bestprofile = staE[i];
		delta=0;
		minD=0;
		for (j=0;j<N*N;j++)
		{
			if (!inNashset(j,ne,ns))
			{
				delta = (p[j].localcost-p[staE[i]].localcost + p[j].peercost-p[staE[i]].peercost);
				if (delta < minD)
				{
					minD = delta;
					bestprofile= j;
					//not consider that case that 2 or more profiles have same minD - current only select 1
				}
			}
		}
		p[bestprofile].status=1;
	}
}

//similar to the UnSelfishJump but change the condition (constraint) to jump from the starting equilibrium
void ParetoJump(strategy_profile p[N*N],int ne,int ns[ne])
{
	int i,j,delta1,delta2,minD;
	int staE[ne];		//starting equilibrium set
	int bestprofile;	//index of best profile, best jump from starting equilibrium

	//shrinking the nash set and create the starting equilibrium list
	int nSe = shrinkNashset(p,ne,ns,staE);

	//find the best jump for each starting equilibrium
	for (i=0;i<nSe;i++)
	{
		bestprofile = staE[i];
		delta1=0;
		delta2=0;
		minD=0;

		for (j=0;j<N*N;j++)
		{
			if (!inNashset(j,ne,ns))
			{
				delta1 = p[j].localcost-p[staE[i]].localcost;
				delta2 = p[j].peercost-p[staE[i]].peercost;
				if (delta1 <= 0 && delta2 <=0)
				{
					if ( delta1+delta2 <= minD)
					{
						minD = delta1+delta2;
						bestprofile= j;
					}
				}
			}
		}
		p[bestprofile].status=1;
	}
}

//Make routing decision based on the selected coordination policy
//0(NEMP) 1(Pareto Frontier) 2(Unselfish Jump) 3(Pareto Jump) 4(restrict_equilibrium_set)
void applyPolicy(strategy_profile g[N][N])
{
	int i,j;
	int nE = findEquilibria(g); //the number of equilibria profile, and set eq = 1 for each equilibria profile
	int nS[nE]; //Nash set
	int index=0;
	strategy_profile profile[N*N];

	for (i = 0;i<N;i++)
		for (j = 0;j<N;j++)
		{
			profile[convert(i,j)] = g[i][j]; //game conversion
			if (g[i][j].eq)
				nS[index++] = convert(i,j);
		}

	switch (Policy) {
		case 0	: NEMP(profile,nE,nS);
					break;
		case 1  : ParetoFrontierPolicy(profile);
					break;
		case 2  : UnSelfJump(profile,nE,nS);
					break;
		case 3  : ParetoJump(profile,nE,nS);
					break;
		case 4	: restrict_equilibrium_set(profile,nE,nS);
					break;
	}

	gameUpdate(profile,g);
}

void printRoutingDecision(strategy_profile g[N][N])
{
	int i,j;
	printf("\n");

	for (i=0;i<N;i++)
		for (j=0;j<N;j++)
			if ( g[i][j].status )
				printf("P(%d) is selected for routing",convert(i,j));
}



/* Load distribution calculation */

// count the number of selected path, repeated paths will not be count
int pathCount(int n,routing_path path[n])
{
	int i,ret=0;
	for ( i=0;i< n;i++)
		if (path[i].status)
			ret++;
	return ret;
}

/*
 * In the selected_path array, there are paths that appear more than 1 times
 * (due to the simple design of path selection process (just pick up profile from the game matrix g[i][j])
 * We handle this issue by introducing a function to deactivate these repeated links
 * When creating the array of selected path, all paths are set as active (link's status = 1)
 * remove_duplicated_selection() change status to 0 for path that already occurred on the list
 * it also count the number of occurrence in frequency attribute
 */
void remove_duplicated_selection(int n,routing_path path[n])
{
	int i,j;
	for (i=0;i<n;i++)
		if (path[i].status)
			for (j=i+1;j<n;j++)
				if (path[i].id == path[j].id)
				{
					path[i].freq++;
					path[j].status = 0;
				}
}

// Among selected paths(status=1) find the max potential value, support the sub-flow load balancing algorithm
int maxPvalue(int n,routing_path path[n])
{
	int i;
	float max=T;
	for (i=0; i<n; i++)
		if (path[i].status)
			max=max<path[i].pvalue?path[i].pvalue:max;
	return max;
}

//Calculate load on each path according to the potential value and threshold
void loadCal(int n,routing_path path[])
{
	int i,j;
	if ( pathCount(n,path) == 1) // only one path is selected
	{
		for (i=0;i<n;i++)
			if(path[i].status)
			{
				path[i].tload = 1;
				break;
			}
	}
	else  // more than one path is selected
	{
		// there is a relationship between traffic loaded and potential value
		float total = 0;
		for (i=0;i<n;i++)
			if(path[i].status)
			{
				path[i].tload = 1 + T - path[i].pvalue;
				for (j=i+1;j<n;j++)
					if ( path[i].id == path[j].id)
						path[i].tload = path[i].tload + (1 + T - path[j].pvalue) ;
				total = total + path[i].tload;
			}

		for (i=0;i<n;i++)
			if(path[i].status)
				path[i].tload = path[i].tload/total;
	}
}


//Using even load-balancing (LB not set) equally distributed load among selected links
void equalLoad(int n,routing_path path[])
{
	int i;
	for (i=0;i<n;i++)
		if (path[i].status)
			path[i].tload = (float) path[i].freq/n;
}

void loadbalacing(strategy_profile g[N][N],int n1, int n2,routing_path local_selectedpath[],routing_path peer_selectedpath[])
{
	//pre-processing the list, de_activate links that occurred more than one time by the frequency and status attribute
	remove_duplicated_selection(n1,local_selectedpath);
	remove_duplicated_selection(n2,peer_selectedpath);

	if (LB && Policy == 0)  // load balancing according to the potential value of selected strategy , this special mode of LB only applicable for NEMP
	{
		loadCal(n1,local_selectedpath);
		loadCal(n2,peer_selectedpath);
	}
	else 	// equal load balancing
	{
		equalLoad(n1,local_selectedpath);
		equalLoad(n2,peer_selectedpath);
	}
}

// process the game g[i][j] and construct an array that stored paths selected by player p (local = 1 , peer = 2)
// and return the number of link select by player p
int path_selection(strategy_profile g[N][N],path_cost s[],routing_path selectedpath[],int p)
{
	int npath=0; //count the number of path selected by player p, also the index of selectedpath array
	int i,j,k;

	for (i=0;i<N;i++)
		for (j=0;j<N;j++)
			if (g[i][j].status)
			{
				k = (p == LOCAL) ? i : j;  //if (p == 1) k=i; else k=j;
				selectedpath[npath].id 		= s[k].path_id; // linkage between game route cost and selected path array
				selectedpath[npath].freq	= 1;
				selectedpath[npath].tload 	= 0;
				selectedpath[npath].status 	= 1;
				selectedpath[npath].pvalue 	= g[i][j].pvalue;
				switch (p){
				case LOCAL:
					selectedpath[npath].ingresscost = s[k].ingresscost;
					selectedpath[npath].egresscost 	= s[k].egresscost;
					break;
				case PEER:
					selectedpath[npath].ingresscost = s[k].Pingresscost;
					selectedpath[npath].egresscost 	= s[k].Pegresscost;
					break;
				}
				/*
				if (p == LOCAL)
				{
					selectedpath[npath].ingresscost = s[k].ingresscost;
					selectedpath[npath].egresscost 	= s[k].egresscost;
				}
				else
				{
					selectedpath[npath].ingresscost = s[k].Pingresscost;
					selectedpath[npath].egresscost 	= s[k].Pegresscost;
				}
				*/
				npath++;
			}

	return npath;
}

//initialize the selected path array
void initPathArr(int n,routing_path path[])
{
	int i;
	for (i=0;i<n;i++)
	{
		path[i].id 			= 0;
		path[i].status		= 0;
		path[i].freq		= 0;
		path[i].tload		= 0;
		path[i].ingresscost = 0;
		path[i].egresscost	= 0;
	}
}

// the default routing decision process
// recording the routing decision and load distribution made by local AS into selectedpath array
// return the number of path selected by local AS
int routingDecision(strategy_profile g[N][N],path_cost s[],routing_path selectedpath[],int p)
{
	int i;
	int npath=0; // count the number of path selected by local AS, also the index of selectedpath array

	routing_path local_AS_path[N*N]; 	// links selected by local AS
	routing_path peer_AS_path[N*N]; 	// links selected by peer AS

	initPathArr(N*N,local_AS_path);
	initPathArr(N*N,peer_AS_path);

	int nlocal 	= path_selection(g,s,local_AS_path,LOCAL);		// number of path selected by local AS
	int npeer 	= path_selection(g,s,peer_AS_path,PEER); 		// number of path selected by peer AS

	loadbalacing(g,nlocal,npeer,local_AS_path,peer_AS_path);

	// init the selected path array
	initPathArr(N,selectedpath);

	switch (p){
	case LOCAL:
		for (i=0;i<nlocal;i++)
			if (local_AS_path[i].status)
			{
				selectedpath[npath].id 				=	local_AS_path[i].id;
				selectedpath[npath].tload 			=	local_AS_path[i].tload;
				selectedpath[npath].ingresscost 	=	local_AS_path[i].ingresscost;
				selectedpath[npath].egresscost		=	local_AS_path[i].egresscost;
				selectedpath[npath].status 			= 	1;
				npath++;
			}
		break;
	case PEER:
		for (i=0;i<npeer;i++)
			if (peer_AS_path[i].status)
			{
				selectedpath[npath].id 				=	peer_AS_path[i].id;
				selectedpath[npath].tload 			=	peer_AS_path[i].tload;
				selectedpath[npath].ingresscost 	=	peer_AS_path[i].ingresscost;
				selectedpath[npath].egresscost		=	peer_AS_path[i].egresscost;
				selectedpath[npath].status 			= 	1;
				npath++;
			}
		break;
	}
	return npath;
}

// added for LISP_TE 15Mar
// the default routingDecision() function could not be reused
// this new routing_decision() function updates local routing strategy
// with the result from the routing game, determine which profiles are selected
int routing_decision(int n, struct routing_strategy local_strategy[n],
						struct routing_strategy remote_strategy[n],
						strategy_profile profile[n][n],
						routing_path selectedpath[n])
{
	uint8_t i,j,x=0;
	uint8_t n_selected = 0 ; // number of selected strategy
	// reuse the selectedpath array to keep track of the routing decision
	// the difference is the selectedpath[i].id is set to the id of local strategy


	initPathArr(n,selectedpath);

	for (i=0;i<N;i++)
		for (j=0;j<N;j++)
			if (profile[i][j].status)
			{
				// update selected local and remote strategy
				local_strategy[i].selected = 1;
				remote_strategy[j].selected = 1;

				// keep track of selected local strategy in the selected path array
				selectedpath[x].id 		= i ; // i is the id of local strategy, actually i = local_strategy[i].id
				selectedpath[x].status 	= 1 ;
				selectedpath[x].pvalue 	= profile[i][j].pvalue;
				selectedpath[x].freq 	= 1 ;
				x++;
			}

	remove_duplicated_selection(x,selectedpath);

	// calculate the weight for each selected strategy
	loadCal(x,selectedpath);

	for(i=0;i<x;i++)
		if(selectedpath[i].status)
			n_selected++;

	return n_selected;

}

/* routing game main functions */

//main function of the routing game library, combine multiple functions into one
//output result is routing decision by local AS recorded in selectedpath array, and the game data stored in strategy_profile array
int routing_game_main(int n, int p, float t, int u,path_cost pathcost[],strategy_profile routinggame[n][n],routing_path selectedpath[])
{
	game_config(n,p,t,u);
	buildGame(pathcost,routinggame);
	calculatePvalue(pathcost,routinggame);
	applyPolicy(routinggame);
	return routingDecision(routinggame,pathcost,selectedpath,LOCAL);
}

//output result is decision made by local AS and peering AS recorded in selectedpath and peer_selected_path array
void routing_game_result_all(int n, int p, float t, int u,path_cost pathcost[],strategy_profile routinggame[n][n],routing_path selectedpath[],routing_path peer_selectedpath[])
{
	game_config(n,p,t,u);
	buildGame(pathcost,routinggame);
	calculatePvalue(pathcost,routinggame);
	applyPolicy(routinggame);
	routingDecision(routinggame,pathcost,selectedpath,LOCAL);
	routingDecision(routinggame,pathcost,peer_selectedpath,PEER);
}

// modified 16/03
// update the local strategy with weight value collected from selectedpath array
// based on that, calculate the load for each source and destination locator
void update_local_strategy(int n, struct routing_strategy local_strategy[],routing_path selectedpath[])
{
	int i;
	for (i=0;i<n;i++)
	{
		if(selectedpath[i].status)
		{
			int s = selectedpath[i].id;
			local_strategy[s].selected = 1;
			local_strategy[s].weight = selectedpath[i].tload * 100;
			//printf("local strategy selected src %d dest %d ",local_strategy[s].src_id,local_strategy[s].dst_id);
		}
	}
}

// modified 15Mar
// calling new defined functions that support LISP-TE
// building_routing_game takes two new input
// + local_strategy represents the routing path could be used by local router to direct traffic to remote site
// + remote_strategy represents the routing path could be used by remote router to send traffic to local site
// NOTE: how to create these local and strategy is not part of the routing game library

// Routing game is constructed by considering all possible combinations of local and remote strategy
// from that the set of strategy profiles is built with corresponding potential value of each profile
// then the equilibria profiles are selected
// depend on potential value, threshold and policy (pareto restriction, policy = 4) the selected profile is determined
// NOTE: define a method to find a threshold value (1st quartile of potential distribution)

// Reuse the selected_path array, then convert the result from selected path to local_strategy array
// update the local_strategy with weight, weight represented for the percentage of traffic distributed on that path
// from the computed weight for each local strategy, calculate the corresponding weight for each destination and source locator
// NOTE: this weight assginment is not part of the routing game library
int routing_game_result_LISP(int n, float t,
		struct routing_strategy local_strategy[n],
		struct routing_strategy remote_strategy[n])
{
	strategy_profile routinggame[n][n];
	game_config(n,4,t,1); // with LISP_TE the routing policy is 4 and always use load balancing
	build_routing_game(local_strategy,remote_strategy,routinggame);
	applyPolicy(routinggame);
	printf("\n");
	int n_selected; // number of selected routing strategy

	int i,j;
	for (i=0;i<N;i++)
	{
		for (j=0;j<N;j++)
		{
			//printf(" profile[%d,%d] cost value (%d,%d) potential value %d \n",i,j,profile[i][j].localcost,profile[i][j].peercost,profile[i][j].pvalue);
			printf("  (%d,%d)",routinggame[i][j].localcost,routinggame[i][j].peercost);
			printf("[%d]",routinggame[i][j].pvalue);
			if (routinggame[i][j].status)
				printf("*");
			printf("   ");
		}
		printf("\n");
	}
	routing_path selectedpath[n];
	n_selected = routing_decision(n, local_strategy,remote_strategy,routinggame,selectedpath);
	update_local_strategy(n, local_strategy,selectedpath);

	return n_selected;
}

// output routing game data as well as local AS decision into file
int routing_game_output_file(char filename[],int n, strategy_profile g[n][n], int npath,routing_path selectedpath[])
{
	//filename = filename concatenate time stamp returned from system time
	time_t 		now;
    struct tm 	*gmt;
    char 		formatted_gmt[80];
    FILE 		*fp;
    int 	i,j;

    now = time ( NULL );
    gmt = localtime ( &now );

    strftime(formatted_gmt, sizeof(formatted_gmt),"%H%I%p", gmt );
	printf(" \n output file %s \n",formatted_gmt);
	strcat(filename,formatted_gmt);
	printf(" \n output file %s \n",filename);

	fp = fopen(filename,"w");

	if ( fp != NULL)
	{
		fprintf(fp,"Local/Peer ");
		for (j=0;j<N;j++)
			fprintf(fp,"  %d        ",j);

		fprintf(fp,"\n");

		for ( i = 0; i < N; i++)
		{
			fprintf(fp,"  %d ",i);
			fprintf(fp,"   ");
			for ( j = 0; j < N; j++)
			{
				fprintf(fp,"   (%d,%d)",g[i][j].localcost,g[i][j].peercost);
				if (g[i][j].status)
					fprintf(fp,"*");
				else
					fprintf(fp," ");
			}
			fprintf(fp,"\n");
		}

		fprintf(fp,"\nPotential value for each strategy profile \n");
		for ( i = 0; i < N; i++)
		{
			for ( j = 0; j < N; j++)
				fprintf(fp,"  %d  ",g[i][j].pvalue);
			fprintf(fp,"\n");
		}

		fprintf(fp,"Minimum potential value = %d \n",findPmin(g));

		fprintf(fp,"\nGame's parameter: Coordination policy = %d Threshold = %f Use load balancing = %d \n",Policy,T,LB);

		if ( npath )
		{
			fprintf(fp,"CoreRouter in local AS selects %d paths \n",npath);
			for ( i = 0; i< n;i++)
				if ( selectedpath[i].status == 1)
					fprintf(fp," Path %d ingress cost = %d egress cost = %d -- Percent load = %f \n",
							selectedpath[i].id,selectedpath[i].ingresscost,selectedpath[i].egresscost,selectedpath[i].tload);
		}
		fclose(fp);
		return 1;
	}
	else
		return 0;
}

// output routing game data as well as routing decision at both side into file
int routing_game_output_file_all(char filename[],int n, strategy_profile g[n][n],routing_path selectedpath[],routing_path peer_selectedpath[])
{
	//filename = filename concatenate time stamp returned from system time
	time_t 		now;
    struct tm 	*gmt;
    char 		formatted_gmt[80];
    FILE 		*fp;
    int 	i,j;

    now = time ( NULL );
    gmt = localtime ( &now );

    strftime(formatted_gmt, sizeof(formatted_gmt),"%H%I%p", gmt );
	printf(" \n output file %s \n",formatted_gmt);
	strcat(filename,formatted_gmt);
	printf(" \n output file %s \n",filename);

	fp = fopen(filename,"w");

	if ( fp != NULL)
	{
		fprintf(fp,"Local/Peer ");
		for (j=0;j<N;j++)
			fprintf(fp,"  %d        ",j);

		fprintf(fp,"\n");

		for ( i = 0; i < N; i++)
		{
			fprintf(fp,"  %d ",i);
			fprintf(fp,"   ");
			for ( j = 0; j < N; j++)
			{
				fprintf(fp,"   (%d,%d)",g[i][j].localcost,g[i][j].peercost);
				if (g[i][j].status)
					fprintf(fp,"*");
				else
					fprintf(fp," ");
			}
			fprintf(fp,"\n");
		}

		fprintf(fp,"\nPotential value for each strategy profile \n");
		for ( i = 0; i < N; i++)
		{
			for ( j = 0; j < N; j++)
				fprintf(fp,"  %d  ",g[i][j].pvalue);
			fprintf(fp,"\n");
		}

		fprintf(fp,"Minimum potential value = %d \n",findPmin(g));

		fprintf(fp,"\nGame's parameter: Coordination policy = %d Threshold = %f Use load balancing = %d \n",Policy,T,LB);

		fprintf(fp,"ClubmedRouter in local AS selects  \n");
		for ( i = 0; i< n;i++)
			if ( selectedpath[i].status == 1)
				fprintf(fp," Path %d ingress cost = %d egress cost = %d -- Percent load = %f \n",
					selectedpath[i].id,selectedpath[i].ingresscost,selectedpath[i].egresscost,selectedpath[i].tload);

		fprintf(fp,"CoreRouter in peering AS selects \n");
		for ( i = 0; i< n;i++)
			if ( peer_selectedpath[i].status == 1)
				fprintf(fp," Path %d ingress cost = %d egress cost = %d -- Percent load = %f \n",
					peer_selectedpath[i].id,peer_selectedpath[i].ingresscost,peer_selectedpath[i].egresscost,peer_selectedpath[i].tload);

		fclose(fp);

		return 1;
	}
	else
		return 0;
}

