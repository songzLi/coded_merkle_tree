#include<iostream>
#include<random>
#include<vector>
#include<algorithm>
#include<ctime>
#include "generate_random_LDPC.h"
using namespace std;
int myrandom (int i) { return std::rand()%i;}
vector<vector<  int >> create_random_LDPC_1(int m,  int n, int c, int d){
    if (n*c - m*d != 0)
		return vector<vector<int>>(0,vector<int>(0));
	 int E = n*c;
	vector<int> perm(E);
	for (  int i = 0; i <E; i++)
		perm[i] = i;
	random_shuffle(perm.begin(),perm.end(),myrandom);
	vector<vector< int>> H(m);
	for  (int i = 0; i<E; i++){
		 int var_index = perm[i]/c;
		 int check_index = i/d;
		H[check_index].push_back(var_index);
	}


	
	for (int i =0; i <m; i++){
		sort(H[i].begin(),H[i].end());
		for (int j = H[i].size()-2; j>=0;j--){
			if ((j<H[i].size()-1) &&(H[i][j] == H[i][j+1])){
				H[i].erase(H[i].begin()+j+1);
				H[i].erase(H[i].begin()+j);
			}
		}
	}	
	return H;
}
vector<vector<int>> create_random_LDPC_1_redundant(int m, int n, int c, int d){
	if (n*c - m*d != 0)
		return vector<vector<int>>(0,vector<int>(0));
	int E = n*c;
	vector<int> perm(E);
	for (int i = 0; i <E; i++)
		perm[i] = i;
	random_shuffle(perm.begin(),perm.end());
	vector<vector<int>> H(m,vector<int>(n,0));
	for (int i = 0; i<E; i++){
		int var_index = perm[i]/c;
		int check_index = i/d;
		H[check_index][var_index] =(H[check_index][var_index]+1)%2;
	}
	for (int i = 0;i<m/2;i+=2){
		vector<int> new_row(n);
		for (int j = 0; j<n;j++){
			new_row[j] = (H[2*i][j] + H[2*i+1][j])%2;
		}
		H.push_back(new_row);
	}
	return H;
}
vector<vector<int>> create_random_LDPC_2(int m, int n, int c, int d){
	if (n*c - m*d != 0)
		return vector<vector<int>>(0,vector<int>(0));
	vector<int> row(n,0);
	for (int i = 0; i <d; i++)
		row[i] = 1;
	vector<vector<int>> H(m,vector<int>(n));
	for(int i =0; i<m; i++){	
		random_shuffle(row.begin(),row.end());
		H[i] = row;
	}
	return H;
}
