#include<iostream>
#include<fstream>
#include<random>
#include<vector>
#include<algorithm>
#include<ctime>
#include<string>
#include <cstdlib>
#include "generate_random_LDPC.h"
#include <chrono>

vector<vector<int>> row_to_column(vector<vector<int>> R,int n){
    vector<vector<int>>C(n);
    for (int i = 0; i <R.size(); i++){
        for(int j = 0; j < R[i].size(); j++){
            C[R[i][j]].push_back(i);
        }
    }
    for(int i = 0; i <n; i++){
        sort(C[i].begin(),C[i].end());
    }
    return C;
}

vector<vector<int>> column_to_row(vector<vector<int>> C, int m){
    vector<vector<int>>R(m);
    for (int i = 0; i <C.size(); i++){
        for(int j = 0; j < C[i].size(); j++){
            R[C[i][j]].push_back(i);
        }
    }
    for(int i = 0; i <m; i++){
        sort(R[i].begin(),R[i].end());
    }
    return R;
}

vector<int > find_pivote_columns(vector<vector<int> > R, vector<vector<int> > C,int m, int n){
	vector<   int> pivotes(m);
    int suspected_row;
    int i,j,k,val;
    vector<int>::iterator position;
	for (i = 0; i < m; i++){
		if (R[i].size() == 0){
			pivotes[i] = -1;
			continue;
	 	}
		
		pivotes[i] = R[i][0];
		for (j = 0; j < C[R[i][0]].size(); j++){
            suspected_row =C[R[i][0]][j];
			if (suspected_row== i)
				continue;
			for (k = 0; k <R[i].size(); k++){
                val = R[i][k];
                position = lower_bound(R[suspected_row].begin(),R[suspected_row].end(),val);
                if (position != R[suspected_row].end() && R[suspected_row][position-R[suspected_row].begin()] == val ){
                    R[suspected_row].erase(position);
                    if(k != 0){
                        position = lower_bound(C[val].begin(), C[val].end(),suspected_row);
                        C[val].erase(position);
                    }
                }else{
                    R[suspected_row].insert(upper_bound( R[suspected_row].begin(), R[suspected_row].end(), val ),val);
                    C[val].insert(upper_bound( C[val].begin(), C[val].end(), suspected_row ),suspected_row);
                }
			}
		}
        C[R[i][0]].clear();
        C[R[i][0]].push_back(i);
	}
	return pivotes;
}
vector<vector<int>>swap_columns(vector<vector<int >> C, vector<int> pivotes, int m, int n){
    int i;
    for(i =0; i <pivotes.size() ; i++){
        C.push_back(C[pivotes[i]]);
    }
    sort(pivotes.begin(),pivotes.end());
    for(i =pivotes.size()-1; i >=0; i--){
        C.erase(C.begin() + pivotes[i]);
    }
    vector<vector<int>> R = column_to_row(C,m);
    return R;
}

vector<vector<int >> finalize(vector<int> pivotes,vector<vector<int>> R,vector<vector<int>> C, int m, int n){
    vector<int> sorted_pivotes(pivotes);
    sort(sorted_pivotes.begin(),sorted_pivotes.end());
    int num_new_rows = 0;
    int i;
    for (i = 0; i <sorted_pivotes.size(); i ++){
        if(sorted_pivotes[i] == -1)
            num_new_rows ++ ;
        else
            break;
    }

    vector<vector<int>> new_rows(num_new_rows);
    int current_row = 0;
    int last_pivote = -1;
    sorted_pivotes.push_back(n); //temporary insertion.
    for (i = 0; i <sorted_pivotes.size(); i ++){
        if (current_row == num_new_rows) break;
        while (sorted_pivotes[i] > last_pivote+1){
            if(current_row == num_new_rows){
                break;
            }
            new_rows[current_row].push_back(last_pivote+1);
            last_pivote++;
            if(new_rows[current_row].size() >1)
                current_row++;
        }
        last_pivote = sorted_pivotes[i];
    }
    
    for(i = 0; i <num_new_rows; i++){
        R.push_back(new_rows[i]);
        pivotes.push_back(new_rows[i][0]);
    }
    vector<int> redundant_rows;
    for (i = 0; i <pivotes.size(); i ++){
        if (pivotes[i] == -1){
            R.push_back(R[i]);
            redundant_rows.push_back(i);
        }
    }
    sort(redundant_rows.begin(),redundant_rows.end());
    for(i = redundant_rows.size()-1; i >=0; i--){
        R.erase(R.begin()+redundant_rows[i]);
    }
    for (i = pivotes.size()-1; i >=0; i --){
        if (pivotes[i] == -1){
            pivotes.erase(pivotes.begin()+i);
        }
    }
    C = row_to_column(R,n);
    R = swap_columns(C,pivotes,R.size(),n);
    return R;
}



int main(){    
    srand(time(0));
    
	int c = 6;
	int d = 8;
    vector<int> a {4,16,64,256,1024,2048};
	int k,n;
	for(int i = 0; i <a.size(); i++){
		cout << a[i]<<endl;
		k = a[i];
		n = (k*d)/(d-c);
        ///////////////////////
        
        
		vector<vector<int> > H = create_random_LDPC_1(n-k,n,c,d);
        vector<vector<int> > C = row_to_column(H,n);
        auto start = chrono::high_resolution_clock::now();
		vector<int> pivotes = find_pivote_columns(H,C,n-k,n);
        auto stop = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
        cout << "Time taken by find_pivote_columns: "
        << duration.count() << " microseconds" << endl;
        H = finalize(pivotes,H,C,n-k,n);
        auto stop2 = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(stop2 - stop);
        cout << "Time taken by finalize: "
        << duration.count() << " microseconds" << endl;
        
        duration = chrono::duration_cast<chrono::microseconds>(stop - start);
        
		ofstream myfile;
		string filename = "code" + to_string(a[i]) + ".txt";
		myfile.open (filename);
		for(int j = 0; j < H.size(); j++){
			for(int ell = 0; ell <H[j].size(); ell++)
				myfile<< H[j][ell] << " ";
			myfile<<endl;
		}			
		myfile.close();
	}
	return 0;
}
