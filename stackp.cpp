#include<iostream>
#include<stack>
#include<cstring>
#include<cstdlib>

using namespace std;

void printStack(stack<int> Stack){
	stack<int> tmp;
	while(!Stack.empty()){
		tmp.push(Stack.top());
		cout << Stack.top() << ' ';
		Stack.pop();
	}
	while(!tmp.empty()){
		Stack.push(tmp.top());
		tmp.pop();
	}
	cout << endl;
}

int main(int argc, char** argv ){
	if(argc<2){
		cout << "Argument Error";
		return(0);
	}
	FILE* fp = fopen(argv[1],"rt");
	if(fp == NULL){
		cout << "File Error.";
		return(1);
	}
	char str[64];
	char* stok;
	int op = 0;
	int arg = 0;
	int loop = 0;

	stack<int> S;
	int tmp1, tmp2;

	while(!feof(fp)){
		loop++;
		fgets(str, 64, fp);
		stok = strtok(str,"\n");
		stok = strtok(str," ");
		
		op = 0;
		arg = 0;
		if(!strcmp(stok,"PUSH"))	op = 1;
		else if(!strcmp(stok,"POP"))	op = 2;
		else if(!strcmp(stok,"ADD"))	op = 3;
		else if(!strcmp(stok,"SUB"))	op = 4;
		else if(!strcmp(stok,"MUL"))	op = 5;
		else if(!strcmp(stok,"EQUAL"))	op = 6;
		else if(!strcmp(stok,"SHOW"))	op = 7;
		
		if(op==1||op==2){
			stok = strtok(NULL," ");
			arg = atoi(stok);
		}

		switch(op){
			case 1:
				S.push(arg);
				break;
			case 2:
				S.pop();
				break;
			case 3:
				tmp1 = S.top();
				S.pop();
				tmp2 = S.top();
				S.pop();
				S.push(tmp1 + tmp2);
				break;
			case 4:
				tmp1 = S.top();
				S.pop();
				tmp2 = S.top();
				S.pop();
				S.push(tmp1 - tmp2);
				break;
			case 5:
				tmp1 = S.top();
				S.pop();
				tmp2 = S.top();
				S.pop();
				S.push(tmp1 * tmp2);
				break;
			case 6:
				tmp1 = S.top();
				S.pop();
				tmp2 = S.top();
				S.pop();
				S.push((tmp1 == tmp2));
				break;
			case 7:
				cout << S.top() << endl;
				break;
		}

		// printStack(S);
	}
}