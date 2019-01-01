#include<stdio.h>
#include"../aes.h"
#include<time.h>
#include<vector>
#define Buffsize 0x80000


typedef struct{
	unsigned char cypher[16];
	char *input;
	char *output;
}option;

void map_to_AESKey1(const char *Key, unsigned char AES_Key[16],uint32_t k){

//把原始的密钥通过MD5变成AES需要的密钥，k是需要附加的值，而且k是变化的,要求cypher1是长为16为的char型数组
	size_t len_of_cypher = strlen((char*)Key);
	unsigned char *cypher_instant = (unsigned char*)malloc((len_of_cypher + 1) * sizeof(char));
	MD5_CTX md5;
	MD5Init(&md5);
	size_t j = 0;
	for (j = 0; j<len_of_cypher; j++)
	{
		*(cypher_instant + j) = Key[j];
	}
	if (j >= 4)
	{
		*(cypher_instant + j - 4) = Key[j - 4] + ((unsigned char*)(&k))[0];
		*(cypher_instant + j - 3) = Key[j - 3] + ((unsigned char*)(&k))[1];
		*(cypher_instant + j - 2) = Key[j - 2] + ((unsigned char*)(&k))[2];
		*(cypher_instant + j - 1) = Key[j - 1] + ((unsigned char*)(&k))[3];
	}
	else
	{
		*(cypher_instant + j - 1) = Key[j - 1] + (unsigned char)k;
	}
	*(cypher_instant + j) = '\0';
	MD5Update(&md5, cypher_instant, strlen((char *)cypher_instant));
	MD5Final(&md5, AES_Key);
	free(cypher_instant);
};

void match_option(option* opt,char **argv,int index){
	switch(argv[index][1]){
		case 'c':
		case 'C':
			map_to_AESKey1(argv[index+1], opt->cypher, 0);
			break;
		case 'i':
		case 'I':
			opt->input=argv[index+1];
			break;
		case 'o':
		case 'O':
			opt->output=argv[index+1];
			break;
	}
};

option parse_options(int argc,char *argv[]){
	option result;
	memset(&result,0,sizeof(result));
	if(argc>0){
		for(int i=1;i<argc;){
			if(argv[i][0]=='-' && (i+1)<argc){
				match_option(&result,argv,i);
				i+=2;
			}else {
				return result;		
			}
		}
	}
	return result;
}

//返回1成功，返回0失败
int check_param(option* opt){
	int cypher_null=0;
	for(int i=0;i<16;i++){
		if(opt->cypher[i]!=0){
			cypher_null=1;
			break;
		}
	}
	if(cypher_null==0){
		map_to_AESKey1("sdbefdjr%^$#sqplx", opt->cypher, 0);
	}
	if(opt->input==NULL ||
		strlen(opt->input)==0){
		return 0;
	}

	if(opt->output==NULL ||
		strlen(opt->input)==0){
		opt->output="default.encrypt";
	} 
	return 1;
}

void write_file(unsigned char *src,size_t len,FILE* fp){
	size_t l=len;
	while(l>0){
		size_t count=fwrite((void *)src,sizeof(unsigned char),l,fp);
		if(count==0){
			printf("Write file fail,exit!\n");
			exit(1);
		}
		l-=count;
	}
}


int main(int argc,char *argv[]){

	FILE *input, *output;
	uint32_t KEY_EXTEND[44];
	size_t i = 0;
	double j = 0;
	std::vector<unsigned char*> file_mem;

	option opt=parse_options(argc,argv);
	
	if(check_param(&opt)!=1){
		printf("param error!\n");
		return 1;
	}
	
	//open the input file
	if ((input = fopen(opt.input, "rb")) == NULL)
	{
		printf("\nCannot open intput file, exit!");
		return 1;
	}

	output = fopen(opt.output, "wb");
	int file_size=0;	
	void *buff;

	while(!feof(input)){
		if(file_size%Buffsize==0){
			buff=malloc(Buffsize);
			file_mem.push_back((unsigned char*)buff);
		}
		int count=fread(buff+(file_size%Buffsize),sizeof(unsigned char),Buffsize,input);
		file_size+=count;
	}

	printf("Read file done!");
	clock_t start, finish;
	start = clock();
		
	cypher_extended(opt.cypher, KEY_EXTEND);
	for(size_t i=0;i<file_mem.size();i++){
		unsigned char* mem=file_mem[i];
		if(i!=file_mem.size()-1){
			for(size_t j=0;j<Buffsize/0x10;j++)			{
				AES_encrypt((unsigned int*)&(mem[j*0x10]), KEY_EXTEND);
			}
		}else{
			for (size_t j = 0; j<((file_size-(file_size%0x10))%Buffsize)/0x10; j++){
				AES_encrypt(((unsigned int*)&(mem[j * 0x10])), KEY_EXTEND);
			}
		}
	}
	
	finish = clock();

	for(size_t i=0;i<file_mem.size();i++){
		unsigned char* mem=file_mem[i];
		size_t len=Buffsize;
		if(i!=file_mem.size()-1){
			write_file(mem,Buffsize,output);
		}else{
			write_file(mem,file_size%Buffsize,output);
		}
	}


	j = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("加密了%ld字节，用时为%lf秒\n", i, j);
	
	for(size_t i=0;i<file_mem.size();i++){
		free(file_mem[i]);
	}

	fclose(input);
	fclose(output);
	return 0;
}



//加密机械姬，用时226.53900s
//更新:利用单表替换算法实现多项式乘法后，加密机械姬用时135.327s,吞吐量位8.74MB/s
//更新:第二次测试129.416s,吞吐量9.14MB/s

//bufffer 1M,129.782s
//buffer 4096  131.223
//buffer 16 127.993
