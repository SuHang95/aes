#include<stdio.h>
#include"../aes.h"
#include<time.h>
#define Buffsize 0x80000


void map_to_AESKey1(unsigned char *Key, unsigned char AES_Key[16],uint32_t k)
{//把原始的密钥通过MD5变成AES需要的密钥，k是需要附加的值，而且k是变化的,要求cypher1是长为16为的char型数组
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
}


int main()
{
	FILE *fp, *fp2, *fp1;
	unsigned char cypher[256], AES_KEY[16];
	uint32_t KEY_EXTEND[44], temp = 0;
	size_t i = 0;
	double j = 0;
	unsigned char filename[256], filename1[256];
	unsigned char *file=(unsigned char*)malloc(sizeof(unsigned char)*Buffsize);
	
	
	printf("请输入文件路径及文件名，可以是相对路径，也可以是绝对路径,0加回车则为默认文件\n");
	scanf("%s", filename);
	if (filename[0] =='0' && filename[1] =='\0')
	{
		strcpy(filename,"plaintext");
	}
	for (int i = 0; i < 256; i++)
		cypher[i] = 0;
	
	printf("请输入密钥内容，最好大于16个简单字符或8个汉字,0加回车则为默认密钥\n");
	scanf("%s", cypher);
	if (cypher[0] == '0' && cypher[1] == '\0')
	{//读出密钥,如果没有则选择默认文件cypher.txt里内容为cypher
		
		strcpy(cypher,"cypher.txt");
		if ((fp = fopen(cypher, "r")) == NULL)
		{//如果不成功则打印文件读写失败
			printf("\nCannot open cypher!");
			return 1;
		}
		for (int i = 0; i < 256; i++)
			cypher[i] = 0;
		while ((!feof(fp)) && i < 254)
		{
			cypher[i] = fgetc(fp);
			i++;
		}
		fclose(fp);
		cypher[i] = '\0';
	}
	
	
	printf("请输入输出文件路径及文件名，可以是相对路径，也可以是绝对路径,0加回车则为默认文件名\n");
	scanf("%s", filename1);
	if (filename1[0] == '0' && filename1[1] == '\0')
	{
		strcpy(filename1,"output.encrypt");
	}
	
	//读出源文件,
	if ((fp1 = fopen(filename, "rb")) == NULL)
	{//如果不成功则退出
		printf("\nCannot open plaintext, exit!");
		return 1;
	}
	fp2 = fopen(filename1, "wb");
	
	
	i = 0;
	clock_t start, finish;
	start = clock();
	
	map_to_AESKey1(cypher, AES_KEY, 0);
	cypher_extended(AES_KEY, KEY_EXTEND);
	while (!feof(fp1))
	{
		file[i%Buffsize] = fgetc(fp1);
		if ((i % Buffsize) == Buffsize-1)
		{
			for(size_t j=0;j<Buffsize/0x10;j++)
			{
				AES_encrypt((unsigned int*)&(file[j*0x10]), &KEY_EXTEND[0]);
			}
			for (size_t j = 0; j < Buffsize; j++)
			{
				fputc(file[j], fp2);
			}
		}
		i++;
	}
	i = i - 1;
	for (size_t j = 0; j<((i-(i%0x10))%Buffsize)/0x10; j++)
	{
		AES_encrypt(((unsigned int*)&(file[j * 0x10])), &KEY_EXTEND[0]);
	}
	for (size_t j = 0; j < i%Buffsize; j++)
	{
		fputc(file[j], fp2);
	}
	
	finish = clock();
	j = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("加密了%ld字节，用时为%lf秒\n", i, j);
	free(file);
	fclose(fp1);
	fclose(fp2);
	return 0;
}

//加密机械姬，用时226.53900s
//更新:利用单表替换算法实现多项式乘法后，加密机械姬用时135.327s,吞吐量位8.74MB/s
//更新:第二次测试129.416s,吞吐量9.14MB/s

//bufffer 1M,129.782s
//buffer 4096  131.223
//buffer 16 127.993
