#include<stdio.h>
#include<stdlib.h>
#include"../aes.h"
#include<time.h>
#define BUFFSIZE 0x80000


int main()
{
	FILE *fp, *fp2, *fp1;
	unsigned char cypher[256], AES_KEY[16];
	uint32_t KEY_EXTEND[44], temp = 0;
	size_t i = 0;
	int size = 0;
	clock_t start, finish;
	double duration;
	unsigned char file[0x80000];
	
	unsigned char filename[256], filename1[256];
	printf("请输入文件路径及文件名，可以是相对路径，也可以是绝对路径,0加回车则为默认文件\n");
	scanf("%s", filename);
	if (filename[0] == 30 && filename[1] == 0)
	{
		strcpy(filename,"output.encrypt");
	}
	for (int i = 0; i < 256; i++)
		cypher[i] = 0;
	printf("请输入密钥内容，最好大于16个简单字符或8个汉字,0加回车则为默认密钥\n");
	scanf("%s", cypher);
	if (cypher[0] == '0' && cypher[1] == '\0')
	{
		strcpy(cypher, "cypher.txt");
		//读出密钥
		if ((fp = fopen(cypher, "r")) == NULL)
		{//如果不成功则打印文件读写失败
			printf("\nCannot open cypher, exit!");
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
	if (filename1[0] == 30 && filename1[1] == 0)
	{
		strcpy(filename1,"decrption");
	}



	//读出源文件,
	if ((fp1 = fopen(filename, "rb")) == NULL)
	{//如果不成功则打印文件读写失败
		printf("\nCannot open plaintext!");
		return 1;
	}
	i = 0;
	fp2 = fopen(filename1, "wb");
	start = clock();

	while (!feof(fp1))
	{
		file[i % BUFFSIZE] = fgetc(fp1);
		if ((i % BUFFSIZE) == BUFFSIZE-1)
		{
			for (size_t j = 0; j<BUFFSIZE/0x10; j++)
			{
				map_to_AESKey1(cypher, AES_KEY, temp);
				cypher_extended(AES_KEY, KEY_EXTEND);
				*((unsigned char*)(&temp)) = file[j * 0x10 + 0xc];
				*((unsigned char*)(&temp) + 1) = file[j * 0x10 + 0xd];
				*((unsigned char*)(&temp) + 2) = file[j * 0x10 + 0xe];
				*((unsigned char*)(&temp) + 3) = file[j * 0x10 + 0xf];
				AES_decrypt((unsigned int*)&(file[j * 0x10]), &KEY_EXTEND[0]);
			}
			for (size_t j = 0; j < BUFFSIZE; j++)
			{
				fputc(file[j], fp2);
			}
		}
		i++;
	}
	i = i - 1;
	for (size_t j = 0; j<((i - (i % 0x10)) % BUFFSIZE) / 0x10; j++)
	{
		map_to_AESKey1(cypher, AES_KEY, temp);
		cypher_extended(AES_KEY, KEY_EXTEND);
		*((unsigned char*)(&temp)) = file[j * 0x10 + 0xc];
		*((unsigned char*)(&temp) + 1) = file[j * 0x10 + 0xd];
		*((unsigned char*)(&temp) + 2) = file[j * 0x10 + 0xe];
		*((unsigned char*)(&temp) + 3) = file[j * 0x10 + 0xf];
		AES_decrypt((unsigned int*)&(file[j * 0x10]), &KEY_EXTEND[0]);
	}
	for (size_t j = 0; j < i%BUFFSIZE; j++)
	{
		fputc(file[j], fp2);
	}
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	
	printf("解密结束，解密时间为%lf秒", duration);
	fclose(fp1);
	fclose(fp2);
	printf("\n");
}
