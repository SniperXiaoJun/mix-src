#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "o_all_func_def.h"
#include "pci_func_def.h"


int main(int argc, char * argv[])
{
	unsigned long ulRet = 0;
	unsigned long len = 0;
	unsigned int select = 0;
	time_t time_start;
	time_t time_end;
	unsigned long	ulResult = 0;
	ECCrefPublicKey  stECC_PK_Gen = {0};			// ECC生成钥（待生成）
	ECCrefPrivateKey stECC_SK_Gen = {0};			// ECC生成密钥（待生成）
	unsigned int ulEnPrivakeyLen = ECCref_MAX_LEN;	// 密文私钥长度
	void * hSessionHandle = NULL;
	void * hPCIHandle = NULL;
	unsigned long userID;
	unsigned long ulRetry = 0;
	int i = 0;
	
	if(argc != 2 || strlen(argv[1]) != 8)
	{
		printf("%s\n","arg err, argv[1] is the password and must be 8 byts length");
		return -1;
	}
	
	ulResult = PCI_Open(&hPCIHandle,&hSessionHandle);
	
	if(ulResult)
	{
		printf("%s\n","open pci err");
		return -1;
	}
	
	ulResult = PCI_ICLogin(hSessionHandle, (unsigned char *)argv[1], 8, &userID, &ulRetry);
	if(ulResult)
	{
		printf("%s,retry = %d\n","login pci err", ulRetry);
		return -1;
	}
	// test if is the user if operator user;
	ulResult = SDF_GenerateKeyPair_ECC(
						hSessionHandle, 
						KEY_TYPE_ECC,
						ECCref_MAX_BITS,
						&stECC_PK_Gen,
						&stECC_SK_Gen);

	if (0 == ulResult)
	{
		
	}
	else
	{
		printf("%s\n","user must be operator user");
		return -1;
	}
	
	printf("\nUsage:\n");
	printf("\t%d:%s\n", 0,"exit");
	printf("\t%d:%s\n", 1,"gen sm2 keypair test");
	printf("\t%d:%s\n", 2,"sm2 sign test");
	printf("\t%d:%s\n", 3,"sm2 verify test");


	while ('0' != (select = getchar()))
	{
		switch(select)
		{
		case '0':
			break;
		case '1':
			{
				int n = 10000;
				printf("%s\n","gen sm2 keypair test");
				time(&time_start);
				printf("\nstart time:%s\n",ctime(&time_start));
				
				for(i = 0; i < n; i++)
				{
					// 生成ECC密钥对
					ulResult = SDF_GenerateKeyPair_ECC(
						hSessionHandle, 
						KEY_TYPE_ECC,
						ECCref_MAX_BITS,
						&stECC_PK_Gen,
						&stECC_SK_Gen);

					if (0 == ulResult)
					{
						int j = 0;
						printf("\n%d time", i + 1);
						printf("\npubkey-x\n");
						for(j =0; j < 32; j++)
						{
							printf("%2x ",stECC_PK_Gen.x[j]);
						}
						printf("\npubkey-y\n");
						for(j =0; j < 32; j++)
						{
							printf("%2x ",stECC_PK_Gen.y[j]);
						}
						printf("\nprivatekey\n");
						for(j =0; j < 32; j++)
						{
							printf("%2x ",stECC_SK_Gen.D[j]);
						}
					}
					else
					{
						printf("something err");
						break;
					}
				}
				
				time(&time_end);
				printf("\nend time:%s\n",ctime(&time_end));
				printf("\nuse time %ds,gen sm2 keypair %d times!",time_end-time_start,n);
			}
			break;
		case '2':
			{
				int n = 10000;
				unsigned char digest[32] = {0};
				
				srand(time(NULL)); // 设定随机数种子

				printf("\random-digest\n");
				for(i = 0; i < 32; i++)
				{
					digest[i] = rand()%255;
					printf("%2x ",digest[i]);
				}
				
				// 生成ECC密钥对
				ulResult = SDF_GenerateKeyPair_ECC(
						hSessionHandle, 
						KEY_TYPE_ECC,
						ECCref_MAX_BITS,
						&stECC_PK_Gen,
						&stECC_SK_Gen);

				if (0 == ulResult)
				{
					int j = 0;
					printf("\npubkey-x\n");
					for(j =0; j < 32; j++)
					{
						printf("%2x ",stECC_PK_Gen.x[j]);
					}
					printf("\npubkey-y\n");
					for(j =0; j < 32; j++)
					{
						printf("%2x ",stECC_PK_Gen.y[j]);
					}
					printf("\nprivatekey\n");
					for(j =0; j < 32; j++)
					{
						printf("%2x ",stECC_SK_Gen.D[j]);
					}
				}
				else
				{
					printf("%s\n","something err");
					return -1;
				}
				
				printf("%s\n","sm2 sign test");
				time(&time_start);
				printf("\nstart time:%s\n",ctime(&time_start));
				
				for(i = 0; i < n; i++)
				{
					ECCSignature stECCSignature = {0};
					
					// 签名
					ulResult = SDF_ExternalSign_ECC(
						hSessionHandle,
						SGD_SM2_1,
						&stECC_SK_Gen,
						(SGD_UCHAR *)digest,
						32,
						&stECCSignature);
					
					if (0 == ulResult)
					{
						int j = 0;
						printf("\n%d time", i + 1);
						printf("\nSignature-r\n");
						for(j =0; j < 32; j++)
						{
							printf("%2x ",stECCSignature.r[j]);
						}
						printf("\nSignature-s\n");
						for(j =0; j < 32; j++)
						{
							printf("%2x ",stECCSignature.s[j]);
						}
					}
					else
					{
						printf("something err");
						break;
					}
				}
				
				time(&time_end);
				printf("\nend time:%s\n",ctime(&time_end));
				printf("\nuse time %ds,sm2 sign test %d times!",time_end-time_start,n);
			}
			break;
		case '3':
			{
				int n = 10000;
				unsigned char digest[32] = {0};
				ECCSignature stECCSignature = {0};
				
				srand(time(NULL)); // 设定随机数种子

				printf("\random-digest\n");
				for(i = 0; i < 32; i++)
				{
					digest[i] = rand()%255;
					printf("%2x ",digest[i]);
				}
				
				// 生成ECC密钥对
				ulResult = SDF_GenerateKeyPair_ECC(
						hSessionHandle, 
						KEY_TYPE_ECC,
						ECCref_MAX_BITS,
						&stECC_PK_Gen,
						&stECC_SK_Gen);

				if (0 == ulResult)
				{
					int j = 0;
					printf("\npubkey-x\n");
					for(j =0; j < 32; j++)
					{
						printf("%2x ",stECC_PK_Gen.x[j]);
					}
					printf("\npubkey-y\n");
					for(j =0; j < 32; j++)
					{
						printf("%2x ",stECC_PK_Gen.y[j]);
					}
					printf("\nprivatekey\n");
					for(j =0; j < 32; j++)
					{
						printf("%2x ",stECC_SK_Gen.D[j]);
					}
				}
				else
				{
					printf("%s\n","something err");
					return -1;
				}
				
				// 签名
				ulResult = SDF_ExternalSign_ECC(
					hSessionHandle,
					SGD_SM2_1,
					&stECC_SK_Gen,
					(SGD_UCHAR *)digest,
					32,
					&stECCSignature);
				
				if (0 == ulResult)
				{
					int j = 0;
					printf("\nSignature-r\n");
					for(j =0; j < 32; j++)
					{
						printf("%2x ",stECCSignature.r[j]);
					}
					printf("\nSignature-s\n");
					for(j =0; j < 32; j++)
					{
						printf("%2x ",stECCSignature.s[j]);
					}
				}
				else
				{
					printf("something err");
					break;
				}
				
				
				printf("%s\n","sm2 verfiy test");
				time(&time_start);
				printf("\nstart time:%s\n",ctime(&time_start));
				
				for(i = 0; i < n; i++)
				{
					ulResult = SDF_ExternalVerify_ECC(
						hSessionHandle,
						SGD_SM2_1,
						&stECC_PK_Gen,
						(SGD_UCHAR *)digest,
						32,
						&stECCSignature);
					
					if (0 == ulResult)
					{
						int j = 0;
						printf("\n%d time OK", i + 1);
					}
					else
					{
						printf("something err");
						break;
					}
				}
				
				time(&time_end);
				printf("\nend time:%s\n",ctime(&time_end));
				printf("\nuse time %ds,sm2 verify test %d times!",time_end-time_start,n);
			}
			break;
		default:
			printf("\nUsage:\n");
			printf("\t%d:%s\n", 0,"exit");
			printf("\t%d:%s\n", 1,"gen sm2 keypair test");
			printf("\t%d:%s\n", 2,"sm2 sign test");
			printf("\t%d:%s\n", 3,"sm2 verify test");

		}
	}

	PCI_ICLogout(hSessionHandle,2);
	PCI_Close(hPCIHandle,hSessionHandle);
	

	return 0;
}
