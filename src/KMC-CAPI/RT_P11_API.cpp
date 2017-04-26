#include "RT_P11_API.h"
#include "FILE_LOG.h"
#include "o_all_type_def.h"
#include "o_all_func_def.h"
#include <string.h>
#include <pkcs11/cryptoki-win32.h>
#include <Windows.h>

#define RT_P11_API_USE_CRC 1
#define RT_P11_API_USE_DEFAULT_VALUE 0

#define GM_ECC_512_BYTES_LEN (32*2)

CK_BBOOL bTrue = CK_TRUE;
CK_BBOOL bFalse = CK_FALSE;

HMODULE g_hP11Module = NULL;
CK_FUNCTION_LIST* g_FunctionPtr = NULL;


CK_ULONG IN_LoadLibrary( void )
{
	CK_RV rv; 	// Return Code 
	char *perror;	
	CK_RV (*symPtr)(CK_FUNCTION_LIST_PTR_PTR);

	perror = 0;

	//Load library.
	if(g_hP11Module == NULL)
	{
		g_hP11Module = LoadLibraryA("TFTknP11.dll"); 
		if (!g_hP11Module)
		{
			return CKR_GENERAL_ERROR;   
		}

		//Load C_GetFunctionList.
		symPtr = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))GetProcAddress(g_hP11Module, "C_GetFunctionList");  
		if (!symPtr)
		{
			return CKR_GENERAL_ERROR;  
		}

		rv = symPtr(&g_FunctionPtr); 
		if(rv != CKR_OK)
			return rv;

		rv = g_FunctionPtr->C_Initialize(NULL);
		if(rv != CKR_OK)
			return rv;
	}

	return CKR_OK;
}


void IN_FreeLibrary()
{
	if(g_hP11Module != NULL)
	{
		g_FunctionPtr->C_Finalize(NULL);
		FreeLibrary(g_hP11Module);
		g_hP11Module=NULL;
		g_FunctionPtr=NULL;
	}
}

int RT_P11_API_SetMetas(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	char *pSecID, int uiSecIDLen,
	unsigned char *pHMac, int uiHMacLen,
	char * pszPIN, unsigned int * pulRetry
	)
{
	CK_RV rv = CKR_OK;

	CK_ULONG ulSlotID = 0;
	CK_ULONG ulAuthSlotID = 0;
	CK_SLOT_ID szSlotID[256];
	CK_ULONG ulSlotCount = 256;
	int i = 0;
	CK_SESSION_HANDLE hSession = NULL_PTR;

	IN_LoadLibrary();

	ulSlotCount = sizeof(szSlotID)/sizeof(CK_SLOT_ID);
	rv = g_FunctionPtr->C_GetSlotList(bTrue, szSlotID, &ulSlotCount);
	if(rv != CKR_OK)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	ulAuthSlotID = atoi((char *) pAuthKey);

	for(i = 0; i < ulSlotCount; i++)
	{
		if (szSlotID[i] == ulAuthSlotID)
		{
			continue;
		}
		else
		{
			ulSlotID = szSlotID[i];
			break;
		}
	}

	rv = g_FunctionPtr->C_OpenSession(ulSlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	rv = g_FunctionPtr->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pszPIN, strlen(pszPIN));
	if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	{{
		// this add secid
		CK_KEY_TYPE		keyType = CKK_GENERIC_SECRET;
		CK_OBJECT_CLASS dataClass = CKO_DATA;
		CK_OBJECT_HANDLE hSecID=NULL_PTR;
		CK_OBJECT_HANDLE hObjectFind[16] = {0};
		CK_ULONG ulObjectFind = 16;

		CK_ATTRIBUTE secIDCreateTemplate[] = {
			{CKA_CLASS, &dataClass, sizeof(dataClass)},
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_OBJECT_ID, RT_SECID, strlen(RT_SECID)}, // 数据对象 CKA_OBJECT_ID
			{CKA_VALUE, pSecID, uiSecIDLen}
		};

		CK_ATTRIBUTE findTemplate[] = {
			{CKA_CLASS, &dataClass, sizeof(dataClass)},
			{CKA_ID, RT_SECID, strlen(RT_SECID)}
		};


		rv = g_FunctionPtr->C_FindObjectsInit(hSession, findTemplate, sizeof(findTemplate)/sizeof(CK_ATTRIBUTE));
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_FindObjects(hSession, hObjectFind, sizeof(hObjectFind)/sizeof(CK_OBJECT_HANDLE), &ulObjectFind); 
		g_FunctionPtr->C_FindObjectsFinal(hSession);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		if(ulObjectFind > 0)
		{
			
		}
		else
		{
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_HEX(file_log_name, (unsigned char *)pSecID, strlen(pSecID));

			rv = g_FunctionPtr->C_CreateObject(hSession, secIDCreateTemplate, sizeof(secIDCreateTemplate) / sizeof(CK_ATTRIBUTE), &hSecID);
			if (rv != CKR_OK) {
				FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
				goto err;
			}
			
		}

		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulObjectFind);
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	}}


	{{
		// HMAC密钥
		// 每个用户有9个HMAC密钥，每个密钥长度为32字节
		// 09 +
		// 0120 3131313131313131313131313131313131313131313131313131313131313131 +
		// 0220 3232323232323232323232323232323232323232323232323232323232323232 +
		// 0320 3333333333333333333333333333333333333333333333333333333333333333 +
		// 0420 3434343434343434343434343434343434343434343434343434343434343434 +
		// 0520 3535353535353535353535353535353535353535353535353535353535353535 +
		// 0620 3636363636363636363636363636363636363636363636363636363636363636 +
		// 0720 3737373737373737373737373737373737373737373737373737373737373737 + 
		// 0820 3838383838383838383838383838383838383838383838383838383838383838 + 09 3939393939393939393939393939393939393939393939393939393939393939

		// A类用户
		// char *pszHMACKey = "03012031313131313131313131313131313131313131313131313131313131313131310520353535353535353535353535353535353535353535353535353535353535353506203636363636363636363636363636363636363636363636363636363636363636";
		unsigned char bHMACKey[512];

		CK_KEY_TYPE		keyType = CKK_GENERIC_SECRET;
		CK_OBJECT_CLASS SecretClass = CKO_SECRET_KEY;
		CK_ATTRIBUTE KPXTemplate[] = {
			{CKA_CLASS, &SecretClass, sizeof(SecretClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_ID, RT_HMAC_KEY, strlen(RT_HMAC_KEY)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VALUE, (unsigned char *)bHMACKey, 1+1+32+1+32+32}
		};
		CK_OBJECT_HANDLE hKPX=NULL_PTR;
		int pos = 0;
		CK_OBJECT_HANDLE hObjectFind[16] = {0};
		CK_ULONG ulObjectFind = 16;


		CK_ATTRIBUTE findTemplate[] = {
			{CKA_CLASS, &SecretClass, sizeof(SecretClass)},
			{CKA_ID, RT_SECID, strlen(RT_SECID)}
		};

		rv = g_FunctionPtr->C_FindObjectsInit(hSession, findTemplate, sizeof(findTemplate)/sizeof(CK_ATTRIBUTE));
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_FindObjects(hSession, hObjectFind, sizeof(hObjectFind)/sizeof(CK_OBJECT_HANDLE), &ulObjectFind); 
		g_FunctionPtr->C_FindObjectsFinal(hSession);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		if(ulObjectFind > 0)
		{

		}
		else
		{
			switch(pSecID[0])
			{
			case '1':
				//A类用户CKA_VALUE：
				//	03 + {01+20+HK1} + {05+20+HK5} + {06+20+HK6}
				pos = 0;
				bHMACKey[pos] = 0x03;
				pos+=1;
				bHMACKey[pos] = 0x01;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x01-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x05;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x05-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x06;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x06-1)*32,32);
				pos+=32;
				KPXTemplate[5].ulValueLen = pos;
				break;
			case '2':
				//B0类用户CKA_VALUE：
				//	05 + {02+20+HK2} + {06+20+HK6} + {07+20+HK7} + {08+20+HK8}  + {09+20+HK9}
				pos = 0;
				bHMACKey[pos] = 0x05;
				pos+=1;
				bHMACKey[pos] = 0x02;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x02-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x06;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x06-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x07;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x07-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x08;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x08-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x09;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x09-1)*32,32);
				pos+=32;
				KPXTemplate[5].ulValueLen = pos;
				break;
			case '3':
				//B1类用户CKA_VALUE：
				//	03 + {03+20+HK3} + {08+20+HK8} + {09+20+HK9}
				pos = 0;
				bHMACKey[pos] = 0x03;
				pos+=1;
				bHMACKey[pos] = 0x03;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x03-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x08;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x08-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x09;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x09-1)*32,32);
				pos+=32;
				KPXTemplate[5].ulValueLen = pos;
				break;
			case '4':
				//C类用户CKA_VALUE：
				//	02 + {04+20+HK4} + {09+20+HK9}
				pos = 0;
				bHMACKey[pos] = 0x02;
				pos+=1;
				bHMACKey[pos] = 0x04;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x04-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x09;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x09-1)*32,32);
				pos+=32;
				KPXTemplate[5].ulValueLen = pos;
				break;
			default:
				break;
			}

			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_HEX(file_log_name, bHMACKey, pos);

			rv = g_FunctionPtr->C_CreateObject(hSession, KPXTemplate, sizeof(KPXTemplate) / sizeof(CK_ATTRIBUTE), &hKPX);
			if (rv != CKR_OK) {
				FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
				goto err;
			}
		}

		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulObjectFind);
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	}}

err:
	if (hSession)
	{
		g_FunctionPtr->C_CloseSession(hSession);
	}

	IN_FreeLibrary();

	return rv;

}


#if RT_P11_API_USE_CRC

typedef unsigned int U32;

#define CRC_INIT 0x0000

/****下表是常用ccitt 16,生成式1021反转成8408后的查询表格****/
unsigned short crc16_ccitt_table[256] =
{
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

unsigned short crc_16(unsigned char *message, unsigned int len)
{
	unsigned short crc_reg = CRC_INIT;

	while (len--)
		crc_reg = (crc_reg >> 8) ^ crc16_ccitt_table[(crc_reg ^ *message++) & 0xff];

	return crc_reg;
} 

#endif


int RT_P11_API_SetZMMetas(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	char *pSecID, int uiSecIDLen,
	unsigned char szR1[32],unsigned char szR2[32], 
	unsigned char *pKPX, int uiKPXLen,
	unsigned char *pSignKey, int uiSignKeyLen,
	unsigned char *pCryptKey, int uiCryptKeyLen,
	unsigned char *pExchangeKey, int uiExchangeKeyLen,
	char * pszPIN, unsigned int * pulRetry
	)
{
	CK_RV rv = CKR_OK;

	CK_ULONG ulSlotID = 0;
	CK_ULONG ulAuthSlotID = 0;
	CK_SLOT_ID szSlotID[256];
	CK_ULONG ulSlotCount = 256;
	unsigned char szR3[32] = {0};
	int i = 0;
	CK_SESSION_HANDLE hSession = NULL_PTR;

	IN_LoadLibrary();



#if RT_P11_API_USE_DEFAULT_VALUE

	{
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// 
		// 中办定制

		//   随机数：
		//       r1：0101010101010101010101010101010101010101010101010101010101010101
		//       r2：0202020202020202020202020202020201010101010101010101010101010101
		//       r3=r1⊕r2: 03030303030303030303030303030303
		//   r2用联通服务器SM2公钥加密导给服务器

		//   互通密钥参数：
		//   A类用户（KPA）： 0x02 + {0x31 + KA} + {0x32 + KB0}
		//       0x02 + 0x31 + AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA + 0x32 + B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0
		//   B0类用户（KPB0）：0x02 + {0x32 + KB0}+ {0x33 + KB1}
		//       0x02 + 0x32 + B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0 + 0x33 + B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1
		//   B1类用户（KPB1）：0x01 + {0x33 + KB1}
		//       0x01 + 0x33 + B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1
		//   r1加密KPX后(r1加密KPX后，与固定数据对称异或，固定数据为：5A595F4A4D54657374584F5244617461)：
		//       A类用户（KPA）：  0x02 + 0x31 + BE087F4168213C144B6DA3AACBF5D056BE087F4168213C144B6DA3AACBF5D056 + 0x32 + FAAAAE0892E71A69BAC81ECC3CCD3E1BFAAAAE0892E71A69BAC81ECC3CCD3E1B
		//       B0类用户（KPB0）：0x02 + 0x32 + FAAAAE0892E71A69BAC81ECC3CCD3E1BFAAAAE0892E71A69BAC81ECC3CCD3E1B + 0x33 + D0E229A2F36BA390071A4EC3E70C1D55D0E229A2F36BA390071A4EC3E70C1D55
		//       B1类用户（KPB1）：0x01 + 0x33 + D0E229A2F36BA390071A4EC3E70C1D55D0E229A2F36BA390071A4EC3E70C1D55


		// 专密ECC512密钥对
		// 签名：
		//     公钥：3C38323473E06F922A7B1309FA8DD61FEE05ED6E0B85D7C9B7C13218E4DC28F519E3DB21B24BBFB393927583A6416E0C4DA3A64080B81B8A7C36A80A9D7DA6BA3DAD4DA77DCC7573FB3B400914184D5FFAD0225077AED46BCBC2C4E0F10A96B62702AEC66570A1DB6EAA9933DDD1B4B1C87BA90C6AA635058695EC15A767DEF1
		//     私钥：39469E05AE530C64A99599FBE72FC56209B8A995232865FDF47CE0B4CB32CD8945C6008AFDF24E475CCB64013B625FB3AE881206A0490EC0B86C4F44AD2A6C34
		// r1加密后私钥：9EBDB1CD25754F5A5DA1508BCF0A882D 950BA10E5D5BC8B036AC11743946487A 5DBF841D70472592AE07D8415B6F4185 CA68BE6639CF2E5C80A02A6E54CCC61D
		// 加密：
		//     公钥：B94126B7ED5A2DED7B6D91712E330310C2546ACB19A028389725C8D8314DFC8FC7791F9BC156317090376B06D3C7F60C0B91BBB50B929C4DF344CAACAD55D1ED20C28DCD586F97C3E2276FDB9A9190292FC36DB2264F030D3E40C0022952C554756A96831C7F6604D505E3448FFE50E9C505ACFD5AA54115A9A41DEE4D572B90
		//     私钥：55EFA1E323D90772E9C1E0DA17A6AB492ADDC5FA9A250919740897EEC53449B66273C52D063E3BABEB81FE1A895EAAF0E87B5C97A94CA2CA1695D2193C858E7B
		// r1加密后私钥：70E20553368A5C0D3C4C38DF635D04F4 9B37E087970E90B2AE06013CDFFE968F CD30A0EFB86BC1CEFB6B240FB66AE374 3BF5F64FE02DCDE80FA4489A965116BD
		// 交换：
		//     公钥：95A2768BD82CF689540E3D1C3D6E2F7C06DC693706B731363C18927DBC08EE5828DD4422AC7559197536F5E99B1277A56FAC7EFA47EBBCAA57CBD44AD793E61243AC095ECD2BD5247875551B9E46B614FC6E909C905521B22E9CEE407DB118C4BFAE7AA4D035CAAADDE0DB11E4C32A343282F71C35F922442927641146BACF3E
		//     私钥：9C98B36A34FADE5DC8F497898352129D32E1244A95541F732376C9098B9C98740B10F6947023BE35DE89E11E992B1DEA6CDA4EDAA932DB994F4DC617A0FCE5F0
		// r1加密后私钥：56542FCA38140CCCA8DEFB8DF90E6394 BBE45EBD8107B822C54D1FB61D7202D6 D22B3529A2483190F4460368321B38CF AC2344C8A997D71A962D966D3A1B4BC3


		// HMAC密钥
		// 9个HMAC密钥，每个密钥长度为32字节
		// 09 +
		// 01 3131313131313131313131313131313131313131313131313131313131313131 +
		// 02 3232323232323232323232323232323232323232323232323232323232323232 +
		// 03 3333333333333333333333333333333333333333333333333333333333333333 +
		// 04 3434343434343434343434343434343434343434343434343434343434343434 +
		// 05 3535353535353535353535353535353535353535353535353535353535353535 +
		// 06 3636363636363636363636363636363636363636363636363636363636363636 +
		// 07 3737373737373737373737373737373737373737373737373737373737373737 + 
		// 08 3838383838383838383838383838383838383838383838383838383838383838 + 
		// 09 3939393939393939393939393939393939393939393939393939393939393939


		memset(szR1,1,32);
		memset(szR2,2,32);

		memcpy(pSignKey + 4, "\x3C\x38\x32\x34\x73\xE0\x6F\x92\x2A\x7B\x13\x09\xFA\x8D\xD6\x1F\xEE\x05\xED\x6E\x0B\x85\xD7\xC9\xB7\xC1\x32\x18\xE4\xDC\x28\xF5\x19\xE3\xDB\x21\xB2\x4B\xBF\xB3\x93\x92\x75\x83\xA6\x41\x6E\x0C\x4D\xA3\xA6\x40\x80\xB8\x1B\x8A\x7C\x36\xA8\x0A\x9D\x7D\xA6\xBA\x3D\xAD\x4D\xA7\x7D\xCC\x75\x73\xFB\x3B\x40\x09\x14\x18\x4D\x5F\xFA\xD0\x22\x50\x77\xAE\xD4\x6B\xCB\xC2\xC4\xE0\xF1\x0A\x96\xB6\x27\x02\xAE\xC6\x65\x70\xA1\xDB\x6E\xAA\x99\x33\xDD\xD1\xB4\xB1\xC8\x7B\xA9\x0C\x6A\xA6\x35\x05\x86\x95\xEC\x15\xA7\x67\xDE\xF1",2 * GM_ECC_512_BYTES_LEN);
		memcpy(pSignKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, "\x39\x46\x9E\x05\xAE\x53\x0C\x64\xA9\x95\x99\xFB\xE7\x2F\xC5\x62\x09\xB8\xA9\x95\x23\x28\x65\xFD\xF4\x7C\xE0\xB4\xCB\x32\xCD\x89\x45\xC6\x00\x8A\xFD\xF2\x4E\x47\x5C\xCB\x64\x01\x3B\x62\x5F\xB3\xAE\x88\x12\x06\xA0\x49\x0E\xC0\xB8\x6C\x4F\x44\xAD\x2A\x6C\x34", GM_ECC_512_BYTES_LEN);

		memcpy(pCryptKey + 4, "\xB9\x41\x26\xB7\xED\x5A\x2D\xED\x7B\x6D\x91\x71\x2E\x33\x03\x10\xC2\x54\x6A\xCB\x19\xA0\x28\x38\x97\x25\xC8\xD8\x31\x4D\xFC\x8F\xC7\x79\x1F\x9B\xC1\x56\x31\x70\x90\x37\x6B\x06\xD3\xC7\xF6\x0C\x0B\x91\xBB\xB5\x0B\x92\x9C\x4D\xF3\x44\xCA\xAC\xAD\x55\xD1\xED\x20\xC2\x8D\xCD\x58\x6F\x97\xC3\xE2\x27\x6F\xDB\x9A\x91\x90\x29\x2F\xC3\x6D\xB2\x26\x4F\x03\x0D\x3E\x40\xC0\x02\x29\x52\xC5\x54\x75\x6A\x96\x83\x1C\x7F\x66\x04\xD5\x05\xE3\x44\x8F\xFE\x50\xE9\xC5\x05\xAC\xFD\x5A\xA5\x41\x15\xA9\xA4\x1D\xEE\x4D\x57\x2B\x90",2 * GM_ECC_512_BYTES_LEN);
		memcpy(pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4,"\x55\xEF\xA1\xE3\x23\xD9\x07\x72\xE9\xC1\xE0\xDA\x17\xA6\xAB\x49\x2A\xDD\xC5\xFA\x9A\x25\x09\x19\x74\x08\x97\xEE\xC5\x34\x49\xB6\x62\x73\xC5\x2D\x06\x3E\x3B\xAB\xEB\x81\xFE\x1A\x89\x5E\xAA\xF0\xE8\x7B\x5C\x97\xA9\x4C\xA2\xCA\x16\x95\xD2\x19\x3C\x85\x8E\x7B",GM_ECC_512_BYTES_LEN);

		memcpy(pExchangeKey + 4, "\x95\xA2\x76\x8B\xD8\x2C\xF6\x89\x54\x0E\x3D\x1C\x3D\x6E\x2F\x7C\x06\xDC\x69\x37\x06\xB7\x31\x36\x3C\x18\x92\x7D\xBC\x08\xEE\x58\x28\xDD\x44\x22\xAC\x75\x59\x19\x75\x36\xF5\xE9\x9B\x12\x77\xA5\x6F\xAC\x7E\xFA\x47\xEB\xBC\xAA\x57\xCB\xD4\x4A\xD7\x93\xE6\x12\x43\xAC\x09\x5E\xCD\x2B\xD5\x24\x78\x75\x55\x1B\x9E\x46\xB6\x14\xFC\x6E\x90\x9C\x90\x55\x21\xB2\x2E\x9C\xEE\x40\x7D\xB1\x18\xC4\xBF\xAE\x7A\xA4\xD0\x35\xCA\xAA\xDD\xE0\xDB\x11\xE4\xC3\x2A\x34\x32\x82\xF7\x1C\x35\xF9\x22\x44\x29\x27\x64\x11\x46\xBA\xCF\x3E",2 * GM_ECC_512_BYTES_LEN);
		memcpy(pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4,"\x9C\x98\xB3\x6A\x34\xFA\xDE\x5D\xC8\xF4\x97\x89\x83\x52\x12\x9D\x32\xE1\x24\x4A\x95\x54\x1F\x73\x23\x76\xC9\x09\x8B\x9C\x98\x74\x0B\x10\xF6\x94\x70\x23\xBE\x35\xDE\x89\xE1\x1E\x99\x2B\x1D\xEA\x6C\xDA\x4E\xDA\xA9\x32\xDB\x99\x4F\x4D\xC6\x17\xA0\xFC\xE5\xF0",GM_ECC_512_BYTES_LEN);

		memset(pKPX+0*32,0xAA,32);
		memset(pKPX+1*32,0xB0,32);
		memset(pKPX+2*32,0xB1,32);
	}

#endif

	ulSlotCount = sizeof(szSlotID)/sizeof(CK_SLOT_ID);
	rv = g_FunctionPtr->C_GetSlotList(bTrue, szSlotID, &ulSlotCount);
	if(rv != CKR_OK)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	ulAuthSlotID = atoi((char *) pAuthKey);

	for(i = 0; i < ulSlotCount; i++)
	{
		if (szSlotID[i] == ulAuthSlotID)
		{
			continue;
		}
		else
		{
			ulSlotID = szSlotID[i];
			break;
		}
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSecID, strlen(pSecID));

	rv = g_FunctionPtr->C_OpenSession(ulSlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	rv = g_FunctionPtr->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pszPIN, strlen(pszPIN));
	if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey, uiSignKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey, uiCryptKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey, uiExchangeKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pKPX, uiKPXLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR1, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR2, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR3, 32);

	// c1 encrypt key and zmp
	{

#if 1
		CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
		CK_KEY_TYPE keyType = CKK_ZYJM;
		CK_OBJECT_HANDLE hKey = NULL_PTR;
		CK_ATTRIBUTE KeyTemplate[] = {
			{CKA_CLASS, &objectClass, sizeof(objectClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &bFalse, sizeof(bFalse)},
			{CKA_ID, "temp_key", strlen("temp_key")},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VALUE, szR1, 32}
		};

		CK_ULONG ulLen = 0;

		CK_MECHANISM mech = {CKM_ZYJM_ECB, NULL, 0};

#else
		CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
		CK_KEY_TYPE keyType = CKK_SM1;
		CK_OBJECT_HANDLE hKey = NULL_PTR;
		CK_ATTRIBUTE KeyTemplate[] = {
			{CKA_CLASS, &objectClass, sizeof(objectClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &bFalse, sizeof(bFalse)},
			{CKA_ID, "temp_key", strlen("temp_key")},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VALUE, szR1, 16}
		};

		CK_ULONG ulLen = 0;

		CK_MECHANISM mech = {CKM_SM1_ECB, NULL, 0};
#endif

		rv = g_FunctionPtr->C_CreateObject(hSession, KeyTemplate, sizeof(KeyTemplate) / sizeof(CK_ATTRIBUTE), &hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

			goto err;
		}

		rv = g_FunctionPtr->C_EncryptInit(hSession, &mech, hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		ulLen = uiKPXLen;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)pKPX, ulLen);

		rv = g_FunctionPtr->C_Encrypt(hSession, pKPX, ulLen, pKPX, &ulLen);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);


		rv = g_FunctionPtr->C_EncryptInit(hSession, &mech, hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		ulLen = 64;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey  + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, ulLen);
		rv = g_FunctionPtr->C_Encrypt(hSession, pSignKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4 , ulLen, pSignKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, &ulLen);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_EncryptInit(hSession, &mech, hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		ulLen = 64;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, ulLen);
		rv = g_FunctionPtr->C_Encrypt(hSession, pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4 , ulLen, pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, &ulLen);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_EncryptInit(hSession, &mech, hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		ulLen = 64;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, ulLen);
		rv = g_FunctionPtr->C_Encrypt(hSession, pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4 , ulLen, pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, &ulLen);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_DestroyObject(hSession,hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey, uiSignKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey, uiCryptKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey, uiExchangeKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pKPX, uiKPXLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR1, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR2, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR3, 32);

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密：互通密钥参数文件
	{{ // 创建文件
		// r1加密后的A类用户（KPA）：  0x02 + 0x31 + BE087F4168213C144B6DA3AACBF5D056BE087F4168213C144B6DA3AACBF5D056 + 0x32 + FAAAAE0892E71A69BAC81ECC3CCD3E1BFAAAAE0892E71A69BAC81ECC3CCD3E1B
		// r3: 0303030303030303030303030303030303030303030303030303030303030303
		// data: KPA||r3
		//unsigned char *pbKPX = (unsigned char*)"\x02\x31\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\x32\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03";
		//unsigned char *pbKPX = (unsigned char*)"\x02\x31\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\x32\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

		unsigned char szKPX[32*3 + 1 + 2];
		CK_ULONG ulKPXLen = 32*3 + 1 + 2;
		int i = 0;
		int pos = 0;
		CK_KEY_TYPE		keyType = CKK_GENERIC_SECRET;
		CK_OBJECT_CLASS SecretClass = CKO_SECRET_KEY;
		CK_ATTRIBUTE KPXTemplate[] = {
			{CKA_CLASS, &SecretClass, sizeof(SecretClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_ID, RT_ZM_KPX, strlen(RT_ZM_KPX)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VALUE, (unsigned char *)szKPX, ulKPXLen}
		};
		CK_OBJECT_HANDLE hKPX=NULL_PTR;

		for(i = 0; i < 32; i++)
		{
			szR3[i] = szR1[i]^szR2[i];
		}

		switch(pSecID[0])
		{
		case '1':
			pos = 0;
			szKPX[pos] = 0x02;
			pos+=1;
			szKPX[pos] = 0x31;
			pos+=1;
			memcpy(szKPX+pos,pKPX+(0x31-0x31)*32,32);
			pos+=32;
			szKPX[pos] = 0x32;
			pos+=1;
			memcpy(szKPX+pos,pKPX+(0x32-0x31)*32,32);
			pos+=32;
			memcpy(szKPX+pos,szR3,32);
			pos+=32;

#if RT_P11_API_USE_CRC
			{
				unsigned short crc_val = crc_16(szR1, 32);

				szKPX[pos] = (unsigned char)crc_val;
				pos+=1;
				szKPX[pos] = (unsigned char)crc_val>>8;
				pos+=1;
			}
#endif

			KPXTemplate[5].ulValueLen = pos;
			break;
		case '2':
			pos = 0;
			szKPX[pos] = 0x02;
			pos+=1;
			szKPX[pos] = 0x32;
			pos+=1;
			memcpy(szKPX+pos,pKPX+(0x32-0x31)*32,32);
			pos+=32;
			szKPX[pos] = 0x33;
			pos+=1;
			memcpy(szKPX+pos,pKPX+(0x33-0x31)*32,32);
			pos+=32;
			memcpy(szKPX+pos,szR3,32);
			pos+=32;

#if RT_P11_API_USE_CRC
			{
				unsigned short crc_val = crc_16(szR1, 32);

				szKPX[pos] = (unsigned char)crc_val;
				pos+=1;
				szKPX[pos] = (unsigned char)crc_val>>8;
				pos+=1;
			}
#endif

			KPXTemplate[5].ulValueLen = pos;
			break;
		case '3':
			pos = 0;
			szKPX[pos] = 0x01;
			pos+=1;
			szKPX[pos] = 0x33;
			pos+=1;
			memcpy(szKPX+pos,pKPX+(0x33-0x31)*32,32);
			pos+=32;
			memcpy(szKPX+pos,szR3,32);
			pos+=32;

#if RT_P11_API_USE_CRC
			{
				unsigned short crc_val = crc_16(szR1, 32);

				szKPX[pos] = (unsigned char)crc_val;
				pos+=1;
				szKPX[pos] = (unsigned char)crc_val>>8;
				pos+=1;
			}
#endif

			KPXTemplate[5].ulValueLen = pos;
			break;
		case '4':
			pos = 0;
			break;
		default:
			pos = 0;
			break;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)szKPX, pos);

		rv = g_FunctionPtr->C_CreateObject(hSession, KPXTemplate, sizeof(KPXTemplate) / sizeof(CK_ATTRIBUTE), &hKPX);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		
	}}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey, uiSignKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey, uiCryptKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey, uiExchangeKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pKPX, uiKPXLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR1, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR2, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR3, 32);


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512签名密钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_SIGN, strlen(RT_ZM_SIGN)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VERIFY, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pSignKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pSignKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_SIGN, strlen(RT_ZM_SIGN)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bTrue, sizeof(bTrue)},
			{CKA_DECRYPT, &bTrue, sizeof(bTrue)},
			{CKA_SIGN, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pSignKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pSignKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, pSignKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, GM_ECC_512_BYTES_LEN}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		
	}}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512加密密钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_ENC, strlen(RT_ZM_ENC)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VERIFY, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pCryptKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pCryptKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_ENC, strlen(RT_ZM_ENC)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bTrue, sizeof(bTrue)},
			{CKA_DECRYPT, &bTrue, sizeof(bTrue)},
			{CKA_SIGN, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pCryptKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pCryptKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, GM_ECC_512_BYTES_LEN}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	}}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512交换钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_EXC, strlen(RT_ZM_EXC)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VERIFY, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pExchangeKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pExchangeKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_EXC, strlen(RT_ZM_EXC)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bTrue, sizeof(bTrue)},
			{CKA_DECRYPT, &bTrue, sizeof(bTrue)},
			{CKA_SIGN, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pExchangeKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pExchangeKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, GM_ECC_512_BYTES_LEN}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		
	}}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey, uiSignKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey, uiCryptKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey, uiExchangeKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pKPX, uiKPXLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR1, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR2, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR3, 32);


err:
	if (hSession)
	{
		g_FunctionPtr->C_CloseSession(hSession);
	}

	IN_FreeLibrary();

	return rv;
}

int RT_P11_API_SetZMCerts(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	unsigned char *pSignCert, int uiSignCertLen,
	unsigned char *pCryptCert, int uiCryptCertLen,
	unsigned char *pExchangeCert, int uiExchangeCertLen,
	char * pszPIN, unsigned int * pulRetry
	)
{
	CK_RV rv = CKR_OK;

	CK_ULONG ulSlotID = 0;
	CK_ULONG ulAuthSlotID = 0;
	CK_SLOT_ID szSlotID[256];
	CK_ULONG ulSlotCount = 256;
	int i = 0;
	CK_SESSION_HANDLE hSession = NULL_PTR;

	IN_LoadLibrary();

	ulSlotCount = sizeof(szSlotID)/sizeof(CK_SLOT_ID);

	rv = g_FunctionPtr->C_GetSlotList(bTrue, szSlotID, &ulSlotCount);
	if(rv != CKR_OK)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	ulAuthSlotID = atoi((char *) pAuthKey);

	for(i = 0; i < ulSlotCount; i++)
	{
		if (szSlotID[i] == ulAuthSlotID)
		{
			continue;
		}
		else
		{
			ulSlotID = szSlotID[i];
			break;
		}
	}

	rv = g_FunctionPtr->C_OpenSession(ulSlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	rv = g_FunctionPtr->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pszPIN, strlen(pszPIN));
	if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	{
		CK_OBJECT_CLASS DataClass = CKO_CERTIFICATE;
		CK_BBOOL True = TRUE;
		CK_ULONG ulObjectCount = 0;
		CK_OBJECT_HANDLE hObjects[16];
		CK_CERTIFICATE_TYPE CertType = CKC_X_509;
		CK_UTF8CHAR CertSubject[] = "ECC512 X509 Certificate";

		CK_ATTRIBUTE certTemplateSign[] = {
			{CKA_CLASS, &DataClass , sizeof(DataClass)},
			{CKA_CERTIFICATE_TYPE, &CertType, sizeof(CertType)},
			{CKA_LABEL,RT_ZM_SIGN , strlen(RT_ZM_SIGN)},
			{CKA_SUBJECT, CertSubject, sizeof(CertSubject)-1},
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_ID,RT_ZM_SIGN , strlen(RT_ZM_SIGN)},
			{CKA_VALUE, pSignCert,uiSignCertLen}
		};

		CK_ATTRIBUTE certTemplateEnc[] = {
			{CKA_CLASS, &DataClass , sizeof(DataClass)},
			{CKA_CERTIFICATE_TYPE, &CertType, sizeof(CertType)},
			{CKA_LABEL ,RT_ZM_ENC , strlen(RT_ZM_ENC)},
			{CKA_SUBJECT, CertSubject, sizeof(CertSubject)-1},
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_ID,RT_ZM_ENC , strlen(RT_ZM_ENC)},
			{CKA_VALUE, pCryptCert,uiCryptCertLen}
		};

		CK_ATTRIBUTE certTemplateExc[] = {
			{CKA_CLASS, &DataClass , sizeof(DataClass)},
			{CKA_CERTIFICATE_TYPE, &CertType, sizeof(CertType)},
			{CKA_LABEL, RT_ZM_EXC , strlen(RT_ZM_EXC)},
			{CKA_SUBJECT, CertSubject, sizeof(CertSubject)-1},
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_ID,RT_ZM_EXC , strlen(RT_ZM_EXC)},
			{CKA_VALUE, pExchangeCert,uiExchangeCertLen}
		};

		rv = g_FunctionPtr->C_CreateObject(hSession, certTemplateSign, sizeof(certTemplateSign)/sizeof(CK_ATTRIBUTE),hObjects);
		if (rv != CKR_OK)
		{
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}

		rv = g_FunctionPtr->C_CreateObject(hSession, certTemplateEnc, sizeof(certTemplateEnc)/sizeof(CK_ATTRIBUTE),hObjects);
		if (rv != CKR_OK)
		{
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}

		rv = g_FunctionPtr->C_CreateObject(hSession, certTemplateExc, sizeof(certTemplateExc)/sizeof(CK_ATTRIBUTE),hObjects);
		if (rv != CKR_OK)
		{
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
	}	

err:
	if (hSession)
	{
		g_FunctionPtr->C_CloseSession(hSession);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	IN_FreeLibrary();

	return rv;
}

int RT_P11_API_GetCertCount(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	unsigned int *CertCount,
	char * pszPIN, unsigned int * pulRetry
	)
{
	CK_RV rv = CKR_OK;

	CK_ULONG ulSlotID = 0;
	CK_ULONG ulAuthSlotID = 0;
	CK_SLOT_ID szSlotID[256];
	CK_ULONG ulSlotCount = 256;
	int i = 0;
	CK_SESSION_HANDLE hSession = NULL_PTR;

	IN_LoadLibrary();

	ulSlotCount = sizeof(szSlotID)/sizeof(CK_SLOT_ID);

	rv = g_FunctionPtr->C_GetSlotList(bTrue, szSlotID, &ulSlotCount);
	if(rv != CKR_OK)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	ulAuthSlotID = atoi((char *) pAuthKey);

	*CertCount = 0;

	for(i = 0; i < ulSlotCount; i++)
	{
		if (szSlotID[i] == ulAuthSlotID)
		{
			continue;
		}
		else
		{
			ulSlotID = szSlotID[i];
			break;
		}
	}

	rv = g_FunctionPtr->C_OpenSession(ulSlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	//rv = g_FunctionPtr->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pszPIN, strlen(pszPIN));
	//if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) {
	//	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	//	goto err;
	//}

	{
		CK_OBJECT_CLASS DataClass = CKO_CERTIFICATE;
		CK_BBOOL True = TRUE;
		CK_ULONG ulObjectCount = 0;
		CK_OBJECT_HANDLE hObjects[16], hUserInfoObj = NULL_PTR;

		CK_ATTRIBUTE searchTemplate[] = {
			{CKA_CLASS, &DataClass , sizeof(DataClass)},
			{CKA_TOKEN, &True, sizeof(True)},
		};

		rv = g_FunctionPtr->C_FindObjectsInit(hSession, searchTemplate, sizeof(searchTemplate)/sizeof(CK_ATTRIBUTE));
		if (rv != CKR_OK)
		{
			goto err;
		}
		ulObjectCount = sizeof(hObjects)/sizeof(CK_OBJECT_HANDLE);
		rv = g_FunctionPtr->C_FindObjects(hSession, hObjects, sizeof(hObjects)/sizeof(CK_OBJECT_HANDLE), &ulObjectCount);
		g_FunctionPtr->C_FindObjectsFinal(hSession);

		if (rv != CKR_OK)
		{
			goto err;
		}

		*CertCount = ulObjectCount;
	}	

err:
	if (hSession)
	{
		g_FunctionPtr->C_CloseSession(hSession);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)CertCount, 4);

	IN_FreeLibrary();

	return rv;
}
